//! Integration tests for the ingest of a file system tree.
//!
//! These tests build source trees on disk. Then they ingest each tree through
//! `write_dfd_to_mtree` under a `CommitModifier`. The tests cover:
//!
//! - the checksums of the fixture tree
//! - the modes and the xattrs of the canonical-permissions output of the
//!   `ostree` command
//! - the pruning of a subtree by the filter
//! - an xattr callback that changes the object id
//! - a devino-cache hit that skips the ingest of a file
//! - the consumption of the source, and its removal after the commit
//! - a round trip of a `user.*` xattr

mod common;

use std::collections::HashSet;
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::Arc;

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

/// Returns `value`. A call is a compile-time check that the future of the
/// ingest walk is `Send`, callbacks included.
fn assert_send<T: Send>(value: T) -> T {
    value
}

/// Sets the permission bits of a path.
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Builds the fixture source tree (hello/empty/nested/link) under `base/src`
/// and returns the source directory. The tree does not depend on the owner.
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

/// Returns the uid and gid of this process, read from a directory that it
/// created.
fn own_ids(path: &Path) -> (u32, u32) {
    let stat = rustix::fs::stat(path).unwrap();
    (stat.st_uid, stat.st_gid)
}

#[test]
fn ingest_reproduces_the_fixture_tree() {
    // The modes are already canonical (0644 files, 0755 dirs). An ingest that
    // sets the owner to 0:0 gives the owner-0:0 fixture of the `ostree`
    // command exactly.
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
    // The source is the tree of mixed modes that the canon fixture comes from.
    // An ingest with CANONICAL_PERMISSIONS gives the root-tree identity that
    // the `ostree` command gave with --canonical-permissions.
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
    // The rule: 0664 -> 0644, 0755 -> 0755, 04755 -> 0755, and the owner is
    // 0:0. The test reads the ingested modes back through ostrya, without the
    // `ostree` command.
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
    // Because a canonical ingest records no xattrs, an entry with an xattr gets
    // the identity of the same entry without it. This applies to a file and to
    // the metadata of a directory. The test
    // `canonical_permissions_match_the_tool_over_xattrs` compares this with the
    // `ostree` command.
    let tmp = TmpDir::new("ingest-canon-xattr");
    let base = tmp.path();
    // Two copies of one tree. Only one copy has the xattrs.
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
            // No SKIP_XATTRS: the walk reads the xattrs on disk, and the
            // canonical ingest removes them.
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

        // The recorded file header also has no xattr.
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
    // The `--canonical-permissions` option of the `ostree` command records no
    // xattrs. The canonical ingest of ostrya must give the same object names
    // as the `ostree` command for a tree with xattrs.
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
    // A filter that skips /subdir excludes the directory and all its contents.
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

/// Sets the mode of each listed path again on drop.
///
/// Declare it after the `TmpDir` of the test. It then drops first, and the
/// `TmpDir` can remove an entry that the test made unreadable.
struct RestoreModes(Vec<(std::path::PathBuf, u32)>);

impl Drop for RestoreModes {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        for (path, mode) in &self.0 {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode));
        }
    }
}

/// Returns the sorted names of the entries of a directory.
fn entry_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn filter_skips_an_entry_that_does_not_open() {
    // The walk opens an entry only after the filter keeps it. An entry that
    // does not open and that the filter skips thus does not stop the walk,
    // and the tree is the tree without the entry. Without the filter, the
    // open fails. The `ostree` command gives the same results for an entry
    // that `--skip-list` names. A directory at mode 0644 opens, so it has no
    // control.
    for (name, mode) in [
        ("file0000", 0o000),
        ("file0200", 0o200),
        ("empty0000", 0o000),
        ("dir0000", 0o000),
        ("dir0311", 0o311),
        ("dir0644", 0o644),
    ] {
        let tmp = TmpDir::new("ingest-filter-unopened");
        let base = tmp.path();
        for tree in ["src", "want"] {
            let dir = base.join(tree);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("kept.txt"), b"kept\n").unwrap();
            set_mode(&dir.join("kept.txt"), 0o644);
            set_mode(&dir, 0o755);
        }
        let entry = base.join("src").join(name);
        if name.starts_with("dir") {
            std::fs::create_dir(&entry).unwrap();
            std::fs::write(entry.join("inner"), b"inner\n").unwrap();
        } else if name.starts_with("empty") {
            std::fs::write(&entry, b"").unwrap();
        } else {
            std::fs::write(&entry, b"secret\n").unwrap();
        }
        let _restore = RestoreModes(vec![(entry.clone(), 0o755)]);
        set_mode(&entry, mode);

        block_on(async {
            let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
                .await
                .unwrap();
            let dfd = std::fs::File::open(base).unwrap();

            let want = {
                let txn = repo.transaction().await.unwrap();
                let mut mtree = MutableTree::new();
                txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("want"), &mut mtree, None)
                    .await
                    .unwrap();
                let rt = txn.write_mtree(&mut mtree).await.unwrap();
                let want = (*rt.dirtree_checksum(), *rt.dirmeta_checksum());
                txn.abort().await.unwrap();
                want
            };

            if name != "dir0644" {
                let txn = repo.transaction().await.unwrap();
                let mut mtree = MutableTree::new();
                let result = txn
                    .write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
                    .await;
                txn.abort().await.unwrap();
                match result {
                    Err(ostrya::Error::Io(err)) => assert_eq!(
                        err.kind(),
                        std::io::ErrorKind::PermissionDenied,
                        "{name}: {err}"
                    ),
                    Err(err) => panic!("{name}: the walk without a filter gives {err}"),
                    Ok(()) => {
                        if !rustix::process::geteuid().is_root() {
                            panic!("{name}: the walk without a filter reads the entry");
                        }
                        eprintln!("skipping the control of {name}: root opens each mode");
                    }
                }
            }

            let txn = repo.transaction().await.unwrap();
            let listed = format!("/{name}");
            let mut modifier = CommitModifier::new(CommitModifierFlags::empty());
            modifier.filter = Some(Box::new(move |path, _meta| {
                if path == Path::new(&listed) {
                    FilterResult::Skip
                } else {
                    FilterResult::Allow
                }
            }));
            let mut mtree = MutableTree::new();
            if let Err(err) = txn
                .write_dfd_to_mtree(
                    dfd.as_fd(),
                    Path::new("src"),
                    &mut mtree,
                    Some(&mut modifier),
                )
                .await
            {
                panic!("{name}: the walk that skips the entry gives {err}");
            }
            let rt = txn.write_mtree(&mut mtree).await.unwrap();
            let got = (*rt.dirtree_checksum(), *rt.dirmeta_checksum());
            let stats = txn.commit().await.unwrap();
            assert_eq!(stats.filtered, 1, "{name}: one entry skipped");
            assert_eq!(got, want, "{name}: the tree without the entry");
        });
    }
}

#[test]
fn filter_gets_no_xattrs_from_disk() {
    // The filter runs before the walk opens an entry, so the metadata that it
    // gets holds no xattrs from the disk. The committed entry holds them.
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    let tmp = TmpDir::new("ingest-filter-xattrs");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("hello.txt"), b"labeled\n").unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    for path in [src.join("hello.txt"), src.join("sub")] {
        rustix::fs::setxattr(
            &path,
            "user.demo",
            b"value",
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
    }
    let seen: Arc<Mutex<HashMap<String, Xattrs>>> = Arc::new(Mutex::new(HashMap::new()));

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let record = Arc::clone(&seen);
        let mut modifier = CommitModifier::new(CommitModifierFlags::empty());
        modifier.filter = Some(Box::new(move |path, meta| {
            record
                .lock()
                .unwrap()
                .insert(path.to_str().unwrap().to_owned(), meta.xattrs.clone());
            FilterResult::Allow
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

        for path in ["/hello.txt", "/sub"] {
            let xattrs = seen.lock().unwrap().get(path).cloned();
            let xattrs = xattrs.unwrap_or_else(|| panic!("{path} filtered"));
            assert!(xattrs.is_empty(), "{path}: the filter gets {xattrs:?}");
        }

        let has_demo = |xattrs: &Xattrs| {
            xattrs
                .iter()
                .any(|(name, value)| name == b"user.demo\0" && value == b"value")
        };
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let hello = tree.files.iter().find(|(n, _)| n == "hello.txt").unwrap().1;
        let file = repo.load_file(&hello).await.unwrap();
        assert!(has_demo(&file.xattrs), "file xattrs: {:?}", file.xattrs);
        let sub = tree.dirs.iter().find(|(n, _, _)| n == "sub").unwrap();
        let dirmeta = repo.load_dirmeta(&sub.2).await.unwrap();
        assert!(has_demo(&dirmeta.xattrs), "dirmeta xattrs: {:?}", dirmeta);
    });
}

#[test]
fn nested_directory_xattrs_reach_the_dirmeta() {
    // The walk reads the xattrs of a nested directory. They enter its dirmeta,
    // with no modifier and under a modifier, and the xattr callback gets them.
    use std::sync::{Arc, Mutex};

    let tmp = TmpDir::new("ingest-dir-xattrs");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub/nested.txt"), b"nested\n").unwrap();
    set_mode(&src.join("sub/nested.txt"), 0o644);
    rustix::fs::setxattr(
        src.join("sub"),
        "user.demo",
        b"value",
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
    let has_demo = |xattrs: &Xattrs| {
        xattrs
            .iter()
            .any(|(name, value)| name == b"user.demo\0" && value == b"value")
    };

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        for with_callback in [false, true] {
            let seen: Arc<Mutex<Option<Xattrs>>> = Arc::new(Mutex::new(None));
            let mut modifier = with_callback.then(|| {
                let record = Arc::clone(&seen);
                let mut modifier = CommitModifier::new(CommitModifierFlags::empty());
                modifier.xattr_callback = Some(Box::new(move |path, meta| {
                    if path == Path::new("/sub") {
                        *record.lock().unwrap() = Some(meta.xattrs.clone());
                    }
                    meta.xattrs.clone()
                }));
                modifier
            });
            let txn = repo.transaction().await.unwrap();
            let dfd = std::fs::File::open(base).unwrap();
            let mut mtree = MutableTree::new();
            txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, modifier.as_mut())
                .await
                .unwrap();
            let rt = txn.write_mtree(&mut mtree).await.unwrap();
            let root_dirtree = *rt.dirtree_checksum();
            txn.commit().await.unwrap();

            let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
            let sub = tree.dirs.iter().find(|(n, _, _)| n == "sub").unwrap();
            let dirmeta = repo.load_dirmeta(&sub.2).await.unwrap();
            assert!(
                has_demo(&dirmeta.xattrs),
                "callback {with_callback}: dirmeta xattrs: {dirmeta:?}"
            );
            if with_callback {
                let got = seen
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("the callback gets /sub");
                assert!(has_demo(&got), "the callback gets {got:?}");
            }
        }
    });
}

#[test]
fn xattr_callback_lands_in_the_object_id() {
    // A callback sets user.extra on hello.txt. The ingested object id is then
    // equal to the id of the same content, written with that xattr in its
    // header.
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

        // The identity of the same payload, written with the xattr directly.
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
    // The canonical reduction is the last of the mode modifiers. A mode
    // callback sets the mode, and then the reduction masks it. The file type
    // stays the type that the walk found: a callback that names a different
    // type does not change the kind of the entry. The plain walk and the
    // devino-cache path run the callback through the same step, so the test
    // checks both.
    let tmp = TmpDir::new("ingest-canon-order");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    set_mode(&src.join("sub"), 0o700);
    set_mode(&src, 0o755);
    let stat = rustix::fs::stat(src.join("hello.txt")).unwrap();

    // This closure does what the mode callback of the CLI `--statoverride`
    // option does for `=511 /hello.txt`, `=2048 /sub`, and a value that names
    // a different file type.
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

        // 0o777 is set, then reduced to 0o755. 0o4000 is set, then reduced: no
        // bit passes the mask. A reduction before the callback gives 0o777 and
        // 0o4000.
        assert_eq!(walk(0o777, None).await, (0o100755, 0o40755));
        assert_eq!(walk(0o4000, None).await, (0o100000, 0o40000));
        // A value that names the directory type on a regular file leaves a
        // regular file. The mask applies to the permission bits of the value.
        assert_eq!(walk(0o40755, None).await, (0o100755, 0o40755));

        // The same on the devino-cache path: the stored object supplies the
        // metadata. The callback changes it first, and then the reduction.
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
    // With DEVINO_CANONICAL and a cache entry for the (dev, ino) of the file,
    // the file gets the cached checksum, and the walk stages no object.
    // Without the flag, the walk also reads the cache. The stored object
    // supplies the metadata that the modifier changes. If the changed metadata
    // matches the stored object, the walk reuses the object. If not, the walk
    // writes the object again from the stored content.
    let tmp = TmpDir::new("ingest-devino");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    let stat = rustix::fs::stat(src.join("hello.txt")).unwrap();
    let sentinel = Checksum::sha256(b"a checksum that is not the real content");

    block_on(async {
        // Hit: the walk reads the cache and stages no object.
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

        // A repository with the real object, for the next two walks.
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

        // The test writes a new payload to the source file in place, and the
        // inode stays the same. The payload of the stored object and the
        // payload of the source file are now different. If one of the next two
        // walks reads the source, its object holds the new payload.
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

        // No flag, and the changed metadata is equal to the stored metadata:
        // the walk reuses the object and counts the hit.
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

        // No flag, and the modifier changes the metadata: the walk writes the
        // object again from the stored content, with the changed metadata.
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
    // A consuming walk removes each source file and the walk-root directory.
    // The parent of the walk root stays. The objects are still staged.
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
    // A consuming walk keeps the walk root if the path is exactly `.`. It
    // removes the walk root for each other spelling, `./` included. The check
    // is on the text of the path. The `ostree` command applies the same rule
    // to `commit --consume`.
    // Both spellings here name the directory that the walk-root descriptor is
    // open on. The kernel refuses to unlink a path whose last component is
    // `.`, so each spelling leaves the directory in place and empties it.
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
    // A file with a user.* xattr ingests into bare-user and reads back with
    // the same xattr.
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
        // No SKIP_XATTRS: the walk reads the xattrs on disk.
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
    // The xattr fixture is a bare-user commit that the `ostree` command made,
    // with a user.demo xattr on hello.txt. The command stored the xattr in the
    // user.ostreemeta of the file, and the fixture tarball carries it in git.
    // The read proves that ostrya decodes an xattr set that the `ostree`
    // command wrote. The test `user_xattr_round_trips_through_ingest` uses
    // ostrya at both ends. This test reads the bytes that the `ostree` command
    // wrote.
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
    // A symlink object with a user.* xattr makes a round trip through the
    // modes that store xattrs in-band. Archive keeps them in the framed
    // header, and bare-user keeps them in user.ostreemeta. write_symlink takes
    // the xattr set directly, so the test checks storage and read-back with
    // no xattr on a source symlink. The VFS forbids user.* xattrs on a
    // symlink, and other xattrs on a symlink need CAP_SYS_ADMIN. The bare mode
    // stores the same xattr on the inode. That needs the same privilege, so a
    // test on a privileged host covers it.
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
    // A symlink to a regular file with an xattr ingests with the xattr set of
    // the link itself, which is empty. The user.demo of the target must not go
    // into the symlink object. The ingest has no SKIP_XATTRS, so the walk
    // reads the xattrs on disk.
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

        // The symlink does not get the xattr: a no-follow read gives an empty
        // set for the link.
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
    // A label callback gives an SELinux label. The label goes into the xattr
    // set of the content object, so the object id matches the id of the same
    // content with that label.
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

        // The identity of the same payload, written with the label directly.
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
    // With ERROR_ON_UNLABELED and a label callback that labels nothing, the
    // ingest fails. It does not commit an unlabeled path.
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
fn consume_keeps_a_file_that_the_filter_skips() {
    // A consuming walk does not remove a file that the filter skips. The file
    // and the directories that hold it stay, and the committed tree does not
    // hold the file.
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

        assert_eq!(entry_names(&src), vec!["subdir"], "the walk root stays");
        assert_eq!(
            entry_names(&src.join("subdir")),
            vec!["skip.txt"],
            "the skipped file and its parent stay"
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
fn consume_keeps_a_directory_that_the_filter_skips() {
    // A consuming walk does not enter or remove a directory that the filter
    // skips. The directory keeps its subtree, the walk root stays, and the
    // walk removes the other entries.
    let tmp = TmpDir::new("ingest-consume-prune-dir");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir_all(src.join("pruned/deeper")).unwrap();
    std::fs::write(src.join("pruned/a.txt"), b"a\n").unwrap();
    std::fs::write(src.join("pruned/deeper/b.txt"), b"b\n").unwrap();
    std::fs::write(src.join("keep.txt"), b"keep\n").unwrap();
    for path in ["pruned/deeper/b.txt", "pruned/a.txt", "keep.txt"] {
        set_mode(&src.join(path), 0o644);
    }
    for path in ["pruned/deeper", "pruned", ""] {
        set_mode(&src.join(path), 0o755);
    }

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut modifier =
            CommitModifier::new(CommitModifierFlags::CONSUME | CommitModifierFlags::SKIP_XATTRS);
        modifier.filter = Some(Box::new(|path, _meta| {
            if path == Path::new("/pruned") {
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
        txn.abort().await.unwrap();
    });

    assert_eq!(entry_names(&src), vec!["pruned"], "the walk root stays");
    assert_eq!(entry_names(&src.join("pruned")), vec!["a.txt", "deeper"]);
    assert_eq!(entry_names(&src.join("pruned/deeper")), vec!["b.txt"]);
}

#[test]
fn consume_keeps_an_entry_that_the_filter_skips_and_that_does_not_open() {
    // A consuming walk never opens an entry that the filter skips. A skipped
    // directory that does not open and a skipped file stay, with each
    // directory that holds them, the walk root included. The walk removes
    // each other entry and succeeds.
    let tmp = TmpDir::new("ingest-consume-unopened");
    let base = tmp.path();
    let src = base.join("src");
    for dir in ["sub/locked", "other", "gone"] {
        std::fs::create_dir_all(src.join(dir)).unwrap();
    }
    for path in [
        "top.txt",
        "sub/a.txt",
        "sub/locked/inner",
        "other/skip.txt",
        "other/b.txt",
        "gone/c.txt",
    ] {
        std::fs::write(src.join(path), path.as_bytes()).unwrap();
        set_mode(&src.join(path), 0o644);
    }
    let locked = src.join("sub/locked");
    let _restore = RestoreModes(vec![(locked.clone(), 0o755)]);
    set_mode(&locked, 0o000);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        let mut modifier = CommitModifier::new(CommitModifierFlags::CONSUME);
        modifier.filter = Some(Box::new(|path, _meta| {
            if path == Path::new("/sub/locked") || path == Path::new("/other/skip.txt") {
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
        txn.write_mtree(&mut mtree).await.unwrap();
        let stats = txn.commit().await.unwrap();
        assert_eq!(stats.filtered, 2, "two entries skipped");
    });

    assert_eq!(entry_names(&src), vec!["other", "sub"]);
    assert_eq!(entry_names(&src.join("sub")), vec!["locked"]);
    assert_eq!(entry_names(&src.join("other")), vec!["skip.txt"]);
    set_mode(&locked, 0o755);
    assert_eq!(entry_names(&locked), vec!["inner"]);
}

#[test]
fn modifier_callbacks_run_once_per_directory() {
    // The xattr callback runs exactly once for each path, directories
    // included.
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
    // A devino-cache hit takes the cached checksum and does not run the label
    // hook. As a result, ERROR_ON_UNLABELED with a hook that does not label
    // the cached file does not make the ingest fail.
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
        // The hook labels each path except the cached file. If the hook runs
        // for the cached file, it returns None, and ERROR_ON_UNLABELED stops
        // the ingest.
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
    // A devino-cache hit runs no user callbacks: the walk does not call a
    // counting xattr callback for the cached file.
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

/// The environment variable that marks the re-executed child of
/// [`deep_source_tree_ingests_under_a_low_descriptor_limit`]. Its value names
/// the file that the child writes to record that the ingest ran.
const DEEP_INGEST_CHILD: &str = "OSTRYA_DEEP_INGEST_CHILD";
/// The soft descriptor limit of the child. It is much higher than the number
/// of descriptors that the repository, the runtime, and the blocking pool open
/// for themselves.
const DEEP_INGEST_NOFILE: usize = 256;
/// The depth of the source tree that the child ingests. It is much higher than
/// [`DEEP_INGEST_NOFILE`], so a walk that holds one descriptor for each level
/// runs out.
const DEEP_INGEST_DEPTH: usize = 1024;
/// The thread stack size of the child. Each level of the walk costs one
/// future, and the tree is deep. The stack has room for the full descent, so
/// the walk meets the descriptor limit first.
const DEEP_INGEST_STACK: usize = 512 * 1024 * 1024;

#[test]
fn deep_source_tree_ingests_under_a_low_descriptor_limit() {
    // The walk holds at most two directory descriptors at a time, for any
    // depth of the source. As a result, a tree deeper than the descriptor
    // limit of the process ingests.
    //
    // The limit applies to the whole process, and the tests of this binary
    // run in parallel threads. For this reason, a child gets the lowered
    // limit. The child is this test binary, run again for this test alone,
    // through `sh` with `ulimit -n`.
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
    // If the filter of the child matches no test name, the child runs nothing
    // and still exits 0. The marker proves that the ingest ran.
    assert!(
        marker.exists(),
        "the child ran no deep ingest: the test name the filter names is stale"
    );
}

/// Returns the soft `RLIMIT_NOFILE` of the running process, read from `/proc`.
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

/// Ingests a source tree [`DEEP_INGEST_DEPTH`] directories deep and consumes
/// it. Runs in the child process, under the lowered descriptor limit.
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
    // The test builds the tree through a descriptor that descends, so no path
    // that it uses grows past the path limit of the kernel. CONSUME empties
    // the tree as the walk ascends, and this also removes the tree. A removal
    // by path of a tree this deep runs out of descriptors itself.
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

/// The environment variable that marks the re-executed child of
/// [`remove_source_tree_removes_a_deep_tree_under_a_low_descriptor_limit`].
/// Its value names the file that the child writes to record that the removal
/// ran.
const REMOVE_DEEP_CHILD: &str = "OSTRYA_REMOVE_DEEP_CHILD";
/// The soft descriptor limit of the child.
const REMOVE_DEEP_NOFILE: usize = 128;
/// The depth of the tree that the child removes. It is much higher than
/// [`REMOVE_DEEP_NOFILE`], so a removal that holds one descriptor for each
/// level runs out.
const REMOVE_DEEP_DEPTH: usize = 512;

#[test]
fn remove_source_tree_removes_a_deep_tree_under_a_low_descriptor_limit() {
    // The limit applies to the whole process, and the tests of this binary
    // run in parallel threads. For this reason, a child gets the lowered
    // limit, as in `deep_source_tree_ingests_under_a_low_descriptor_limit`.
    if let Some(marker) = std::env::var_os(REMOVE_DEEP_CHILD) {
        remove_a_deep_tree();
        std::fs::write(marker, b"removed").expect("record that the deep removal ran");
        return;
    }
    let tmp = TmpDir::new("remove-deep-marker");
    let marker = tmp.path().join("removed");
    let exe = std::env::current_exe().expect("the path of the running test binary");
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"ulimit -n "$1" || exit 111; shift; exec "$@""#)
        .arg("sh")
        .arg(REMOVE_DEEP_NOFILE.to_string())
        .arg(&exe)
        .arg("--exact")
        .arg("remove_source_tree_removes_a_deep_tree_under_a_low_descriptor_limit")
        .arg("--nocapture")
        .env(REMOVE_DEEP_CHILD, &marker)
        .status()
        .expect("re-run the test binary under a lowered descriptor limit");
    assert!(
        status.success(),
        "the deep removal failed under a soft limit of {REMOVE_DEEP_NOFILE} descriptors: {status}"
    );
    assert!(
        marker.exists(),
        "the child ran no deep removal: the test name the filter names is stale"
    );
}

/// Removes a tree [`REMOVE_DEEP_DEPTH`] directories deep with
/// `remove_source_tree`. Runs in the child process, under the lowered
/// descriptor limit.
fn remove_a_deep_tree() {
    assert_eq!(
        soft_nofile_limit(),
        REMOVE_DEEP_NOFILE,
        "the child runs under the lowered descriptor limit"
    );
    let tmp = TmpDir::new("remove-deep");
    let base = tmp.path();
    let src = base.join("src");
    std::fs::create_dir(&src).unwrap();
    // The test builds the tree through a descriptor that descends, so no path
    // that it uses grows past the path limit of the kernel.
    let mut dir: std::os::fd::OwnedFd = std::fs::File::open(&src).unwrap().into();
    for _ in 0..REMOVE_DEEP_DEPTH {
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
    let bottom = rustix::fs::openat(
        dir.as_fd(),
        "f",
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o644),
    )
    .unwrap();
    drop(bottom);
    drop(dir);

    let dfd = std::fs::File::open(base).unwrap();
    block_on(ostrya::remove_source_tree(
        dfd.as_fd(),
        Path::new("src"),
        Arc::default(),
    ))
    .unwrap();
    assert!(!src.exists(), "the removal left the deep tree behind");
    assert!(base.exists(), "the removal went past the tree");
}

/// Builds a tree for a `remove_source_tree` test: a file, a subdirectory with
/// a file, and a symlink to a directory outside the tree.
fn removal_source(dir: &Path, outside: &Path) {
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("x"), "x\n").unwrap();
    std::fs::write(dir.join("sub/y"), "y\n").unwrap();
    std::os::unix::fs::symlink(outside, dir.join("out")).unwrap();
}

/// A path whose last component is `.` keeps the directory and loses its
/// contents. A symlink in the tree is removed, and its target stays.
#[test]
fn remove_source_tree_keeps_a_directory_spelled_dot() {
    let tmp = TmpDir::new("remove-dot");
    let base = tmp.path();
    let outside = base.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("kept"), "kept\n").unwrap();
    let src = base.join("src");

    // The first two spellings name `src` through its own descriptor, the
    // other two through the descriptor of its parent.
    for (from_src, spelling) in [
        (true, "."),
        (true, "./"),
        (false, "src/."),
        (false, "src/./"),
    ] {
        removal_source(&src, &outside);
        let dfd = std::fs::File::open(if from_src { &src } else { base }).unwrap();
        block_on(ostrya::remove_source_tree(
            dfd.as_fd(),
            Path::new(spelling),
            Arc::default(),
        ))
        .unwrap_or_else(|err| panic!("`{spelling}` failed: {err}"));
        assert_eq!(
            std::fs::read_dir(&src).map(Iterator::count).ok(),
            Some(0),
            "`{spelling}` did not keep an empty directory",
        );
        assert!(
            outside.join("kept").exists(),
            "`{spelling}` followed the symlink"
        );
    }
}

/// A relative path and an absolute path remove the directory, and the parent
/// stays. An absolute path does not use the descriptor.
#[test]
fn remove_source_tree_removes_the_directory() {
    let tmp = TmpDir::new("remove-dir");
    let base = tmp.path();
    let outside = base.join("outside");
    std::fs::create_dir(&outside).unwrap();
    let dfd = std::fs::File::open(base).unwrap();
    let unrelated = std::fs::File::open(&outside).unwrap();

    let relative = base.join("relative");
    removal_source(&relative, &outside);
    block_on(ostrya::remove_source_tree(
        dfd.as_fd(),
        Path::new("relative"),
        Arc::default(),
    ))
    .unwrap();
    assert!(!relative.exists(), "the relative path stayed");

    let absolute = base.join("absolute");
    removal_source(&absolute, &outside);
    block_on(ostrya::remove_source_tree(
        unrelated.as_fd(),
        &absolute,
        Arc::default(),
    ))
    .unwrap();
    assert!(!absolute.exists(), "the absolute path stayed");

    assert!(
        base.exists() && outside.exists(),
        "the removal went too far"
    );
}

/// An entry that `keep` names stays and is never opened. Each directory that
/// holds it stays, the source root included. A kept directory keeps its
/// subtree, and `/` keeps the whole source.
#[test]
fn remove_source_tree_keeps_the_entries_that_keep_names() {
    let tmp = TmpDir::new("remove-keep");
    let base = tmp.path();
    let src = base.join("src");
    for dir in ["sub/locked", "sub/deep", "gone", "kept"] {
        std::fs::create_dir_all(src.join(dir)).unwrap();
    }
    for file in [
        "x",
        "sub/y",
        "sub/locked/inner",
        "sub/deep/z",
        "gone/w",
        "kept/q",
    ] {
        std::fs::write(src.join(file), file).unwrap();
    }
    let locked = src.join("sub/locked");
    let _restore = RestoreModes(vec![(locked.clone(), 0o755)]);
    set_mode(&locked, 0o000);
    let dfd = std::fs::File::open(base).unwrap();

    let all = Arc::new(HashSet::from(["/".to_owned()]));
    block_on(ostrya::remove_source_tree(
        dfd.as_fd(),
        Path::new("src"),
        all,
    ))
    .unwrap();
    assert_eq!(entry_names(&src), vec!["gone", "kept", "sub", "x"]);
    assert_eq!(entry_names(&src.join("sub")), vec!["deep", "locked", "y"]);

    let keep = [
        "/sub/locked",
        "/kept",
        "/x",
        "/absent",
        "sub/y",
        "/sub/deep/",
    ]
    .map(String::from);
    block_on(ostrya::remove_source_tree(
        dfd.as_fd(),
        Path::new("src"),
        Arc::new(HashSet::from(keep)),
    ))
    .unwrap();
    assert_eq!(entry_names(&src), vec!["kept", "sub", "x"]);
    assert_eq!(entry_names(&src.join("sub")), vec!["locked"]);
    assert_eq!(entry_names(&src.join("kept")), vec!["q"]);
    set_mode(&locked, 0o755);
    assert_eq!(entry_names(&locked), vec!["inner"]);
}

/// A symlink or a file at the path is refused, and nothing is removed. A
/// trailing slash does not make the removal follow a symlink.
#[test]
fn remove_source_tree_refuses_a_symlink_or_a_file_at_the_path() {
    let tmp = TmpDir::new("remove-refused");
    let base = tmp.path();
    let target = base.join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("kept"), "kept\n").unwrap();
    std::os::unix::fs::symlink("target", base.join("link")).unwrap();
    std::fs::write(base.join("file"), "file\n").unwrap();
    let dfd = std::fs::File::open(base).unwrap();

    for spelling in ["link", "link/", "file", "file/"] {
        let err = block_on(ostrya::remove_source_tree(
            dfd.as_fd(),
            Path::new(spelling),
            Arc::default(),
        ))
        .expect_err(spelling);
        assert!(
            matches!(err, ostrya::Error::ConsumeUnlink { .. }),
            "`{spelling}` gave another error: {err:?}"
        );
    }
    assert!(
        target.join("kept").exists(),
        "the symlink target lost an entry"
    );
    assert!(
        base.join("link").symlink_metadata().is_ok(),
        "the symlink is gone"
    );
    assert!(base.join("file").exists(), "the file is gone");
}

/// Nothing at the path is not an error, because nothing is left to remove.
#[test]
fn remove_source_tree_of_a_missing_path_is_ok() {
    let tmp = TmpDir::new("remove-missing");
    let dfd = std::fs::File::open(tmp.path()).unwrap();
    block_on(ostrya::remove_source_tree(
        dfd.as_fd(),
        Path::new("absent"),
        Arc::default(),
    ))
    .unwrap();
    block_on(ostrya::remove_source_tree(
        dfd.as_fd(),
        Path::new("absent/"),
        Arc::default(),
    ))
    .unwrap();
}

/// Builds a wide tree for a `remove_source_tree` test: 5000 files at the top,
/// and three levels of subdirectories with files at each level.
fn wide_removal_source(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    for i in 0..5000 {
        std::fs::write(dir.join(format!("f{i}")), "").unwrap();
    }
    for a in 0..3 {
        for b in 0..3 {
            let sub = dir.join(format!("a{a}/b{b}/c"));
            std::fs::create_dir_all(&sub).unwrap();
            for i in 0..20 {
                std::fs::write(dir.join(format!("a{a}/g{i}")), "").unwrap();
                std::fs::write(dir.join(format!("a{a}/b{b}/h{i}")), "").unwrap();
                std::fs::write(sub.join(format!("k{i}")), "").unwrap();
            }
        }
    }
}

/// A directory with many files and nested subdirectories is removed
/// completely. With `.` as the last component, the directory stays empty.
#[test]
fn remove_source_tree_removes_a_wide_tree() {
    let tmp = TmpDir::new("remove-wide");
    let base = tmp.path();
    let src = base.join("src");
    let dfd = std::fs::File::open(base).unwrap();

    wide_removal_source(&src);
    block_on(ostrya::remove_source_tree(
        dfd.as_fd(),
        Path::new("src"),
        Arc::default(),
    ))
    .unwrap();
    assert!(!src.exists(), "the removal left the wide tree behind");

    wide_removal_source(&src);
    block_on(ostrya::remove_source_tree(
        dfd.as_fd(),
        Path::new("src/."),
        Arc::default(),
    ))
    .unwrap();
    assert_eq!(
        std::fs::read_dir(&src).map(Iterator::count).ok(),
        Some(0),
        "`src/.` did not keep an empty directory",
    );
}

/// A name below the path that is not valid UTF-8 stops the removal with an
/// error that names the entry, and the entry stays.
#[test]
fn remove_source_tree_refuses_a_name_that_is_not_utf8() {
    use std::os::unix::ffi::OsStrExt;

    let tmp = TmpDir::new("remove-not-utf8");
    let base = tmp.path();
    let sub = base.join("src/sub");
    std::fs::create_dir_all(&sub).unwrap();
    let bad = sub.join(std::ffi::OsStr::from_bytes(b"bad\xff"));
    std::fs::write(&bad, "").unwrap();
    let dfd = std::fs::File::open(base).unwrap();

    let err = block_on(ostrya::remove_source_tree(
        dfd.as_fd(),
        Path::new("src"),
        Arc::default(),
    ))
    .expect_err("a name that is not valid UTF-8 is refused");
    match &err {
        ostrya::Error::ConsumeUnlink { name, .. } => assert_eq!(name, "bad\u{FFFD}"),
        other => panic!("another error: {other:?}"),
    }
    assert_eq!(
        err.to_string(),
        "unlinkat(bad\u{FFFD}): Name is not valid UTF-8"
    );
    assert!(bad.exists(), "the entry with the refused name is gone");
}

/// The environment variable that marks the re-executed child of
/// [`remove_source_tree_starts_at_the_working_directory_with_cwd`]. Its value
/// names the file that the child writes to record that the removal ran.
const REMOVE_CWD_CHILD: &str = "OSTRYA_REMOVE_CWD_CHILD";

/// With `rustix::fs::CWD` as the descriptor, a relative path starts at the
/// working directory, and a working directory with no read permission does
/// not stop the removal.
#[test]
fn remove_source_tree_starts_at_the_working_directory_with_cwd() {
    // A change of the working directory applies to the whole process, and
    // the tests of this binary run in parallel threads. For this reason, a
    // child changes it.
    if let Some(marker) = std::env::var_os(REMOVE_CWD_CHILD) {
        remove_from_the_working_directory();
        std::fs::write(marker, b"removed").expect("record that the removal ran");
        return;
    }
    let tmp = TmpDir::new("remove-cwd-marker");
    let marker = tmp.path().join("removed");
    let exe = std::env::current_exe().expect("the path of the running test binary");
    let status = std::process::Command::new(&exe)
        .arg("--exact")
        .arg("remove_source_tree_starts_at_the_working_directory_with_cwd")
        .arg("--nocapture")
        .env(REMOVE_CWD_CHILD, &marker)
        .status()
        .expect("re-run the test binary to change the working directory");
    assert!(
        status.success(),
        "the removal from the working directory failed: {status}"
    );
    assert!(
        marker.exists(),
        "the child ran no removal: the test name the filter names is stale"
    );
}

/// Removes `src` relative to the working directory through
/// `rustix::fs::CWD`, with the working directory at mode 0311. Runs in the
/// child process.
fn remove_from_the_working_directory() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TmpDir::new("remove-cwd");
    let work = tmp.path().join("work");
    let outside = tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    removal_source(&work.join("src"), &outside);
    std::env::set_current_dir(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o311)).unwrap();
    let result = block_on(ostrya::remove_source_tree(
        rustix::fs::CWD,
        Path::new("src"),
        Arc::default(),
    ));
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o755)).unwrap();
    result.unwrap();
    assert!(!work.join("src").exists(), "the removal left the source");
    assert!(work.exists(), "the removal went past the source");
}
