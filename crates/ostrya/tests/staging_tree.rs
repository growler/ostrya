//! Staging-tree integration tests (Phase 7f).
//!
//! These drive the path-addressed [`StagingTree`] surface: the equivalence
//! between a tree built through staging operations and the same tree ingested
//! from disk through `write_dfd_to_mtree`, hardlink object sharing, staged-first
//! reads that see unpublished content and follow symlink chains (failing on
//! loops and dangling targets), and the tree merge with symlink resolution
//! (a package over `/opt -> usr/opt`, a file over a `localtime` symlink, a
//! left-side symlink staged in the same transaction, and a conflict that names
//! the path). A concurrency test streams many files through one `&StagingTree`.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use common::TmpDir;
use futures_lite::{AsyncReadExt, AsyncWriteExt};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DirMeta, Error,
    FileMeta, FileObject, MergeOptions, MutableTree, Repo, RepoMode, RootDirmeta, StagingEntry,
    StagingLookup, Transaction, TreeEntry,
};
use ostrya_core::{ObjectType, Xattrs};
use ostrya_rt::block_on;

// --- small builders ---

fn reg() -> FileMeta {
    FileMeta::regular(0, 0, 0o644)
}

fn dir_meta() -> DirMeta {
    DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040755,
        xattrs: Xattrs::empty(),
    }
}

/// A symlink's mode is fixed by the object model, so only owner and xattrs
/// matter; canonical ingest zeroes the owner, so this matches a disk symlink
/// committed with canonical permissions.
fn symlink_meta() -> FileMeta {
    FileMeta {
        uid: 0,
        gid: 0,
        mode: 0,
        xattrs: Xattrs::empty(),
    }
}

/// The canonical-permissions, xattr-free flags the equivalence tests use so the
/// staging-tree build and the by-hand ingest agree on owner and mode.
fn canon_flags() -> CommitModifierFlags {
    CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mkdir(path: &Path, mode: u32) {
    std::fs::create_dir_all(path).unwrap();
    set_mode(path, mode);
}

fn write_file(path: &Path, content: &[u8], mode: u32) {
    std::fs::write(path, content).unwrap();
    set_mode(path, mode);
}

/// Stage the shared 0755 root dirmeta and return its checksum.
async fn stage_dir_meta(txn: &Transaction) -> Checksum {
    let bytes = dir_meta().serialize().unwrap();
    txn.write_metadata(ObjectType::DirMeta, None, &bytes)
        .await
        .unwrap()
}

/// Read a file object's whole payload.
async fn read_all(obj: &FileObject) -> Vec<u8> {
    let mut buf = Vec::new();
    obj.reader()
        .await
        .unwrap()
        .read_to_end(&mut buf)
        .await
        .unwrap();
    buf
}

/// Commit the on-disk tree at `path` (relative to `dfd`) onto `refname` with
/// canonical permissions, so it can be hydrated with `MutableTree::from_commit`.
async fn commit_dir(repo: &Repo, dfd: std::os::fd::BorrowedFd<'_>, path: &Path, refname: &str) {
    let txn = repo.transaction().await.unwrap();
    let mut modifier = CommitModifier::new(canon_flags());
    let mut mtree = MutableTree::new();
    txn.write_dfd_to_mtree(dfd, path, &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(CommitOptions::default(), &root)
        .await
        .unwrap();
    txn.set_ref(refname, Some(&commit));
    txn.commit().await.unwrap();
}

/// Count loose objects under `<repo_root>/objects` whose filename ends in
/// `ext`, scanning only the two-character fanout directories.
fn count_objects_with_ext(repo_root: &Path, ext: &str) -> usize {
    let objects = repo_root.join("objects");
    let mut count = 0;
    for fanout in std::fs::read_dir(&objects).unwrap() {
        let fanout = fanout.unwrap();
        if fanout.file_name().len() != 2 || !fanout.file_type().unwrap().is_dir() {
            continue;
        }
        for obj in std::fs::read_dir(fanout.path()).unwrap() {
            if obj.unwrap().file_name().to_string_lossy().ends_with(ext) {
                count += 1;
            }
        }
    }
    count
}

/// The content checksum of the file `name` under directory `dir` in `tree`.
async fn lookup_file(tree: &ostrya::RepoTree, path: &str) -> Checksum {
    match tree.lookup(Path::new(path)).await.unwrap() {
        Some(TreeEntry::File { checksum, .. }) => checksum,
        other => panic!("{path} is not a file: {other:?}"),
    }
}

#[test]
fn builds_same_tree_as_write_dfd_to_mtree() {
    // A tree assembled through staging-tree operations reaches the same root
    // dirtree and dirmeta as ingesting the equivalent on-disk tree.
    let tmp = TmpDir::new("staging-equiv");
    let base = tmp.path();

    // The scratch tree on disk.
    let scratch = base.join("scratch");
    mkdir(&scratch, 0o755);
    write_file(&scratch.join("a.txt"), b"aaa", 0o644);
    std::os::unix::fs::symlink("a.txt", scratch.join("link")).unwrap();
    mkdir(&scratch.join("sub"), 0o755);
    write_file(&scratch.join("sub/b.txt"), b"bbb", 0o644);
    mkdir(&scratch.join("sub/deep"), 0o755);
    write_file(&scratch.join("sub/deep/c.txt"), b"ccc", 0o644);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();

        // The by-hand ingest.
        let txn = repo.transaction().await.unwrap();
        let mut modifier = CommitModifier::new(canon_flags());
        let mut ingested = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("scratch"),
            &mut ingested,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let ingest_root = txn.write_mtree(&mut ingested).await.unwrap();
        let ingest_dirtree = *ingest_root.dirtree_checksum();
        let ingest_dirmeta = *ingest_root.dirmeta_checksum();
        txn.abort().await.unwrap();

        // The staging-tree build.
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let st = txn.staging_tree(None).await.unwrap();
        st.write_file_content(Path::new("a.txt"), &reg(), b"aaa")
            .await
            .unwrap();
        st.symlink(Path::new("link"), Path::new("a.txt"), &symlink_meta())
            .await
            .unwrap();
        st.make_dir_all(Path::new("sub/deep"), &dir_meta())
            .await
            .unwrap();
        st.write_file_content(Path::new("sub/b.txt"), &reg(), b"bbb")
            .await
            .unwrap();
        st.write_file_content(Path::new("sub/deep/c.txt"), &reg(), b"ccc")
            .await
            .unwrap();
        let mut built = st.close().unwrap();
        built.set_metadata_checksum(root_dm);
        let built_root = txn.write_mtree(&mut built).await.unwrap();

        assert_eq!(
            *built_root.dirtree_checksum(),
            ingest_dirtree,
            "staging-tree root dirtree equals the by-hand ingest"
        );
        assert_eq!(
            *built_root.dirmeta_checksum(),
            ingest_dirmeta,
            "staging-tree root dirmeta equals the by-hand ingest"
        );
        txn.abort().await.unwrap();
    });
}

#[test]
fn hardlinked_paths_share_one_content_object() {
    let tmp = TmpDir::new("staging-hardlink");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let st = txn.staging_tree(None).await.unwrap();
        st.write_file_content(Path::new("orig.txt"), &reg(), b"shared")
            .await
            .unwrap();
        st.hardlink(Path::new("copy.txt"), Path::new("orig.txt"))
            .await
            .unwrap();
        let mut built = st.close().unwrap();
        built.set_metadata_checksum(root_dm);
        let built_root = txn.write_mtree(&mut built).await.unwrap();
        let root_dirtree = *built_root.dirtree_checksum();
        let stats = txn.commit().await.unwrap();
        // One content object for both paths, plus the one dirmeta.
        assert_eq!(
            stats.content_written, 1,
            "the hardlink stages no new object"
        );

        let repo = Repo::open(&root).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let orig = tree.files.iter().find(|(n, _)| n == "orig.txt").unwrap().1;
        let copy = tree.files.iter().find(|(n, _)| n == "copy.txt").unwrap().1;
        assert_eq!(orig, copy, "both entries name the same content object");
    });
}

#[test]
fn reads_staged_content_and_follows_symlinks() {
    let tmp = TmpDir::new("staging-reads");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir(Path::new("d"), &dir_meta()).await.unwrap();
        st.write_file_content(Path::new("d/f.txt"), &reg(), b"hello staged")
            .await
            .unwrap();
        st.symlink(Path::new("d/link"), Path::new("f.txt"), &symlink_meta())
            .await
            .unwrap();
        st.symlink(Path::new("abs"), Path::new("/d/f.txt"), &symlink_meta())
            .await
            .unwrap();

        // Staged, unpublished content reads back.
        let f = st.read_file(Path::new("d/f.txt"), false).await.unwrap();
        assert_eq!(read_all(&f).await, b"hello staged");

        // A relative symlink followed to its target.
        let via_rel = st.read_file(Path::new("d/link"), true).await.unwrap();
        assert_eq!(read_all(&via_rel).await, b"hello staged");

        // The same symlink, not followed, is the symlink object itself.
        let link = st.read_file(Path::new("d/link"), false).await.unwrap();
        assert!(link.is_symlink(), "not following yields the symlink object");

        // An absolute symlink resolves from the tree root.
        let via_abs = st.read_file(Path::new("abs"), true).await.unwrap();
        assert_eq!(read_all(&via_abs).await, b"hello staged");

        // read_dir sees the staged directory.
        let entries = st.read_dir(Path::new("d"), false).await.unwrap();
        let names: Vec<&str> = entries
            .iter()
            .map(|e| match e {
                StagingEntry::File { name, .. } => name.as_str(),
                StagingEntry::Dir { name } => name.as_str(),
            })
            .collect();
        assert_eq!(names, vec!["f.txt", "link"], "files listed name-sorted");

        let root_entries = st.read_dir(Path::new("/"), false).await.unwrap();
        assert!(
            root_entries
                .iter()
                .any(|e| matches!(e, StagingEntry::Dir { name } if name == "d")),
            "the staged directory shows at the root"
        );

        // A symlink loop fails.
        st.symlink(Path::new("loop1"), Path::new("loop2"), &symlink_meta())
            .await
            .unwrap();
        st.symlink(Path::new("loop2"), Path::new("loop1"), &symlink_meta())
            .await
            .unwrap();
        let err = st.read_file(Path::new("loop1"), true).await.unwrap_err();
        assert!(
            matches!(err, Error::SymlinkLoop { .. }),
            "a loop is an error: {err:?}"
        );

        // A dangling target fails.
        st.symlink(Path::new("dangling"), Path::new("nowhere"), &symlink_meta())
            .await
            .unwrap();
        let err = st.read_file(Path::new("dangling"), true).await.unwrap_err();
        assert!(
            matches!(err, Error::DanglingSymlink { .. }),
            "a dangling target is an error: {err:?}"
        );

        drop(st);
        txn.abort().await.unwrap();
    });
}

#[test]
fn package_merges_through_opt_symlink() {
    // A package tree merged over a base holding `/opt -> usr/opt` lands its
    // files under `usr/opt` when symlinks are followed.
    let tmp = TmpDir::new("staging-merge-opt");
    let base = tmp.path();

    let base_src = base.join("base");
    mkdir(&base_src, 0o755);
    mkdir(&base_src.join("usr"), 0o755);
    mkdir(&base_src.join("usr/opt"), 0o755);
    write_file(&base_src.join("usr/opt/keep.txt"), b"keep", 0o644);
    std::os::unix::fs::symlink("usr/opt", base_src.join("opt")).unwrap();

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        commit_dir(&repo, dfd.as_fd(), Path::new("base"), "test/base").await;

        let txn = repo.transaction().await.unwrap();

        // The package tree: /opt/foo.txt (opt is a plain directory here).
        let pkg_st = txn.staging_tree(None).await.unwrap();
        pkg_st
            .make_dir(Path::new("opt"), &dir_meta())
            .await
            .unwrap();
        pkg_st
            .write_file_content(Path::new("opt/foo.txt"), &reg(), b"foo")
            .await
            .unwrap();
        let package = pkg_st.close().unwrap();

        // The base, hydrated, merged with symlink following.
        let base_mtree = MutableTree::from_commit(&repo, "test/base").await.unwrap();
        let base_st = txn.staging_tree_from_mutable_tree(base_mtree);
        base_st
            .merge(
                &package,
                MergeOptions {
                    allow_overwrite: false,
                    follow_symlinks: true,
                    ..MergeOptions::default()
                },
            )
            .await
            .unwrap();
        let mut merged = base_st.close().unwrap();
        let root = txn.write_mtree(&mut merged).await.unwrap();
        let commit = txn
            .write_commit(CommitOptions::default(), &root)
            .await
            .unwrap();
        txn.set_ref("test/merged", Some(&commit));
        txn.commit().await.unwrap();

        let repo = Repo::open(&base.join("repo")).await.unwrap();
        let (tree, _) = repo.read_commit("test/merged").await.unwrap();
        // `opt` is still a symlink, not a directory.
        assert!(
            matches!(
                tree.lookup(Path::new("opt")).await.unwrap(),
                Some(TreeEntry::File { .. })
            ),
            "/opt stays a symlink"
        );
        // foo.txt and keep.txt both live under usr/opt.
        let foo = lookup_file(&tree, "usr/opt/foo.txt").await;
        assert_eq!(read_all(&repo.load_file(&foo).await.unwrap()).await, b"foo");
        let _keep = lookup_file(&tree, "usr/opt/keep.txt").await;
    });
}

#[test]
fn file_over_localtime_symlink_replaces_without_writing_through() {
    // A file merged over `etc/localtime -> /usr/share/zoneinfo/UTC` replaces the
    // symlink and leaves the zoneinfo object untouched.
    let tmp = TmpDir::new("staging-merge-localtime");
    let base = tmp.path();

    let base_src = base.join("base");
    mkdir(&base_src, 0o755);
    mkdir(&base_src.join("etc"), 0o755);
    std::os::unix::fs::symlink("/usr/share/zoneinfo/UTC", base_src.join("etc/localtime")).unwrap();
    mkdir(&base_src.join("usr"), 0o755);
    mkdir(&base_src.join("usr/share"), 0o755);
    mkdir(&base_src.join("usr/share/zoneinfo"), 0o755);
    write_file(
        &base_src.join("usr/share/zoneinfo/UTC"),
        b"UTC-zone-data",
        0o644,
    );

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        commit_dir(&repo, dfd.as_fd(), Path::new("base"), "test/base").await;

        let txn = repo.transaction().await.unwrap();

        // The package: a real file at etc/localtime.
        let pkg_st = txn.staging_tree(None).await.unwrap();
        pkg_st
            .make_dir(Path::new("etc"), &dir_meta())
            .await
            .unwrap();
        pkg_st
            .write_file_content(Path::new("etc/localtime"), &reg(), b"TZ override")
            .await
            .unwrap();
        let package = pkg_st.close().unwrap();

        let base_mtree = MutableTree::from_commit(&repo, "test/base").await.unwrap();
        let base_st = txn.staging_tree_from_mutable_tree(base_mtree);
        base_st
            .merge(
                &package,
                MergeOptions {
                    allow_overwrite: true,
                    follow_symlinks: true,
                    ..MergeOptions::default()
                },
            )
            .await
            .unwrap();
        let mut merged = base_st.close().unwrap();
        let root = txn.write_mtree(&mut merged).await.unwrap();
        let commit = txn
            .write_commit(CommitOptions::default(), &root)
            .await
            .unwrap();
        txn.set_ref("test/merged", Some(&commit));
        txn.commit().await.unwrap();

        let repo = Repo::open(&base.join("repo")).await.unwrap();
        let (tree, _) = repo.read_commit("test/merged").await.unwrap();

        // etc/localtime is now a regular file with the override content.
        let localtime = lookup_file(&tree, "etc/localtime").await;
        let obj = repo.load_file(&localtime).await.unwrap();
        assert!(!obj.is_symlink(), "the symlink was replaced by a file");
        assert_eq!(read_all(&obj).await, b"TZ override");

        // The zoneinfo target object is untouched.
        let utc = lookup_file(&tree, "usr/share/zoneinfo/UTC").await;
        assert_eq!(
            read_all(&repo.load_file(&utc).await.unwrap()).await,
            b"UTC-zone-data",
            "the symlink's former target is left in place"
        );
    });
}

#[test]
fn merge_resolves_a_symlink_staged_in_this_transaction() {
    // The left-side symlink `/opt -> usr/opt` is staged in the current
    // transaction, not committed. Resolving it during the merge exercises the
    // staged-first object lookup: a plain objects/ lookup would not find it.
    let tmp = TmpDir::new("staging-merge-staged-symlink");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;

        // The package: /opt/foo.txt.
        let pkg_st = txn.staging_tree(None).await.unwrap();
        pkg_st
            .make_dir(Path::new("opt"), &dir_meta())
            .await
            .unwrap();
        pkg_st
            .write_file_content(Path::new("opt/foo.txt"), &reg(), b"foo")
            .await
            .unwrap();
        let package = pkg_st.close().unwrap();

        // The left tree, built and staged in this same transaction.
        let base_st = txn.staging_tree(None).await.unwrap();
        base_st
            .make_dir_all(Path::new("usr/opt"), &dir_meta())
            .await
            .unwrap();
        base_st
            .symlink(Path::new("opt"), Path::new("usr/opt"), &symlink_meta())
            .await
            .unwrap();
        base_st
            .merge(
                &package,
                MergeOptions {
                    allow_overwrite: false,
                    follow_symlinks: true,
                    ..MergeOptions::default()
                },
            )
            .await
            .unwrap();
        let mut merged = base_st.close().unwrap();
        merged.set_metadata_checksum(root_dm);
        let root_tree = txn.write_mtree(&mut merged).await.unwrap();
        let commit = txn
            .write_commit(CommitOptions::default(), &root_tree)
            .await
            .unwrap();
        txn.set_ref("test/merged", Some(&commit));
        txn.commit().await.unwrap();

        let repo = Repo::open(&root).await.unwrap();
        let (tree, _) = repo.read_commit("test/merged").await.unwrap();
        let foo = lookup_file(&tree, "usr/opt/foo.txt").await;
        assert_eq!(read_all(&repo.load_file(&foo).await.unwrap()).await, b"foo");
        assert!(
            matches!(
                tree.lookup(Path::new("opt")).await.unwrap(),
                Some(TreeEntry::File { .. })
            ),
            "/opt stays a symlink"
        );
    });
}

#[test]
fn merge_reads_committed_right_side_subtrees() {
    // The right side of a merge is a tree hydrated from a commit, so its
    // subdirectories arrive as lazy children resolved through the right-side
    // committed dirtree load. Existing merge tests pass a freshly built (all
    // loaded) right side, so this is the only coverage of that path. The
    // dirtrees here are published, so it does not distinguish staged-first from
    // objects-only: a staged-but-unpublished right-side dirtree is unreachable
    // through the current public API (a lazy child comes only from a
    // hydrated-from-commit tree, whose dirtrees are already published).
    let tmp = TmpDir::new("staging-merge-committed-right");
    let base = tmp.path();

    let pkg = base.join("pkg");
    mkdir(&pkg, 0o755);
    mkdir(&pkg.join("opt"), 0o755);
    write_file(&pkg.join("opt/foo.txt"), b"foo", 0o644);
    mkdir(&pkg.join("opt/sub"), 0o755);
    write_file(&pkg.join("opt/sub/bar.txt"), b"bar", 0o644);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        commit_dir(&repo, dfd.as_fd(), Path::new("pkg"), "test/pkg").await;

        let txn = repo.transaction().await.unwrap();

        // The right side: the package hydrated from its commit, so `opt` and
        // `opt/sub` arrive as lazy (committed) children.
        let pkg_tree = MutableTree::from_commit(&repo, "test/pkg").await.unwrap();

        // The left side: an empty staging tree the package merges into.
        let base_st = txn.staging_tree(None).await.unwrap();
        base_st
            .merge(
                &pkg_tree,
                MergeOptions {
                    allow_overwrite: false,
                    follow_symlinks: false,
                    ..MergeOptions::default()
                },
            )
            .await
            .unwrap();
        let mut merged = base_st.close().unwrap();
        let root = txn.write_mtree(&mut merged).await.unwrap();
        let commit = txn
            .write_commit(CommitOptions::default(), &root)
            .await
            .unwrap();
        txn.set_ref("test/merged", Some(&commit));
        txn.commit().await.unwrap();

        let repo = Repo::open(&base.join("repo")).await.unwrap();
        let (tree, _) = repo.read_commit("test/merged").await.unwrap();
        let foo = lookup_file(&tree, "opt/foo.txt").await;
        assert_eq!(read_all(&repo.load_file(&foo).await.unwrap()).await, b"foo");
        let bar = lookup_file(&tree, "opt/sub/bar.txt").await;
        assert_eq!(read_all(&repo.load_file(&bar).await.unwrap()).await, b"bar");
    });
}

#[test]
fn merge_conflict_names_the_path() {
    let tmp = TmpDir::new("staging-merge-conflict");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();

        let pkg_st = txn.staging_tree(None).await.unwrap();
        pkg_st
            .write_file_content(Path::new("a.txt"), &reg(), b"package")
            .await
            .unwrap();
        let package = pkg_st.close().unwrap();

        let base_st = txn.staging_tree(None).await.unwrap();
        base_st
            .write_file_content(Path::new("a.txt"), &reg(), b"base")
            .await
            .unwrap();
        let err = base_st
            .merge(&package, MergeOptions::default())
            .await
            .unwrap_err();
        match err {
            Error::MergeConflict(msg) => {
                assert_eq!(msg, "file differs at a.txt", "the conflict names the path");
            }
            other => panic!("expected a merge conflict, got {other:?}"),
        }
        drop(base_st);
        txn.abort().await.unwrap();
    });
}

#[test]
fn concurrent_write_file_streams_land_correctly() {
    let tmp = TmpDir::new("staging-concurrent");
    let root = tmp.path().join("repo");
    let repo = block_on(Repo::create(&root, CreateOptions::new(RepoMode::BareUser))).unwrap();
    let txn = block_on(repo.transaction()).unwrap();
    let root_dm = block_on(stage_dir_meta(&txn));
    let st = block_on(txn.staging_tree(None)).unwrap();

    const N: usize = 8;
    let payloads: Vec<(String, Vec<u8>)> = (0..N)
        .map(|i| {
            (
                format!("f{i}.txt"),
                format!("payload number {i}\n").into_bytes(),
            )
        })
        .collect();

    std::thread::scope(|scope| {
        for (name, payload) in &payloads {
            let st = &st;
            scope.spawn(move || {
                block_on(async {
                    let mut writer = st.write_file(Path::new(name), &reg()).await.unwrap();
                    writer.write_all(payload).await.unwrap();
                    writer.finish().await.unwrap();
                });
            });
        }
    });

    let mut built = st.close().unwrap();
    built.set_metadata_checksum(root_dm);
    let built_root = block_on(txn.write_mtree(&mut built)).unwrap();
    let root_dirtree = *built_root.dirtree_checksum();
    let stats = block_on(txn.commit()).unwrap();
    assert_eq!(
        stats.content_written as usize, N,
        "each writer staged one object"
    );

    block_on(async {
        let repo = Repo::open(&root).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        assert_eq!(tree.files.len(), N, "every file landed");
        for (name, payload) in &payloads {
            let checksum = tree.files.iter().find(|(n, _)| n == name).unwrap().1;
            let obj = repo.load_file(&checksum).await.unwrap();
            assert_eq!(&read_all(&obj).await, payload, "{name} content");
        }
    });
}

/// `close` refuses while a file writer is still outstanding.
#[test]
fn close_fails_with_an_outstanding_writer() {
    let tmp = TmpDir::new("staging-close-guard");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();
        let writer = st.write_file(Path::new("f.txt"), &reg()).await.unwrap();
        // A different handle cannot be closed while a writer is live; keep the
        // writer alive across the check.
        match st.close() {
            Err(Error::Staging(msg)) => {
                assert_eq!(
                    msg, "cannot close the staging tree: 1 file writer(s) still outstanding",
                    "the refusal carries the outstanding count"
                );
            }
            other => panic!("close is refused while a writer is outstanding: {other:?}"),
        }
        drop(writer);
        txn.abort().await.unwrap();
    });
}

/// A `make_dir_all` whose path components all already exist creates nothing, so
/// a novel dirmeta it carries must not be staged: were it staged, commit would
/// publish it as an orphan object.
#[test]
fn no_op_make_dir_all_stages_no_orphan_dirmeta() {
    let tmp = TmpDir::new("staging-make-dir-all-noop");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let st = txn.staging_tree(None).await.unwrap();

        // Create a/b with the shared 0755 dirmeta.
        st.make_dir_all(Path::new("a/b"), &dir_meta())
            .await
            .unwrap();

        // A no-op call over the same, existing path carrying a novel dirmeta (a
        // distinct mode used nowhere in the tree). Nothing is created.
        let novel = DirMeta {
            uid: 0,
            gid: 0,
            mode: 0o040700,
            xattrs: Xattrs::empty(),
        };
        st.make_dir_all(Path::new("a/b"), &novel).await.unwrap();

        let mut built = st.close().unwrap();
        built.set_metadata_checksum(root_dm);
        txn.write_mtree(&mut built).await.unwrap();
        txn.commit().await.unwrap();

        // root, a, and b all carry the 0755 dirmeta, so exactly one dirmeta
        // object is published; the novel one was never staged.
        assert_eq!(
            count_objects_with_ext(&root, ".dirmeta"),
            1,
            "the no-op make_dir_all published no orphan dirmeta"
        );
    });
}

/// A non-UTF-8 path component is rejected rather than silently converted with
/// replacement characters. The tree is `String`-keyed, so a lossy name would
/// address the wrong entry; `symlink` already rejects a non-UTF-8 target, and
/// the path entry points agree.
#[test]
fn non_utf8_path_component_is_rejected() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let tmp = TmpDir::new("staging-non-utf8");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        let bad = Path::new(OsStr::from_bytes(b"bad\xffname"));
        let err = st.make_dir_all(bad, &dir_meta()).await.unwrap_err();
        assert!(
            matches!(&err, Error::Staging(msg) if msg.contains("not valid UTF-8")),
            "a non-UTF-8 path component is rejected: {err:?}"
        );

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// Each staging refusal carries its own variant and names the path the walk
/// stopped at, so a consumer branches on the condition instead of matching a
/// message. The path a walk reports is the literal path resolution reached,
/// which is the symlink-resolved form rather than the path as given.
#[test]
fn staging_refusals_are_typed_by_condition() {
    let tmp = TmpDir::new("staging-typed-errors");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir(Path::new("d"), &dir_meta()).await.unwrap();
        st.write_file_content(Path::new("f.txt"), &reg(), b"content")
            .await
            .unwrap();
        st.symlink(Path::new("dangling"), Path::new("nowhere"), &symlink_meta())
            .await
            .unwrap();
        st.symlink(Path::new("loop1"), Path::new("loop2"), &symlink_meta())
            .await
            .unwrap();
        st.symlink(Path::new("loop2"), Path::new("loop1"), &symlink_meta())
            .await
            .unwrap();

        // An absent component along the path.
        match st.read_file(Path::new("missing/f.txt"), false).await {
            Err(Error::PathNotFound { path }) => assert_eq!(path, "missing"),
            other => panic!("expected PathNotFound, got {other:?}"),
        }
        // The same condition on a write, reported from the parent resolution.
        match st
            .write_file_content(Path::new("missing/f.txt"), &reg(), b"x")
            .await
        {
            Err(Error::PathNotFound { path }) => assert_eq!(path, "missing"),
            other => panic!("expected PathNotFound, got {other:?}"),
        }

        // A regular file where the walk needed a directory.
        match st.read_file(Path::new("f.txt/inner"), false).await {
            Err(Error::NotADirectory { path }) => assert_eq!(path, "f.txt"),
            other => panic!("expected NotADirectory, got {other:?}"),
        }
        // The same, where the file is the final component of a parent path.
        match st
            .write_file_content(Path::new("f.txt/inner"), &reg(), b"x")
            .await
        {
            Err(Error::NotADirectory { path }) => assert_eq!(path, "f.txt"),
            other => panic!("expected NotADirectory, got {other:?}"),
        }
        // And through make_dir_all, which resolves its own components.
        match st.make_dir_all(Path::new("f.txt/inner"), &dir_meta()).await {
            Err(Error::NotADirectory { path }) => assert_eq!(path, "f.txt"),
            other => panic!("expected NotADirectory, got {other:?}"),
        }

        // A symlink whose target does not resolve.
        match st.read_file(Path::new("dangling"), true).await {
            Err(Error::DanglingSymlink { path, target }) => {
                assert_eq!(path, "dangling");
                assert_eq!(target, "nowhere");
            }
            other => panic!("expected DanglingSymlink, got {other:?}"),
        }

        // A symlink chain past the depth cap. The name the refusal carries is
        // fixed: the walk starts at `loop1` and the two links alternate, so
        // visit n resolves `loop1` for odd n and `loop2` for even n. Visit n
        // raises the depth to n, and the cap refuses the first visit with a
        // depth above MAX_SYMLINK_DEPTH (40), which is visit 41. 41 is odd, so
        // the refusal names `loop1`.
        match st.read_file(Path::new("loop1"), true).await {
            Err(Error::SymlinkLoop { path }) => assert_eq!(path, "loop1"),
            other => panic!("expected SymlinkLoop, got {other:?}"),
        }

        // An operation that requires a fresh entry.
        match st.make_dir(Path::new("d"), &dir_meta()).await {
            Err(Error::EntryExists { path }) => assert_eq!(path, "d"),
            other => panic!("expected EntryExists, got {other:?}"),
        }

        // A directory where a write wanted a file, from the checked path.
        match st.write_file_content(Path::new("d"), &reg(), b"x").await {
            Err(Error::ReplaceDirWithFile(name)) => assert_eq!(name, "d"),
            other => panic!("expected ReplaceDirWithFile, got {other:?}"),
        }
        // A directory where a read wanted a file stays in `Staging`.
        match st.read_file(Path::new("d"), false).await {
            Err(Error::Staging(msg)) => {
                assert_eq!(msg, "d is a directory, not a file");
            }
            other => panic!("expected Staging, got {other:?}"),
        }
        // A hardlink whose source resolves to a directory stays in `Staging`.
        match st.hardlink(Path::new("copy"), Path::new("d")).await {
            Err(Error::Staging(msg)) => {
                assert_eq!(msg, "cannot hardlink from d: the source is a directory");
            }
            other => panic!("expected Staging, got {other:?}"),
        }

        // read_dir over a file is the not-a-directory condition. It sits
        // outside the walker.
        match st.read_dir(Path::new("f.txt"), false).await {
            Err(Error::NotADirectory { path }) => assert_eq!(path, "f.txt"),
            other => panic!("expected NotADirectory, got {other:?}"),
        }

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// A symlink whose target resolves does not shadow an absent component reached
/// under it: once the target is spent, the walk is back on the caller's own
/// components, so an absent entry is the path-not-found condition. `opt ->
/// usr/opt` is the alias the merge tests build, and both the read path and the
/// write path (through `resolve_parent`) reach the same walk.
#[test]
fn absent_under_a_resolved_symlink_is_path_not_found() {
    let tmp = TmpDir::new("staging-absent-under-symlink");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir_all(Path::new("usr/opt"), &dir_meta())
            .await
            .unwrap();
        st.symlink(Path::new("opt"), Path::new("usr/opt"), &symlink_meta())
            .await
            .unwrap();

        // The read side: the walk crosses `opt`, resolves it, and stops at the
        // absent entry under the target.
        match st.read_file(Path::new("opt/absent"), false).await {
            Err(Error::PathNotFound { path }) => assert_eq!(path, "usr/opt/absent"),
            other => panic!("expected PathNotFound, got {other:?}"),
        }

        // The write side reaches the same walk through `resolve_parent`.
        match st
            .write_file_content(Path::new("opt/absent/f.txt"), &reg(), b"x")
            .await
        {
            Err(Error::PathNotFound { path }) => assert_eq!(path, "usr/opt/absent"),
            other => panic!("expected PathNotFound, got {other:?}"),
        }

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// With one symlink reached through another, the refusal names the innermost
/// symlink whose target is still being consumed. `a -> b` resolves; `b`'s own
/// target is the one that does not, so `b` is what the walk reports.
#[test]
fn nested_symlinks_name_the_innermost_open_symlink() {
    let tmp = TmpDir::new("staging-nested-symlinks");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir(Path::new("c"), &dir_meta()).await.unwrap();
        st.symlink(Path::new("a"), Path::new("b"), &symlink_meta())
            .await
            .unwrap();
        st.symlink(Path::new("b"), Path::new("c/missing"), &symlink_meta())
            .await
            .unwrap();

        match st.read_file(Path::new("a"), true).await {
            Err(Error::DanglingSymlink { path, target }) => {
                assert_eq!(path, "b");
                assert_eq!(target, "c/missing");
            }
            other => panic!("expected DanglingSymlink, got {other:?}"),
        }

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// Every refusal names the resolved literal component path, so an operation
/// reached through the alias `opt -> usr/opt` reports the `usr/opt` form for the
/// conditions raised outside the walker as well: the existing entry `make_dir`
/// refuses and the file `read_dir` refuses. The write over a directory is the
/// carve-out: `ReplaceDirWithFile` names the entry, because the mutable-tree
/// layer raises it and that layer is addressed by name.
#[test]
fn refusals_through_a_symlinked_parent_name_the_resolved_path() {
    let tmp = TmpDir::new("staging-resolved-refusal-paths");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir_all(Path::new("usr/opt/d"), &dir_meta())
            .await
            .unwrap();
        st.write_file_content(Path::new("usr/opt/f.txt"), &reg(), b"content")
            .await
            .unwrap();
        st.symlink(Path::new("opt"), Path::new("usr/opt"), &symlink_meta())
            .await
            .unwrap();

        // An operation that requires a fresh entry, refused at the alias.
        match st.make_dir(Path::new("opt/d"), &dir_meta()).await {
            Err(Error::EntryExists { path }) => assert_eq!(path, "usr/opt/d"),
            other => panic!("expected EntryExists, got {other:?}"),
        }

        // A write over a directory, reached through the alias, names the entry.
        match st
            .write_file_content(Path::new("opt/d"), &reg(), b"x")
            .await
        {
            Err(Error::ReplaceDirWithFile(name)) => assert_eq!(name, "d"),
            other => panic!("expected ReplaceDirWithFile, got {other:?}"),
        }

        // A listing of a file, refused at the alias.
        match st.read_dir(Path::new("opt/f.txt"), false).await {
            Err(Error::NotADirectory { path }) => assert_eq!(path, "usr/opt/f.txt"),
            other => panic!("expected NotADirectory, got {other:?}"),
        }

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// A directory in the way of a write is one condition, whichever moment the
/// directory appeared at. The check in `write_file`/`write_file_content` and
/// the record step a raced directory reaches both refuse with
/// [`Error::ReplaceDirWithFile`] naming the entry, because the mutable-tree
/// layer raises it and that layer is addressed by name, and both convert to
/// `io::ErrorKind::AlreadyExists`. A `StagedFileWriter` is a handle held
/// across calls, so the interleave needs no threads.
#[test]
fn checked_and_raced_directory_clash_report_one_variant() {
    use std::io;

    let tmp = TmpDir::new("staging-checked-vs-raced");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir(Path::new("d"), &dir_meta()).await.unwrap();

        // The checked half: the directory is already there when the check runs.
        st.make_dir(Path::new("d/sub"), &dir_meta()).await.unwrap();
        let err = st
            .write_file_content(Path::new("d/sub"), &reg(), b"x")
            .await
            .unwrap_err();
        match &err {
            Error::ReplaceDirWithFile(name) => {
                assert_eq!(name, "sub", "the checked refusal names the entry");
            }
            other => panic!("expected ReplaceDirWithFile, got {other:?}"),
        }
        assert_eq!(io::Error::from(err).kind(), io::ErrorKind::AlreadyExists);

        // The raced half: the check passed, then the directory appeared.
        let mut writer = st.write_file(Path::new("d/raced"), &reg()).await.unwrap();
        writer.write_all(b"x").await.unwrap();
        st.make_dir(Path::new("d/raced"), &dir_meta())
            .await
            .unwrap();
        let err = writer.finish().await.unwrap_err();
        match &err {
            Error::ReplaceDirWithFile(name) => {
                assert_eq!(name, "raced", "the raced refusal names the entry");
            }
            other => panic!("expected ReplaceDirWithFile, got {other:?}"),
        }
        assert_eq!(io::Error::from(err).kind(), io::ErrorKind::AlreadyExists);

        // The failed `finish` released its writer slot, so the tree still closes.
        st.close().unwrap();
        txn.abort().await.unwrap();
    });
}

/// A merge that follows a left-side symlink resolving to a regular file reports
/// the not-a-directory condition. The refusal comes from the merge's symlink
/// resolution, which is the third re-typed site outside the walker.
#[test]
fn merge_through_a_symlink_to_a_file_is_not_a_directory() {
    let tmp = TmpDir::new("staging-merge-symlink-to-file");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();

        // The right side holds a directory named `link`.
        let pkg_st = txn.staging_tree(None).await.unwrap();
        pkg_st
            .make_dir(Path::new("link"), &dir_meta())
            .await
            .unwrap();
        pkg_st
            .write_file_content(Path::new("link/foo.txt"), &reg(), b"foo")
            .await
            .unwrap();
        let package = pkg_st.close().unwrap();

        // The left side has `link -> f.txt`, a symlink to a regular file, so
        // following it reaches no directory to merge into.
        let base_st = txn.staging_tree(None).await.unwrap();
        base_st
            .write_file_content(Path::new("f.txt"), &reg(), b"base")
            .await
            .unwrap();
        base_st
            .symlink(Path::new("link"), Path::new("f.txt"), &symlink_meta())
            .await
            .unwrap();

        let err = base_st
            .merge(
                &package,
                MergeOptions {
                    allow_overwrite: false,
                    follow_symlinks: true,
                    ..MergeOptions::default()
                },
            )
            .await
            .unwrap_err();
        match err {
            Error::NotADirectory { path } => assert_eq!(path, "f.txt"),
            other => panic!("expected NotADirectory, got {other:?}"),
        }

        drop(base_st);
        txn.abort().await.unwrap();
    });
}

/// The tree root has no components, so a refusal that names the whole path
/// spells it `.`. Both the walker's directory end and the merge's root dirmeta
/// conflict reach that spelling.
#[test]
fn a_refusal_at_the_tree_root_spells_it_as_a_dot() {
    let tmp = TmpDir::new("staging-root-path-form");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();

        // The right side's root carries a dirmeta the left side's root does not,
        // so the merge conflicts on the root's own metadata before it descends.
        let shared = stage_dir_meta(&txn).await;
        let novel = DirMeta {
            uid: 0,
            gid: 0,
            mode: 0o040700,
            xattrs: Xattrs::empty(),
        };
        let novel = txn
            .write_metadata(ObjectType::DirMeta, None, &novel.serialize().unwrap())
            .await
            .unwrap();

        let mut package = MutableTree::new();
        package.set_metadata_checksum(novel);
        let mut base = MutableTree::new();
        base.set_metadata_checksum(shared);
        let base_st = txn.staging_tree_from_mutable_tree(base);

        // A read of `.` resolves to no components, so the walk ends on the root.
        match base_st.read_file(Path::new("."), false).await {
            Err(Error::Staging(msg)) => assert_eq!(msg, ". is a directory, not a file"),
            other => panic!("expected Staging, got {other:?}"),
        }

        let err = base_st
            .merge(&package, MergeOptions::default())
            .await
            .unwrap_err();
        match err {
            Error::MergeConflict(msg) => assert_eq!(msg, "directory metadata differs at ."),
            other => panic!("expected a merge conflict, got {other:?}"),
        }

        drop(base_st);
        txn.abort().await.unwrap();
    });
}

/// The new value types are `Send + Sync` (the lifetime-bearing types are pinned
/// by compile-time assertions inside the crate).
#[test]
fn value_types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MergeOptions>();
    assert_send_sync::<StagingEntry>();
    assert_send_sync::<StagingLookup>();
}

/// A dirmeta with the given full mode, for tests that need one distinct from
/// the shared 0755 dirmeta.
fn dir_meta_mode(mode: u32) -> DirMeta {
    DirMeta {
        uid: 0,
        gid: 0,
        mode,
        xattrs: Xattrs::empty(),
    }
}

/// Remove one loose object file, so a later read of it fails. Used to prove an
/// operation does not read the object: with the file gone, a read errors, so an
/// operation that succeeds provably never issued one.
fn delete_loose_object(repo_root: &Path, checksum: &Checksum, ext: &str) {
    let hex = checksum.to_hex();
    let path = repo_root
        .join("objects")
        .join(&hex[..2])
        .join(format!("{}.{ext}", &hex[2..]));
    std::fs::remove_file(&path).unwrap();
}

/// The dirtree and dirmeta checksums of the committed subdirectory `name`
/// directly under `rev`'s root, plus the root's own dirtree checksum.
async fn committed_subdir(repo: &Repo, rev: &str, name: &str) -> (Checksum, Checksum, Checksum) {
    let (tree, _) = repo.read_commit(rev).await.unwrap();
    let root_dirtree = *tree.dirtree_checksum();
    match tree.lookup(Path::new(name)).await.unwrap() {
        Some(TreeEntry::Dir { tree: sub, .. }) => (
            *sub.dirtree_checksum(),
            *sub.dirmeta_checksum(),
            root_dirtree,
        ),
        other => panic!("{name} is not a committed directory: {other:?}"),
    }
}

/// `lookup` answers `Absent` for a missing component anywhere along the path,
/// and reports files, symlinks, and directories by kind. A symlink's final
/// component follows only with `follow_symlinks`.
#[test]
fn lookup_reports_kind_and_absent_without_error() {
    let tmp = TmpDir::new("staging-lookup");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir(Path::new("d"), &dir_meta()).await.unwrap();
        st.write_file_content(Path::new("f.txt"), &reg(), b"content")
            .await
            .unwrap();
        st.symlink(Path::new("link"), Path::new("f.txt"), &symlink_meta())
            .await
            .unwrap();
        st.symlink(Path::new("dird"), Path::new("d"), &symlink_meta())
            .await
            .unwrap();

        // An absent final component, and an absent path whose parent is also
        // absent: both are `Absent`, not an error.
        assert_eq!(
            st.lookup(Path::new("missing"), false).await.unwrap(),
            StagingLookup::Absent
        );
        assert_eq!(
            st.lookup(Path::new("usr/share/doc/copyright"), false)
                .await
                .unwrap(),
            StagingLookup::Absent
        );

        // A file, a directory, and a symlink with and without following.
        let file = st.lookup(Path::new("f.txt"), false).await.unwrap();
        assert!(matches!(file, StagingLookup::File { .. }));
        assert_eq!(
            st.lookup(Path::new("d"), false).await.unwrap(),
            StagingLookup::Dir
        );
        let unfollowed = st.lookup(Path::new("link"), false).await.unwrap();
        assert!(
            matches!(unfollowed, StagingLookup::File { .. }) && unfollowed != file,
            "not following yields the symlink object's own checksum"
        );
        assert_eq!(
            st.lookup(Path::new("link"), true).await.unwrap(),
            file,
            "following resolves to the target file's checksum"
        );
        assert_eq!(
            st.lookup(Path::new("dird"), true).await.unwrap(),
            StagingLookup::Dir,
            "following a symlink to a directory reports the directory"
        );

        // A non-directory intermediate component stays an error.
        match st.lookup(Path::new("f.txt/inner"), false).await {
            Err(Error::NotADirectory { path }) => assert_eq!(path, "f.txt"),
            other => panic!("expected NotADirectory, got {other:?}"),
        }

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// `symlink` and `hardlink` replace an existing file or symlink, the same rule
/// `write_file` and `write_file_content` follow.
#[test]
fn symlink_and_hardlink_replace_files_and_symlinks() {
    let tmp = TmpDir::new("staging-replace-writes");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.write_file_content(Path::new("fa"), &reg(), b"aaa")
            .await
            .unwrap();
        st.write_file_content(Path::new("f-dst1"), &reg(), b"one")
            .await
            .unwrap();
        st.write_file_content(Path::new("f-dst2"), &reg(), b"two")
            .await
            .unwrap();
        st.write_file_content(Path::new("fc"), &reg(), b"ccc")
            .await
            .unwrap();
        st.symlink(Path::new("s1"), Path::new("fa"), &symlink_meta())
            .await
            .unwrap();
        st.symlink(Path::new("s2"), Path::new("fa"), &symlink_meta())
            .await
            .unwrap();
        let fa = match st.lookup(Path::new("fa"), false).await.unwrap() {
            StagingLookup::File { checksum } => checksum,
            other => panic!("fa is not a file: {other:?}"),
        };

        // A symlink over an absent entry, over a file, and over a symlink.
        st.symlink(Path::new("s-new"), Path::new("fa"), &symlink_meta())
            .await
            .unwrap();
        assert!(
            st.read_file(Path::new("s-new"), false)
                .await
                .unwrap()
                .is_symlink()
        );
        st.symlink(Path::new("f-dst1"), Path::new("fa"), &symlink_meta())
            .await
            .unwrap();
        assert!(
            st.read_file(Path::new("f-dst1"), false)
                .await
                .unwrap()
                .is_symlink(),
            "the file was replaced by a symlink"
        );
        st.symlink(Path::new("s1"), Path::new("fc"), &symlink_meta())
            .await
            .unwrap();
        assert_eq!(
            read_all(&st.read_file(Path::new("s1"), true).await.unwrap()).await,
            b"ccc",
            "the symlink was replaced and points at the new target"
        );

        // A hardlink over an absent entry, over a file, and over a symlink.
        st.hardlink(Path::new("h-new"), Path::new("fa"))
            .await
            .unwrap();
        assert_eq!(
            st.lookup(Path::new("h-new"), false).await.unwrap(),
            StagingLookup::File { checksum: fa }
        );
        st.hardlink(Path::new("f-dst2"), Path::new("fa"))
            .await
            .unwrap();
        assert_eq!(
            st.lookup(Path::new("f-dst2"), false).await.unwrap(),
            StagingLookup::File { checksum: fa },
            "the file was replaced by the source's object"
        );
        st.hardlink(Path::new("s2"), Path::new("fa")).await.unwrap();
        assert_eq!(
            st.lookup(Path::new("s2"), false).await.unwrap(),
            StagingLookup::File { checksum: fa },
            "the symlink was replaced by the source's object"
        );

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// A `symlink` or `hardlink` whose destination holds a directory reports
/// `ReplaceDirWithFile` converting to `AlreadyExists`, the answer every write
/// over a destination directory gives. A `hardlink` whose source resolves to a
/// directory is a distinct condition and stays in `Staging`, converting to
/// `Other`.
#[test]
fn symlink_and_hardlink_over_a_directory_report_replace_dir_with_file() {
    use std::io;

    let tmp = TmpDir::new("staging-replace-dir-refusal");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir(Path::new("d"), &dir_meta()).await.unwrap();
        st.write_file_content(Path::new("fa"), &reg(), b"aaa")
            .await
            .unwrap();

        let err = st
            .symlink(Path::new("d"), Path::new("fa"), &symlink_meta())
            .await
            .unwrap_err();
        match &err {
            Error::ReplaceDirWithFile(name) => assert_eq!(name, "d"),
            other => panic!("expected ReplaceDirWithFile, got {other:?}"),
        }
        assert_eq!(io::Error::from(err).kind(), io::ErrorKind::AlreadyExists);

        let err = st
            .hardlink(Path::new("d"), Path::new("fa"))
            .await
            .unwrap_err();
        match &err {
            Error::ReplaceDirWithFile(name) => assert_eq!(name, "d"),
            other => panic!("expected ReplaceDirWithFile, got {other:?}"),
        }
        assert_eq!(io::Error::from(err).kind(), io::ErrorKind::AlreadyExists);

        let err = st
            .hardlink(Path::new("copy"), Path::new("d"))
            .await
            .unwrap_err();
        match &err {
            Error::Staging(msg) => {
                assert_eq!(msg, "cannot hardlink from d: the source is a directory");
            }
            other => panic!("expected Staging, got {other:?}"),
        }
        assert_eq!(io::Error::from(err).kind(), io::ErrorKind::Other);

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// `ensure_dir` creates an absent directory with its `meta` and restamps an
/// existing one, reaching the same dirtree bytes as `make_dir` given the same
/// input. A file at the path is the not-a-directory condition.
#[test]
fn ensure_dir_creates_and_restamps_like_make_dir() {
    use std::io;

    let tmp = TmpDir::new("staging-ensure-dir");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let meta1 = dir_meta_mode(0o040700);
        let meta2 = dir_meta_mode(0o040750);

        async fn root_checksum(
            txn: &Transaction,
            st: ostrya::StagingTree<'_>,
            root_dm: Checksum,
        ) -> Checksum {
            let mut built = st.close().unwrap();
            built.set_metadata_checksum(root_dm);
            *txn.write_mtree(&mut built)
                .await
                .unwrap()
                .dirtree_checksum()
        }

        // Created over an absent entry, then restamped with a differing meta.
        let st = txn.staging_tree(None).await.unwrap();
        st.ensure_dir(Path::new("d"), &meta1).await.unwrap();
        assert_eq!(
            st.lookup(Path::new("d"), false).await.unwrap(),
            StagingLookup::Dir
        );
        st.ensure_dir(Path::new("d"), &meta2).await.unwrap();
        let ensured = root_checksum(&txn, st, root_dm).await;

        // The oracle: the same tree built with a single make_dir.
        let st = txn.staging_tree(None).await.unwrap();
        st.make_dir(Path::new("d"), &meta2).await.unwrap();
        let made = root_checksum(&txn, st, root_dm).await;
        assert_eq!(ensured, made, "restamping reaches the make_dir tree");

        // A file or symlink at the path is an error.
        let st = txn.staging_tree(None).await.unwrap();
        st.write_file_content(Path::new("f"), &reg(), b"x")
            .await
            .unwrap();
        let err = st.ensure_dir(Path::new("f"), &meta1).await.unwrap_err();
        match &err {
            Error::NotADirectory { path } => assert_eq!(path, "f"),
            other => panic!("expected NotADirectory, got {other:?}"),
        }
        assert_eq!(io::Error::from(err).kind(), io::ErrorKind::NotADirectory);

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// An `ensure_dir` whose `meta` matches the directory's recorded dirmeta
/// offers nothing for staging. `metadata_total` counts every offer before
/// dedup, so the exact count is the assertion.
#[test]
fn unchanged_ensure_dir_stages_no_dirmeta() {
    let tmp = TmpDir::new("staging-ensure-dir-noop");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let novel = dir_meta_mode(0o040700);
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir(Path::new("a"), &novel).await.unwrap();
        st.ensure_dir(Path::new("a"), &novel).await.unwrap();

        let mut built = st.close().unwrap();
        built.set_metadata_checksum(root_dm);
        txn.write_mtree(&mut built).await.unwrap();
        let stats = txn.commit().await.unwrap();

        // The offers: the root dirmeta, make_dir's novel dirmeta, and the two
        // dirtrees write_mtree assembles. The unchanged ensure_dir adds none.
        assert_eq!(
            stats.metadata_total, 4,
            "the unchanged ensure_dir offered no dirmeta"
        );
    });
}

/// An `ensure_dir` whose `meta` matches a lazy committed directory's dirmeta
/// hydrates nothing and stages nothing. The subdirectory's dirtree object is
/// deleted first, so any hydration would fail; the unchanged root dirtree and
/// the zero offer count carry the rest.
#[test]
fn matching_ensure_dir_on_a_lazy_child_hydrates_nothing() {
    let tmp = TmpDir::new("staging-ensure-dir-lazy-match");
    let base = tmp.path();
    let repo_root = base.join("repo");

    let src = base.join("base");
    mkdir(&src, 0o755);
    mkdir(&src.join("sub"), 0o755);
    write_file(&src.join("sub/inner.txt"), b"inner", 0o644);

    block_on(async {
        let repo = Repo::create(&repo_root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        commit_dir(&repo, dfd.as_fd(), Path::new("base"), "test/base").await;
        let (sub_dirtree, _, root_dirtree) = committed_subdir(&repo, "test/base", "sub").await;
        delete_loose_object(&repo_root, &sub_dirtree, "dirtree");

        let checksum = repo.resolve_rev("test/base", false).await.unwrap().unwrap();
        let (commit, _) = repo.load_commit(&checksum).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(Some(&commit)).await.unwrap();

        st.ensure_dir(Path::new("sub"), &dir_meta()).await.unwrap();

        let mut built = st.close().unwrap();
        let rebuilt = txn.write_mtree(&mut built).await.unwrap();
        assert_eq!(
            *rebuilt.dirtree_checksum(),
            root_dirtree,
            "the matching ensure_dir left the tree byte-identical"
        );
        let stats = txn.commit().await.unwrap();
        assert_eq!(stats.metadata_total, 0, "nothing was offered for staging");
    });
}

/// An `ensure_dir` with a differing `meta` restamps a lazy committed directory
/// in place: the entry keeps its dirtree checksum and takes the new dirmeta,
/// and no dirtree is read (the object is deleted, so a read would fail).
#[test]
fn differing_ensure_dir_restamps_a_lazy_child_without_hydrating() {
    let tmp = TmpDir::new("staging-ensure-dir-lazy-differ");
    let base = tmp.path();
    let repo_root = base.join("repo");

    let src = base.join("base");
    mkdir(&src, 0o755);
    mkdir(&src.join("sub"), 0o755);
    write_file(&src.join("sub/inner.txt"), b"inner", 0o644);

    block_on(async {
        let repo = Repo::create(&repo_root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        commit_dir(&repo, dfd.as_fd(), Path::new("base"), "test/base").await;
        let (sub_dirtree, sub_dirmeta, _) = committed_subdir(&repo, "test/base", "sub").await;
        delete_loose_object(&repo_root, &sub_dirtree, "dirtree");

        let checksum = repo.resolve_rev("test/base", false).await.unwrap().unwrap();
        let (commit, _) = repo.load_commit(&checksum).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        let novel = dir_meta_mode(0o040700);
        let novel_csum = txn
            .write_metadata(
                ostrya_core::ObjectType::DirMeta,
                None,
                &novel.serialize().unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(novel_csum, sub_dirmeta, "the new dirmeta differs");
        let st = txn.staging_tree(Some(&commit)).await.unwrap();

        st.ensure_dir(Path::new("sub"), &novel).await.unwrap();

        let mut built = st.close().unwrap();
        let rebuilt = txn.write_mtree(&mut built).await.unwrap();
        let new_root_dirtree = *rebuilt.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&repo_root).await.unwrap();
        let tree = repo.load_dirtree(&new_root_dirtree).await.unwrap();
        let (_, dirtree, dirmeta) = tree.dirs.iter().find(|(n, _, _)| n == "sub").unwrap();
        assert_eq!(
            *dirtree, sub_dirtree,
            "the entry keeps its dirtree checksum"
        );
        assert_eq!(*dirmeta, novel_csum, "the entry carries the new dirmeta");
    });
}

/// `place_object` records a checksum at a path, is silent for an identical
/// placement, and answers a differing entry or a directory with
/// `MergeConflict`.
#[test]
fn place_object_records_dedups_and_conflicts() {
    use std::io;

    let tmp = TmpDir::new("staging-place-object");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir(Path::new("pool"), &dir_meta()).await.unwrap();
        st.write_file_content(Path::new("a"), &reg(), b"aaa")
            .await
            .unwrap();
        st.write_file_content(Path::new("b"), &reg(), b"bbb")
            .await
            .unwrap();
        let ca = match st.lookup(Path::new("a"), false).await.unwrap() {
            StagingLookup::File { checksum } => checksum,
            other => panic!("a is not a file: {other:?}"),
        };
        let cb = match st.lookup(Path::new("b"), false).await.unwrap() {
            StagingLookup::File { checksum } => checksum,
            other => panic!("b is not a file: {other:?}"),
        };

        st.place_object(Path::new("pool/x"), &ca).await.unwrap();
        assert_eq!(
            st.lookup(Path::new("pool/x"), false).await.unwrap(),
            StagingLookup::File { checksum: ca }
        );

        // An identical placement is silent.
        st.place_object(Path::new("pool/x"), &ca).await.unwrap();

        // A differing checksum is a conflict, and the entry is unchanged.
        let err = st.place_object(Path::new("pool/x"), &cb).await.unwrap_err();
        match &err {
            Error::MergeConflict(msg) => {
                assert_eq!(msg, "placed object differs at pool/x");
            }
            other => panic!("expected MergeConflict, got {other:?}"),
        }
        assert_eq!(io::Error::from(err).kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            st.lookup(Path::new("pool/x"), false).await.unwrap(),
            StagingLookup::File { checksum: ca }
        );

        // A directory at the path is a conflict too.
        let err = st.place_object(Path::new("pool"), &ca).await.unwrap_err();
        match &err {
            Error::MergeConflict(msg) => {
                assert_eq!(msg, "an object cannot overwrite the directory at pool");
            }
            other => panic!("expected MergeConflict, got {other:?}"),
        }

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// Concurrent `place_object` calls with two differing checksums at one path
/// resolve to one recorded winner; every call carrying the winner succeeds and
/// every other call conflicts. The rule is decided under the mutating lock
/// acquisition, so no interleaving produces a silent overwrite.
#[test]
fn concurrent_place_object_never_silently_overwrites() {
    let tmp = TmpDir::new("staging-place-concurrent");
    let root = tmp.path().join("repo");
    let repo = block_on(Repo::create(&root, CreateOptions::new(RepoMode::BareUser))).unwrap();
    let txn = block_on(repo.transaction()).unwrap();
    let st = block_on(txn.staging_tree(None)).unwrap();

    block_on(async {
        st.make_dir(Path::new("pool"), &dir_meta()).await.unwrap();
        st.write_file_content(Path::new("a"), &reg(), b"aaa")
            .await
            .unwrap();
        st.write_file_content(Path::new("b"), &reg(), b"bbb")
            .await
            .unwrap();
    });
    let ca = match block_on(st.lookup(Path::new("a"), false)).unwrap() {
        StagingLookup::File { checksum } => checksum,
        other => panic!("a is not a file: {other:?}"),
    };
    let cb = match block_on(st.lookup(Path::new("b"), false)).unwrap() {
        StagingLookup::File { checksum } => checksum,
        other => panic!("b is not a file: {other:?}"),
    };

    const N: usize = 8;
    let results = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for i in 0..N {
            let st = &st;
            let results = &results;
            let placed = if i % 2 == 0 { ca } else { cb };
            scope.spawn(move || {
                let outcome = block_on(st.place_object(Path::new("pool/x"), &placed));
                results.lock().unwrap().push((placed, outcome));
            });
        }
    });

    let winner = match block_on(st.lookup(Path::new("pool/x"), false)).unwrap() {
        StagingLookup::File { checksum } => checksum,
        other => panic!("pool/x is not a file: {other:?}"),
    };
    assert!(winner == ca || winner == cb, "the winner is one of the two");
    for (placed, outcome) in results.into_inner().unwrap() {
        if placed == winner {
            outcome.unwrap();
        } else {
            match outcome {
                Err(Error::MergeConflict(_)) => {}
                other => panic!("a losing call must conflict, got {other:?}"),
            }
        }
    }

    drop(st);
    block_on(txn.abort()).unwrap();
}

/// Concurrent `ensure_dir` calls at one absent path create one directory and
/// publish one dirmeta object for the whole set.
#[test]
fn concurrent_ensure_dir_creates_one_directory() {
    let tmp = TmpDir::new("staging-ensure-dir-concurrent");
    let root = tmp.path().join("repo");
    let repo = block_on(Repo::create(&root, CreateOptions::new(RepoMode::BareUser))).unwrap();
    let txn = block_on(repo.transaction()).unwrap();
    let root_dm = block_on(stage_dir_meta(&txn));
    let st = block_on(txn.staging_tree(None)).unwrap();
    let novel = dir_meta_mode(0o040700);

    const N: usize = 8;
    std::thread::scope(|scope| {
        for _ in 0..N {
            let st = &st;
            let novel = &novel;
            scope.spawn(move || {
                block_on(st.ensure_dir(Path::new("shared"), novel)).unwrap();
            });
        }
    });

    assert_eq!(
        block_on(st.lookup(Path::new("shared"), false)).unwrap(),
        StagingLookup::Dir
    );
    let mut built = st.close().unwrap();
    built.set_metadata_checksum(root_dm);
    block_on(txn.write_mtree(&mut built)).unwrap();
    block_on(txn.commit()).unwrap();

    // The 0755 root dirmeta and the novel one: two objects, however many
    // concurrent calls staged the same bytes.
    assert_eq!(
        count_objects_with_ext(&root, ".dirmeta"),
        2,
        "the set staged one dirmeta object"
    );
}

/// The checksum `lookup` reports for the file at `path`.
async fn staged_file(st: &ostrya::StagingTree<'_>, path: &str) -> Checksum {
    match st.lookup(Path::new(path), false).await.unwrap() {
        StagingLookup::File { checksum } => checksum,
        other => panic!("{path} is not a file: {other:?}"),
    }
}

/// The dirtree and dirmeta checksums of the subdirectory `name` recorded in
/// the dirtree object `dirtree`.
async fn dirtree_subdir(repo: &Repo, dirtree: &Checksum, name: &str) -> (Checksum, Checksum) {
    let tree = repo.load_dirtree(dirtree).await.unwrap();
    let (_, dt, dm) = tree
        .dirs
        .iter()
        .find(|(n, _, _)| n == name)
        .unwrap_or_else(|| panic!("{name} is not a subdirectory"));
    (*dt, *dm)
}

/// Ancestors created by each of the six write operations under an implied
/// dirmeta carry the policy dirmeta, and the `ensure_dir` leaf takes the meta
/// the call itself supplies.
#[test]
fn implied_ancestors_carry_the_policy_dirmeta() {
    let tmp = TmpDir::new("staging-implied-ancestors");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let policy = dir_meta_mode(0o040750);
        let policy_csum = txn
            .write_metadata(ObjectType::DirMeta, None, &policy.serialize().unwrap())
            .await
            .unwrap();
        let leaf_meta = dir_meta_mode(0o040700);
        let leaf_csum = txn
            .write_metadata(ObjectType::DirMeta, None, &leaf_meta.serialize().unwrap())
            .await
            .unwrap();
        let st = txn
            .staging_tree(None)
            .await
            .unwrap()
            .with_implied_dirmeta(policy);

        let mut writer = st.write_file(Path::new("w1/a/f"), &reg()).await.unwrap();
        writer.write_all(b"one").await.unwrap();
        writer.finish().await.unwrap();
        st.write_file_content(Path::new("w2/a/f"), &reg(), b"two")
            .await
            .unwrap();
        st.symlink(Path::new("w3/a/l"), Path::new("f"), &symlink_meta())
            .await
            .unwrap();
        st.hardlink(Path::new("w4/a/h"), Path::new("w2/a/f"))
            .await
            .unwrap();
        let placed = staged_file(&st, "w2/a/f").await;
        st.place_object(Path::new("w5/a/p"), &placed).await.unwrap();
        st.ensure_dir(Path::new("w6/a/d"), &leaf_meta)
            .await
            .unwrap();

        let mut built = st.close().unwrap();
        built.set_metadata_checksum(root_dm);
        let built_root = txn.write_mtree(&mut built).await.unwrap();
        let root_dirtree = *built_root.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&root).await.unwrap();
        for w in ["w1", "w2", "w3", "w4", "w5", "w6"] {
            let (w_dt, w_dm) = dirtree_subdir(&repo, &root_dirtree, w).await;
            assert_eq!(w_dm, policy_csum, "{w} carries the policy dirmeta");
            let (a_dt, a_dm) = dirtree_subdir(&repo, &w_dt, "a").await;
            assert_eq!(a_dm, policy_csum, "{w}/a carries the policy dirmeta");
            if w == "w6" {
                let (_, d_dm) = dirtree_subdir(&repo, &a_dt, "d").await;
                assert_eq!(d_dm, leaf_csum, "the ensure_dir leaf carries its own meta");
            }
        }
    });
}

/// A write whose parent already exists stages no policy dirmeta, and a
/// `make_dir_all` over a path whose every component exists still stages
/// nothing. `metadata_total` counts every offer before dedup, so the exact
/// count is the assertion.
#[test]
fn writes_with_an_existing_parent_stage_no_policy_dirmeta() {
    let tmp = TmpDir::new("staging-implied-existing-parent");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let novel = dir_meta_mode(0o040700);
        let st = txn
            .staging_tree(None)
            .await
            .unwrap()
            .with_implied_dirmeta(dir_meta_mode(0o040750));

        st.make_dir(Path::new("d"), &novel).await.unwrap();
        st.write_file_content(Path::new("d/f"), &reg(), b"x")
            .await
            .unwrap();
        st.symlink(Path::new("d/l"), Path::new("f"), &symlink_meta())
            .await
            .unwrap();
        st.make_dir_all(Path::new("d"), &dir_meta()).await.unwrap();

        let mut built = st.close().unwrap();
        built.set_metadata_checksum(root_dm);
        txn.write_mtree(&mut built).await.unwrap();
        let stats = txn.commit().await.unwrap();

        // The offers: the root dirmeta, make_dir's novel dirmeta, and the two
        // dirtrees write_mtree assembles. The writes into the existing parent
        // and the all-existing make_dir_all add none.
        assert_eq!(
            stats.metadata_total, 4,
            "no policy dirmeta was offered for staging"
        );
    });
}

/// With a policy set, `lookup`, the reads, `remove`, `clear_dir`, and the
/// `from` side of a `rename` resolve a path whose ancestors are absent
/// without creating a directory and without staging an object.
#[test]
fn resolution_for_a_read_creates_nothing_under_a_policy() {
    let tmp = TmpDir::new("staging-implied-reads");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let st = txn
            .staging_tree(None)
            .await
            .unwrap()
            .with_implied_dirmeta(dir_meta_mode(0o040750));

        assert_eq!(
            st.lookup(Path::new("x/y/z"), false).await.unwrap(),
            StagingLookup::Absent
        );
        let err = st.read_file(Path::new("x/y/z"), false).await.unwrap_err();
        assert!(
            matches!(err, Error::PathNotFound { .. }),
            "read_file reports the absent path: {err:?}"
        );
        let err = st.read_dir(Path::new("x/y"), false).await.unwrap_err();
        assert!(
            matches!(err, Error::PathNotFound { .. }),
            "read_dir reports the absent path: {err:?}"
        );
        st.remove(Path::new("r/s/t"), true).await.unwrap();
        st.clear_dir(Path::new("c/d"), true).await.unwrap();
        let err = st
            .rename(Path::new("m/n"), Path::new("q"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::PathNotFound { .. }),
            "the from side reports the absent ancestor: {err:?}"
        );
        for name in ["x", "r", "c", "m"] {
            assert_eq!(
                st.lookup(Path::new(name), false).await.unwrap(),
                StagingLookup::Absent,
                "resolution created no directory"
            );
        }

        let mut built = st.close().unwrap();
        built.set_metadata_checksum(root_dm);
        txn.write_mtree(&mut built).await.unwrap();
        let stats = txn.commit().await.unwrap();

        // The offers: the root dirmeta and the one dirtree of the empty root.
        assert_eq!(stats.metadata_total, 2, "resolution staged no object");
    });
}

/// A tree built entirely through implied ancestors and the same tree built
/// with explicit `make_dir` calls reach the same root dirtree checksum.
#[test]
fn implied_and_explicit_ancestors_agree_on_the_checksum() {
    let tmp = TmpDir::new("staging-implied-equivalence");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let policy = dir_meta_mode(0o040750);

        let implied = txn
            .staging_tree(None)
            .await
            .unwrap()
            .with_implied_dirmeta(policy.clone());
        implied
            .write_file_content(Path::new("usr/share/doc/copyright"), &reg(), b"text")
            .await
            .unwrap();

        let explicit = txn.staging_tree(None).await.unwrap();
        explicit.make_dir(Path::new("usr"), &policy).await.unwrap();
        explicit
            .make_dir(Path::new("usr/share"), &policy)
            .await
            .unwrap();
        explicit
            .make_dir(Path::new("usr/share/doc"), &policy)
            .await
            .unwrap();
        explicit
            .write_file_content(Path::new("usr/share/doc/copyright"), &reg(), b"text")
            .await
            .unwrap();

        let mut built_implied = implied.close().unwrap();
        built_implied.set_metadata_checksum(root_dm);
        let implied_root = txn.write_mtree(&mut built_implied).await.unwrap();
        let mut built_explicit = explicit.close().unwrap();
        built_explicit.set_metadata_checksum(root_dm);
        let explicit_root = txn.write_mtree(&mut built_explicit).await.unwrap();
        assert_eq!(
            implied_root.dirtree_checksum(),
            explicit_root.dirtree_checksum(),
            "the two builds agree on the root dirtree"
        );
        txn.abort().await.unwrap();
    });
}

/// A policy creates an absent ancestor, and does not create the target of a
/// symlink that has one, so the creating walk names the symlink with
/// `DanglingSymlink` the way the non-creating walk does. The refusal creates
/// nothing.
#[test]
fn a_dangling_symlink_ancestor_under_a_policy_is_dangling_not_absent() {
    let tmp = TmpDir::new("staging-implied-dangling");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn
            .staging_tree(None)
            .await
            .unwrap()
            .with_implied_dirmeta(dir_meta_mode(0o040750));
        st.symlink(Path::new("gone"), Path::new("nowhere"), &symlink_meta())
            .await
            .unwrap();

        match st
            .write_file_content(Path::new("gone/f"), &reg(), b"x")
            .await
        {
            Err(Error::DanglingSymlink { path, target }) => {
                assert_eq!(path, "gone");
                assert_eq!(target, "nowhere");
            }
            other => panic!("the creating walk names the symlink: {other:?}"),
        }
        assert_eq!(
            st.lookup(Path::new("nowhere"), false).await.unwrap(),
            StagingLookup::Absent,
            "the policy created no target directory"
        );

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// Without a policy, every write operation still fails on a missing parent.
#[test]
fn writes_without_a_policy_still_fail_on_a_missing_parent() {
    let tmp = TmpDir::new("staging-no-policy-missing-parent");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();
        st.write_file_content(Path::new("src"), &reg(), b"s")
            .await
            .unwrap();
        let src = staged_file(&st, "src").await;

        let assert_missing = |err: Error, op: &str| match &err {
            Error::PathNotFound { path } => assert_eq!(path, "missing", "{op}"),
            other => panic!("{op}: expected PathNotFound, got {other:?}"),
        };
        assert_missing(
            st.write_file(Path::new("missing/f"), &reg())
                .await
                .map(|_| ())
                .unwrap_err(),
            "write_file",
        );
        assert_missing(
            st.write_file_content(Path::new("missing/f"), &reg(), b"x")
                .await
                .unwrap_err(),
            "write_file_content",
        );
        assert_missing(
            st.symlink(Path::new("missing/l"), Path::new("t"), &symlink_meta())
                .await
                .unwrap_err(),
            "symlink",
        );
        assert_missing(
            st.hardlink(Path::new("missing/h"), Path::new("src"))
                .await
                .unwrap_err(),
            "hardlink",
        );
        assert_missing(
            st.place_object(Path::new("missing/p"), &src)
                .await
                .unwrap_err(),
            "place_object",
        );
        assert_missing(
            st.ensure_dir(Path::new("missing/d"), &dir_meta())
                .await
                .unwrap_err(),
            "ensure_dir",
        );

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// Concurrent writes to distinct leaves under one absent ancestor chain
/// create each ancestor once and publish one policy dirmeta object for the
/// whole set.
#[test]
fn concurrent_implied_writes_create_each_ancestor_once() {
    let tmp = TmpDir::new("staging-implied-concurrent");
    let root = tmp.path().join("repo");
    let repo = block_on(Repo::create(&root, CreateOptions::new(RepoMode::BareUser))).unwrap();
    let txn = block_on(repo.transaction()).unwrap();
    let root_dm = block_on(stage_dir_meta(&txn));
    let st = block_on(txn.staging_tree(None))
        .unwrap()
        .with_implied_dirmeta(dir_meta_mode(0o040700));

    const N: usize = 8;
    std::thread::scope(|scope| {
        for i in 0..N {
            let st = &st;
            scope.spawn(move || {
                let path = format!("shared/a/f{i}");
                let payload = format!("payload {i}").into_bytes();
                block_on(st.write_file_content(Path::new(&path), &reg(), &payload)).unwrap();
            });
        }
    });

    for i in 0..N {
        block_on(staged_file(&st, &format!("shared/a/f{i}")));
    }
    let mut built = st.close().unwrap();
    built.set_metadata_checksum(root_dm);
    block_on(txn.write_mtree(&mut built)).unwrap();
    block_on(txn.commit()).unwrap();

    // The 0755 root dirmeta and the policy one: two objects, however many
    // concurrent walks staged the same bytes.
    assert_eq!(
        count_objects_with_ext(&root, ".dirmeta"),
        2,
        "the set published one policy dirmeta object"
    );
}

/// A write racing a `write_file_content` at an ancestor's own name reaches an
/// error: exactly one call wins, and the tree holds the winner's entry rather
/// than a directory silently replacing a file or the reverse.
#[test]
fn a_write_racing_a_file_at_an_ancestor_name_errors() {
    let tmp = TmpDir::new("staging-implied-race");
    let root = tmp.path().join("repo");
    let repo = block_on(Repo::create(&root, CreateOptions::new(RepoMode::BareUser))).unwrap();
    let txn = block_on(repo.transaction()).unwrap();
    let st = block_on(txn.staging_tree(None))
        .unwrap()
        .with_implied_dirmeta(dir_meta_mode(0o040700));

    const ROUNDS: usize = 8;
    for i in 0..ROUNDS {
        let file_path = format!("x{i}");
        let leaf_path = format!("x{i}/y");
        let (file_res, leaf_res) = std::thread::scope(|scope| {
            let st = &st;
            let file = scope
                .spawn(|| block_on(st.write_file_content(Path::new(&file_path), &reg(), b"file")));
            let leaf = scope
                .spawn(|| block_on(st.write_file_content(Path::new(&leaf_path), &reg(), b"leaf")));
            (file.join().unwrap(), leaf.join().unwrap())
        });

        match (file_res, leaf_res) {
            (Ok(()), Err(_)) => {
                assert!(
                    matches!(
                        block_on(st.lookup(Path::new(&file_path), false)).unwrap(),
                        StagingLookup::File { .. }
                    ),
                    "{file_path} holds the file that won"
                );
            }
            (Err(_), Ok(())) => {
                assert_eq!(
                    block_on(st.lookup(Path::new(&file_path), false)).unwrap(),
                    StagingLookup::Dir,
                    "{file_path} holds the implied directory that won"
                );
                block_on(staged_file(&st, &leaf_path));
            }
            (Ok(()), Ok(())) => panic!("both writes succeeded at {file_path}"),
            (Err(f), Err(l)) => panic!("both writes failed at {file_path}: {f:?} / {l:?}"),
        }
    }

    drop(st);
    block_on(txn.abort()).unwrap();
}

/// A merge overwrite that would drop a directory is refused while a file
/// writer is outstanding, names the directory it refused to drop, and leaves
/// the directory and its subtree in place. Once the writer finishes, the same
/// merge succeeds.
#[test]
fn merge_overwrite_of_a_directory_is_refused_while_a_writer_is_live() {
    let tmp = TmpDir::new("staging-merge-writer-guard");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();

        let pkg_st = txn.staging_tree(None).await.unwrap();
        pkg_st
            .write_file_content(Path::new("d"), &reg(), b"a file where the dir was")
            .await
            .unwrap();
        let package = pkg_st.close().unwrap();

        let base_st = txn.staging_tree(None).await.unwrap();
        base_st.make_dir(Path::new("d"), &dir_meta()).await.unwrap();
        base_st
            .write_file_content(Path::new("d/keep.txt"), &reg(), b"keep")
            .await
            .unwrap();
        let mut writer = base_st
            .write_file(Path::new("d/pending.txt"), &reg())
            .await
            .unwrap();
        writer.write_all(b"pending").await.unwrap();

        let opts = MergeOptions {
            allow_overwrite: true,
            ..MergeOptions::default()
        };
        match base_st.merge(&package, opts).await {
            Err(Error::Staging(msg)) => assert_eq!(
                msg, "cannot drop the directory at d: 1 file writer(s) still outstanding",
                "the refusal names the directory and the count"
            ),
            other => panic!("the overwrite is refused while a writer is live: {other:?}"),
        }
        assert_eq!(
            base_st.lookup(Path::new("d"), false).await.unwrap(),
            StagingLookup::Dir,
            "the blocked overwrite leaves the directory in place"
        );
        assert!(
            matches!(
                base_st
                    .lookup(Path::new("d/keep.txt"), false)
                    .await
                    .unwrap(),
                StagingLookup::File { .. }
            ),
            "the blocked overwrite leaves the subtree in place"
        );

        writer.finish().await.unwrap();
        base_st.merge(&package, opts).await.unwrap();
        assert!(
            matches!(
                base_st.lookup(Path::new("d"), false).await.unwrap(),
                StagingLookup::File { .. }
            ),
            "once the writer finished, the overwrite replaces the directory"
        );

        drop(base_st);
        txn.abort().await.unwrap();
    });
}

/// The guard counts writers over the whole tree: a live writer in a branch
/// disjoint from the dropped directory blocks the overwrite too, and an
/// abandoned writer releases the guard.
#[test]
fn merge_overwrite_is_refused_by_a_writer_in_a_disjoint_branch() {
    let tmp = TmpDir::new("staging-merge-writer-guard-disjoint");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();

        let pkg_st = txn.staging_tree(None).await.unwrap();
        pkg_st
            .write_file_content(Path::new("d"), &reg(), b"a file where the dir was")
            .await
            .unwrap();
        let package = pkg_st.close().unwrap();

        let base_st = txn.staging_tree(None).await.unwrap();
        base_st.make_dir(Path::new("d"), &dir_meta()).await.unwrap();
        base_st
            .write_file_content(Path::new("d/keep.txt"), &reg(), b"keep")
            .await
            .unwrap();
        base_st
            .make_dir(Path::new("other"), &dir_meta())
            .await
            .unwrap();
        let writer = base_st
            .write_file(Path::new("other/w.txt"), &reg())
            .await
            .unwrap();

        let opts = MergeOptions {
            allow_overwrite: true,
            ..MergeOptions::default()
        };
        match base_st.merge(&package, opts).await {
            Err(Error::Staging(msg)) => assert_eq!(
                msg, "cannot drop the directory at d: 1 file writer(s) still outstanding",
                "a writer outside the dropped directory blocks the overwrite too"
            ),
            other => panic!("the overwrite is refused while a writer is live: {other:?}"),
        }
        assert_eq!(
            base_st.lookup(Path::new("d"), false).await.unwrap(),
            StagingLookup::Dir,
            "the blocked overwrite leaves the directory in place"
        );

        // Abandoning the writer (drop without finish) releases the guard.
        drop(writer);
        base_st.merge(&package, opts).await.unwrap();
        assert!(
            matches!(
                base_st.lookup(Path::new("d"), false).await.unwrap(),
                StagingLookup::File { .. }
            ),
            "an abandoned writer no longer blocks the overwrite"
        );
        base_st.close().unwrap();

        txn.abort().await.unwrap();
    });
}

/// `remove` takes out a file, a symlink (the symlink object, not its target),
/// and a populated directory with its subtree, under either `allow_noent`
/// value. An absent entry, an absent ancestor, and a path through a dangling
/// symlink are `Ok` with `allow_noent`; without it, the absent entry is
/// `PathNotFound` (converting to `NotFound`) and the walk conditions keep
/// their own variants.
#[test]
fn remove_covers_each_kind_and_absent_paths() {
    use std::io;

    let tmp = TmpDir::new("staging-remove");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.write_file_content(Path::new("f1"), &reg(), b"one")
            .await
            .unwrap();
        st.write_file_content(Path::new("f2"), &reg(), b"two")
            .await
            .unwrap();
        st.symlink(Path::new("s1"), Path::new("f1"), &symlink_meta())
            .await
            .unwrap();
        st.symlink(Path::new("s2"), Path::new("f1"), &symlink_meta())
            .await
            .unwrap();
        st.make_dir_all(Path::new("d1/sub"), &dir_meta())
            .await
            .unwrap();
        st.write_file_content(Path::new("d1/sub/x"), &reg(), b"x")
            .await
            .unwrap();
        st.make_dir_all(Path::new("d2/sub"), &dir_meta())
            .await
            .unwrap();
        st.symlink(Path::new("dangling"), Path::new("nowhere"), &symlink_meta())
            .await
            .unwrap();

        // A symlink: the symlink goes, its target stays.
        st.remove(Path::new("s1"), false).await.unwrap();
        assert_eq!(
            st.lookup(Path::new("s1"), false).await.unwrap(),
            StagingLookup::Absent
        );
        assert!(
            matches!(
                st.lookup(Path::new("f1"), false).await.unwrap(),
                StagingLookup::File { .. }
            ),
            "removing the symlink leaves its target in place"
        );
        st.remove(Path::new("s2"), true).await.unwrap();

        // A file.
        st.remove(Path::new("f1"), false).await.unwrap();
        st.remove(Path::new("f2"), true).await.unwrap();
        assert_eq!(
            st.lookup(Path::new("f2"), false).await.unwrap(),
            StagingLookup::Absent
        );

        // A populated directory, subtree and all.
        st.remove(Path::new("d1"), false).await.unwrap();
        assert_eq!(
            st.lookup(Path::new("d1"), false).await.unwrap(),
            StagingLookup::Absent
        );
        assert_eq!(
            st.lookup(Path::new("d1/sub/x"), false).await.unwrap(),
            StagingLookup::Absent
        );
        st.remove(Path::new("d2"), true).await.unwrap();

        // An absent entry: the variant, its conversion, and the noent form.
        let err = st.remove(Path::new("f1"), false).await.unwrap_err();
        match &err {
            Error::PathNotFound { path } => assert_eq!(path, "f1"),
            other => panic!("expected PathNotFound, got {other:?}"),
        }
        assert_eq!(io::Error::from(err).kind(), io::ErrorKind::NotFound);
        st.remove(Path::new("f1"), true).await.unwrap();

        // An absent ancestor.
        match st.remove(Path::new("missing/deeper/f"), false).await {
            Err(Error::PathNotFound { path }) => assert_eq!(path, "missing"),
            other => panic!("expected PathNotFound, got {other:?}"),
        }
        st.remove(Path::new("missing/deeper/f"), true)
            .await
            .unwrap();

        // A path through a dangling intermediate symlink.
        match st.remove(Path::new("dangling/f"), false).await {
            Err(Error::DanglingSymlink { path, target }) => {
                assert_eq!(path, "dangling");
                assert_eq!(target, "nowhere");
            }
            other => panic!("expected DanglingSymlink, got {other:?}"),
        }
        st.remove(Path::new("dangling/f"), true).await.unwrap();
        // The dangling symlink itself removes as the symlink.
        st.remove(Path::new("dangling"), false).await.unwrap();

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// `clear_dir` empties the directory and the entry keeps its dirmeta
/// checksum; a file at the path, and a symlink there even where it points at
/// a directory, are the not-a-directory condition, and an absent directory
/// follows `allow_noent`.
#[test]
fn clear_dir_empties_and_keeps_the_dirmeta() {
    use std::io;

    let tmp = TmpDir::new("staging-clear-dir");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let novel = dir_meta_mode(0o040700);
        let novel_csum = txn
            .write_metadata(ObjectType::DirMeta, None, &novel.serialize().unwrap())
            .await
            .unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir(Path::new("d"), &novel).await.unwrap();
        st.write_file_content(Path::new("d/f"), &reg(), b"f")
            .await
            .unwrap();
        st.make_dir(Path::new("d/sub"), &dir_meta()).await.unwrap();
        st.write_file_content(Path::new("d/sub/x"), &reg(), b"x")
            .await
            .unwrap();
        st.write_file_content(Path::new("plain"), &reg(), b"p")
            .await
            .unwrap();

        st.clear_dir(Path::new("d"), false).await.unwrap();
        assert_eq!(
            st.lookup(Path::new("d"), false).await.unwrap(),
            StagingLookup::Dir,
            "the directory itself stays"
        );
        assert!(
            st.read_dir(Path::new("d"), false).await.unwrap().is_empty(),
            "every entry under the directory is gone"
        );

        // A file at the path, and a symlink pointing at a directory: the
        // final component never follows, so neither is cleared.
        match st.clear_dir(Path::new("plain"), false).await {
            Err(Error::NotADirectory { path }) => assert_eq!(path, "plain"),
            other => panic!("expected NotADirectory, got {other:?}"),
        }
        st.write_file_content(Path::new("d/keep"), &reg(), b"k")
            .await
            .unwrap();
        st.symlink(Path::new("link"), Path::new("d"), &symlink_meta())
            .await
            .unwrap();
        match st.clear_dir(Path::new("link"), false).await {
            Err(Error::NotADirectory { path }) => assert_eq!(path, "link"),
            other => panic!("expected NotADirectory, got {other:?}"),
        }
        assert!(
            matches!(
                st.lookup(Path::new("d/keep"), false).await.unwrap(),
                StagingLookup::File { .. }
            ),
            "the symlink's target directory keeps its entries"
        );
        st.remove(Path::new("d/keep"), false).await.unwrap();
        st.remove(Path::new("link"), false).await.unwrap();

        // An absent directory, with and without `allow_noent`.
        let err = st.clear_dir(Path::new("absent"), false).await.unwrap_err();
        match &err {
            Error::PathNotFound { path } => assert_eq!(path, "absent"),
            other => panic!("expected PathNotFound, got {other:?}"),
        }
        assert_eq!(io::Error::from(err).kind(), io::ErrorKind::NotFound);
        st.clear_dir(Path::new("absent"), true).await.unwrap();
        st.clear_dir(Path::new("no/ancestor"), true).await.unwrap();

        let mut built = st.close().unwrap();
        built.set_metadata_checksum(root_dm);
        let built_root = txn.write_mtree(&mut built).await.unwrap();
        let root_dirtree = *built_root.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&root).await.unwrap();
        let (_, d_dm) = dirtree_subdir(&repo, &root_dirtree, "d").await;
        assert_eq!(d_dm, novel_csum, "the emptied directory keeps its dirmeta");
    });
}

/// `clear_dir` over a lazily-loaded committed directory hydrates nothing: the
/// subdirectory's dirtree object is deleted first, so any read would fail,
/// and the emptied directory keeps the lazy child's dirmeta checksum.
#[test]
fn clear_dir_on_a_lazy_child_hydrates_nothing() {
    let tmp = TmpDir::new("staging-clear-dir-lazy");
    let base = tmp.path();
    let repo_root = base.join("repo");

    let src = base.join("base");
    mkdir(&src, 0o755);
    mkdir(&src.join("sub"), 0o755);
    write_file(&src.join("sub/inner.txt"), b"inner", 0o644);

    block_on(async {
        let repo = Repo::create(&repo_root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        commit_dir(&repo, dfd.as_fd(), Path::new("base"), "test/base").await;
        let (sub_dirtree, sub_dirmeta, _) = committed_subdir(&repo, "test/base", "sub").await;
        delete_loose_object(&repo_root, &sub_dirtree, "dirtree");

        let checksum = repo.resolve_rev("test/base", false).await.unwrap().unwrap();
        let (commit, _) = repo.load_commit(&checksum).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(Some(&commit)).await.unwrap();

        st.clear_dir(Path::new("sub"), false).await.unwrap();
        assert!(
            st.read_dir(Path::new("sub"), false)
                .await
                .unwrap()
                .is_empty(),
            "the lazy child was emptied without a read"
        );

        let mut built = st.close().unwrap();
        let rebuilt = txn.write_mtree(&mut built).await.unwrap();
        let new_root_dirtree = *rebuilt.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&repo_root).await.unwrap();
        let (sub_dt, sub_dm) = dirtree_subdir(&repo, &new_root_dirtree, "sub").await;
        assert_eq!(
            sub_dm, sub_dirmeta,
            "the emptied directory keeps the lazy child's dirmeta"
        );
        let emptied = repo.load_dirtree(&sub_dt).await.unwrap();
        assert!(
            emptied.files.is_empty() && emptied.dirs.is_empty(),
            "the rewritten subdirectory is empty"
        );
    });
}

/// `remove` and `clear_dir` are refused while any file writer is live -- a
/// writer in a branch disjoint from the affected path included -- leave the
/// tree in place, and succeed once every writer has finished or been dropped.
#[test]
fn remove_and_clear_dir_are_refused_while_a_writer_is_live() {
    let tmp = TmpDir::new("staging-remove-writer-guard");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir(Path::new("d"), &dir_meta()).await.unwrap();
        st.write_file_content(Path::new("d/keep.txt"), &reg(), b"keep")
            .await
            .unwrap();
        st.make_dir(Path::new("other"), &dir_meta()).await.unwrap();
        let mut writer = st
            .write_file(Path::new("other/w.txt"), &reg())
            .await
            .unwrap();
        writer.write_all(b"w").await.unwrap();

        match st.remove(Path::new("d"), false).await {
            Err(Error::Staging(msg)) => assert_eq!(
                msg, "cannot remove d: 1 file writer(s) still outstanding",
                "the refusal names the removed path and the count"
            ),
            other => panic!("remove is refused while a writer is live: {other:?}"),
        }
        match st.clear_dir(Path::new("d"), false).await {
            Err(Error::Staging(msg)) => assert_eq!(
                msg, "cannot clear the directory at d: 1 file writer(s) still outstanding",
                "the refusal names the cleared directory and the count"
            ),
            other => panic!("clear_dir is refused while a writer is live: {other:?}"),
        }
        assert!(
            matches!(
                st.lookup(Path::new("d/keep.txt"), false).await.unwrap(),
                StagingLookup::File { .. }
            ),
            "the blocked calls leave the subtree in place"
        );

        writer.finish().await.unwrap();
        st.clear_dir(Path::new("d"), false).await.unwrap();
        assert!(
            st.read_dir(Path::new("d"), false).await.unwrap().is_empty(),
            "once the writer finished, clear_dir empties the directory"
        );

        // An abandoned writer releases the guard too.
        let writer = st
            .write_file(Path::new("other/w2.txt"), &reg())
            .await
            .unwrap();
        match st.remove(Path::new("d"), false).await {
            Err(Error::Staging(_)) => {}
            other => panic!("remove is refused while a writer is live: {other:?}"),
        }
        drop(writer);
        st.remove(Path::new("d"), false).await.unwrap();
        assert_eq!(
            st.lookup(Path::new("d"), false).await.unwrap(),
            StagingLookup::Absent,
            "once the writer was dropped, remove takes the directory out"
        );

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// `rename` moves a file, a symlink (the symlink object, not its target),
/// and a populated directory with its subtree and dirmeta, and the renamed
/// tree reaches the same root dirtree checksum as the same tree assembled by
/// explicit writes at the final locations.
#[test]
fn rename_moves_each_kind_and_matches_explicit_writes() {
    let tmp = TmpDir::new("staging-rename");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let novel = dir_meta_mode(0o040700);

        let renamed = txn.staging_tree(None).await.unwrap();
        renamed
            .write_file_content(Path::new("f"), &reg(), b"f")
            .await
            .unwrap();
        renamed
            .symlink(Path::new("l"), Path::new("f2"), &symlink_meta())
            .await
            .unwrap();
        renamed.make_dir(Path::new("d"), &novel).await.unwrap();
        renamed
            .write_file_content(Path::new("d/inner"), &reg(), b"inner")
            .await
            .unwrap();
        renamed
            .make_dir(Path::new("dest"), &dir_meta())
            .await
            .unwrap();

        let link_csum = staged_file(&renamed, "l").await;
        renamed
            .rename(Path::new("f"), Path::new("f2"))
            .await
            .unwrap();
        renamed
            .rename(Path::new("l"), Path::new("dest/l"))
            .await
            .unwrap();
        renamed
            .rename(Path::new("d"), Path::new("dest/d"))
            .await
            .unwrap();

        for gone in ["f", "l", "d"] {
            assert_eq!(
                renamed.lookup(Path::new(gone), false).await.unwrap(),
                StagingLookup::Absent,
                "{gone} left its old path"
            );
        }
        assert_eq!(
            staged_file(&renamed, "dest/l").await,
            link_csum,
            "the symlink moved as the symlink object"
        );
        let inner = renamed
            .read_file(Path::new("dest/d/inner"), false)
            .await
            .unwrap();
        assert_eq!(read_all(&inner).await, b"inner", "the subtree moved along");

        let explicit = txn.staging_tree(None).await.unwrap();
        explicit
            .write_file_content(Path::new("f2"), &reg(), b"f")
            .await
            .unwrap();
        explicit
            .make_dir(Path::new("dest"), &dir_meta())
            .await
            .unwrap();
        explicit
            .symlink(Path::new("dest/l"), Path::new("f2"), &symlink_meta())
            .await
            .unwrap();
        explicit
            .make_dir(Path::new("dest/d"), &novel)
            .await
            .unwrap();
        explicit
            .write_file_content(Path::new("dest/d/inner"), &reg(), b"inner")
            .await
            .unwrap();

        let mut built_renamed = renamed.close().unwrap();
        built_renamed.set_metadata_checksum(root_dm);
        let renamed_root = txn.write_mtree(&mut built_renamed).await.unwrap();
        let mut built_explicit = explicit.close().unwrap();
        built_explicit.set_metadata_checksum(root_dm);
        let explicit_root = txn.write_mtree(&mut built_explicit).await.unwrap();
        assert_eq!(
            renamed_root.dirtree_checksum(),
            explicit_root.dirtree_checksum(),
            "the two builds agree on the root dirtree"
        );
        txn.abort().await.unwrap();
    });
}

/// `rename` of a lazily-loaded committed subtree hydrates nothing: the
/// subdirectory's dirtree object is deleted first, so any read would fail,
/// and the moved entry keeps the child's dirtree and dirmeta checksums, which
/// tells a moved lazy child from a rebuilt one -- a rebuild would have had to
/// read the deleted dirtree. The one metadata offer is the new root dirtree.
#[test]
fn rename_of_a_lazy_subtree_hydrates_nothing() {
    let tmp = TmpDir::new("staging-rename-lazy");
    let base = tmp.path();
    let repo_root = base.join("repo");

    let src = base.join("base");
    mkdir(&src, 0o755);
    mkdir(&src.join("sub"), 0o755);
    write_file(&src.join("sub/inner.txt"), b"inner", 0o644);

    block_on(async {
        let repo = Repo::create(&repo_root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        commit_dir(&repo, dfd.as_fd(), Path::new("base"), "test/base").await;
        let (sub_dirtree, sub_dirmeta, _) = committed_subdir(&repo, "test/base", "sub").await;
        delete_loose_object(&repo_root, &sub_dirtree, "dirtree");

        let checksum = repo.resolve_rev("test/base", false).await.unwrap().unwrap();
        let (commit, _) = repo.load_commit(&checksum).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(Some(&commit)).await.unwrap();

        st.rename(Path::new("sub"), Path::new("moved"))
            .await
            .unwrap();

        let mut built = st.close().unwrap();
        let rebuilt = txn.write_mtree(&mut built).await.unwrap();
        let new_root_dirtree = *rebuilt.dirtree_checksum();
        let stats = txn.commit().await.unwrap();
        assert_eq!(
            stats.metadata_total, 1,
            "only the new root dirtree was offered for staging"
        );

        let repo = Repo::open(&repo_root).await.unwrap();
        let (moved_dt, moved_dm) = dirtree_subdir(&repo, &new_root_dirtree, "moved").await;
        assert_eq!(
            moved_dt, sub_dirtree,
            "the moved entry keeps its dirtree checksum"
        );
        assert_eq!(
            moved_dm, sub_dirmeta,
            "the moved entry keeps its dirmeta checksum"
        );
    });
}

/// `rename` onto an existing entry -- the source's own path included -- is
/// `EntryExists`, converting to `AlreadyExists`; an absent source is
/// `PathNotFound`; a destination under the moved entry is refused; and a
/// missing destination parent follows the implied-dirmeta policy: an error
/// without one, created under it.
#[test]
fn rename_refusals_and_destination_parents() {
    use std::io;

    let tmp = TmpDir::new("staging-rename-refusals");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.write_file_content(Path::new("a"), &reg(), b"a")
            .await
            .unwrap();
        st.write_file_content(Path::new("b"), &reg(), b"b")
            .await
            .unwrap();
        st.make_dir(Path::new("d"), &dir_meta()).await.unwrap();

        let err = st.rename(Path::new("a"), Path::new("b")).await.unwrap_err();
        match &err {
            Error::EntryExists { path } => assert_eq!(path, "b"),
            other => panic!("expected EntryExists, got {other:?}"),
        }
        assert_eq!(io::Error::from(err).kind(), io::ErrorKind::AlreadyExists);
        match st.rename(Path::new("a"), Path::new("a")).await {
            Err(Error::EntryExists { path }) => assert_eq!(path, "a"),
            other => panic!("a rename onto its own path is EntryExists: {other:?}"),
        }

        let err = st
            .rename(Path::new("ghost"), Path::new("g2"))
            .await
            .unwrap_err();
        match &err {
            Error::PathNotFound { path } => assert_eq!(path, "ghost"),
            other => panic!("expected PathNotFound, got {other:?}"),
        }

        match st.rename(Path::new("d"), Path::new("d/x")).await {
            Err(Error::Staging(msg)) => assert_eq!(
                msg, "cannot rename d to d/x: the destination is under the moved entry",
                "the refusal names both resolved paths"
            ),
            other => panic!("a destination under the moved entry is refused: {other:?}"),
        }
        assert_eq!(
            st.lookup(Path::new("d"), false).await.unwrap(),
            StagingLookup::Dir,
            "the refused rename leaves the directory in place"
        );

        // A missing destination parent without a policy is the walk's error,
        // and the source stays where it was.
        let err = st
            .rename(Path::new("a"), Path::new("no/where"))
            .await
            .unwrap_err();
        match &err {
            Error::PathNotFound { path } => assert_eq!(path, "no"),
            other => panic!("expected PathNotFound, got {other:?}"),
        }
        staged_file(&st, "a").await;

        // Under a policy the destination parent chain is created.
        let stp = txn
            .staging_tree(None)
            .await
            .unwrap()
            .with_implied_dirmeta(dir_meta_mode(0o040750));
        stp.write_file_content(Path::new("src"), &reg(), b"s")
            .await
            .unwrap();
        stp.rename(Path::new("src"), Path::new("n/e/w"))
            .await
            .unwrap();
        staged_file(&stp, "n/e/w").await;
        assert_eq!(
            stp.lookup(Path::new("src"), false).await.unwrap(),
            StagingLookup::Absent,
            "the source left its old path"
        );

        drop(st);
        drop(stp);
        txn.abort().await.unwrap();
    });
}

/// `rename` is refused while any file writer is live -- a writer in a branch
/// disjoint from both paths included -- leaves both sides as they were, and
/// succeeds once the writer has finished or been dropped.
#[test]
fn rename_is_refused_while_a_writer_is_live() {
    let tmp = TmpDir::new("staging-rename-writer-guard");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let st = txn.staging_tree(None).await.unwrap();

        st.make_dir(Path::new("d"), &dir_meta()).await.unwrap();
        st.write_file_content(Path::new("d/keep.txt"), &reg(), b"keep")
            .await
            .unwrap();
        st.make_dir(Path::new("other"), &dir_meta()).await.unwrap();
        let mut writer = st
            .write_file(Path::new("other/w.txt"), &reg())
            .await
            .unwrap();
        writer.write_all(b"w").await.unwrap();

        match st.rename(Path::new("d"), Path::new("moved")).await {
            Err(Error::Staging(msg)) => assert_eq!(
                msg, "cannot rename d to moved: 1 file writer(s) still outstanding",
                "the refusal names both paths and the count"
            ),
            other => panic!("rename is refused while a writer is live: {other:?}"),
        }
        staged_file(&st, "d/keep.txt").await;
        assert_eq!(
            st.lookup(Path::new("moved"), false).await.unwrap(),
            StagingLookup::Absent,
            "the blocked rename recorded nothing at the destination"
        );

        writer.finish().await.unwrap();
        st.rename(Path::new("d"), Path::new("moved")).await.unwrap();
        staged_file(&st, "moved/keep.txt").await;
        assert_eq!(
            st.lookup(Path::new("d"), false).await.unwrap(),
            StagingLookup::Absent,
            "once the writer finished, the rename moved the directory"
        );

        // An abandoned writer releases the guard too.
        let writer = st
            .write_file(Path::new("other/w2.txt"), &reg())
            .await
            .unwrap();
        match st.rename(Path::new("moved"), Path::new("again")).await {
            Err(Error::Staging(_)) => {}
            other => panic!("rename is refused while a writer is live: {other:?}"),
        }
        drop(writer);
        st.rename(Path::new("moved"), Path::new("again"))
            .await
            .unwrap();
        staged_file(&st, "again/keep.txt").await;
        assert_eq!(
            st.lookup(Path::new("moved"), false).await.unwrap(),
            StagingLookup::Absent,
            "once the writer was dropped, the rename moved the directory"
        );

        drop(st);
        txn.abort().await.unwrap();
    });
}

/// `merge_at` lands the right side under an existing base, and the tree it
/// produces reaches the same root dirtree checksum as the same union assembled
/// by explicit writes.
#[test]
fn merge_at_matches_explicit_writes() {
    let tmp = TmpDir::new("staging-merge-at");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let novel = dir_meta_mode(0o040700);
        let novel_csum = txn
            .write_metadata(ObjectType::DirMeta, None, &novel.serialize().unwrap())
            .await
            .unwrap();

        let pkg_st = txn.staging_tree(None).await.unwrap();
        pkg_st
            .write_file_content(Path::new("f"), &reg(), b"pkg")
            .await
            .unwrap();
        pkg_st
            .make_dir(Path::new("sub"), &dir_meta())
            .await
            .unwrap();
        pkg_st
            .write_file_content(Path::new("sub/g"), &reg(), b"deep")
            .await
            .unwrap();
        let mut package = pkg_st.close().unwrap();
        package.set_metadata_checksum(novel_csum);

        let merged_st = txn.staging_tree(None).await.unwrap();
        merged_st.make_dir(Path::new("dest"), &novel).await.unwrap();
        merged_st
            .write_file_content(Path::new("dest/own"), &reg(), b"own")
            .await
            .unwrap();
        merged_st
            .merge_at(Path::new("dest"), &package, MergeOptions::default())
            .await
            .unwrap();
        assert_eq!(
            read_all(
                &merged_st
                    .read_file(Path::new("dest/f"), false)
                    .await
                    .unwrap()
            )
            .await,
            b"pkg",
            "the right side landed under the base"
        );
        assert_eq!(
            merged_st.lookup(Path::new("f"), false).await.unwrap(),
            StagingLookup::Absent,
            "nothing landed at the tree root"
        );

        // `/` and the empty path name the tree root, like `.`. Each takes a
        // fresh tree, since a base that reached nothing would pass on a tree
        // the merge already filled.
        for spelling in ["/", ""] {
            let at_root = txn.staging_tree(None).await.unwrap();
            at_root
                .merge_at(Path::new(spelling), &package, MergeOptions::default())
                .await
                .unwrap();
            assert!(
                matches!(
                    at_root.lookup(Path::new("f"), false).await.unwrap(),
                    StagingLookup::File { .. }
                ),
                "`{spelling}` merged at the tree root"
            );
            at_root.close().unwrap();
        }

        let explicit = txn.staging_tree(None).await.unwrap();
        explicit.make_dir(Path::new("dest"), &novel).await.unwrap();
        explicit
            .write_file_content(Path::new("dest/own"), &reg(), b"own")
            .await
            .unwrap();
        explicit
            .write_file_content(Path::new("dest/f"), &reg(), b"pkg")
            .await
            .unwrap();
        explicit
            .make_dir(Path::new("dest/sub"), &dir_meta())
            .await
            .unwrap();
        explicit
            .write_file_content(Path::new("dest/sub/g"), &reg(), b"deep")
            .await
            .unwrap();

        let mut built_merged = merged_st.close().unwrap();
        built_merged.set_metadata_checksum(root_dm);
        let merged_root = txn.write_mtree(&mut built_merged).await.unwrap();
        let mut built_explicit = explicit.close().unwrap();
        built_explicit.set_metadata_checksum(root_dm);
        let explicit_root = txn.write_mtree(&mut built_explicit).await.unwrap();
        assert_eq!(
            merged_root.dirtree_checksum(),
            explicit_root.dirtree_checksum(),
            "the two builds agree on the root dirtree"
        );
        txn.abort().await.unwrap();
    });
}

/// `root_dirmeta` governs the merge root alone. A base whose dirmeta equals the
/// right root's is silent under either value; a differing one is a conflict
/// under `Reconcile` and is taken with `allow_overwrite`; `KeepLeft` keeps the
/// base's own dirmeta and merges the entries all the same. A directory below
/// the root reconciles whatever the value is.
#[test]
fn merge_at_root_dirmeta_governs_the_base_alone() {
    let tmp = TmpDir::new("staging-merge-at-root-dirmeta");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        // `dir_meta()` is the 0755 meta the bases below take, so they carry
        // the same checksum the tree root does.
        let base_dm = root_dm;
        let novel = dir_meta_mode(0o040700);
        let novel_csum = txn
            .write_metadata(ObjectType::DirMeta, None, &novel.serialize().unwrap())
            .await
            .unwrap();

        // The right side: a 0700 root holding a file and a 0700 subdirectory.
        let pkg_st = txn.staging_tree(None).await.unwrap();
        pkg_st
            .write_file_content(Path::new("f"), &reg(), b"pkg")
            .await
            .unwrap();
        pkg_st.make_dir(Path::new("sub"), &novel).await.unwrap();
        let mut package = pkg_st.close().unwrap();
        package.set_metadata_checksum(novel_csum);

        let st = txn.staging_tree(None).await.unwrap();
        let keep_left = MergeOptions {
            root_dirmeta: RootDirmeta::KeepLeft,
            ..MergeOptions::default()
        };
        // A base whose dirmeta equals the right root's: silent either way.
        st.make_dir(Path::new("equal"), &novel).await.unwrap();
        st.merge_at(Path::new("equal"), &package, MergeOptions::default())
            .await
            .unwrap();
        st.make_dir(Path::new("equal_kept"), &novel).await.unwrap();
        st.merge_at(Path::new("equal_kept"), &package, keep_left)
            .await
            .unwrap();

        // A differing base under `Reconcile`: a conflict naming the base, and
        // the right dirmeta with `allow_overwrite`.
        st.make_dir(Path::new("differ"), &dir_meta()).await.unwrap();
        match st
            .merge_at(Path::new("differ"), &package, MergeOptions::default())
            .await
        {
            Err(Error::MergeConflict(msg)) => assert_eq!(
                msg, "directory metadata differs at differ",
                "the conflict names the base"
            ),
            other => panic!("a differing base dirmeta conflicts: {other:?}"),
        }
        assert_eq!(
            st.lookup(Path::new("differ/f"), false).await.unwrap(),
            StagingLookup::Absent,
            "the conflict was raised before the entries were applied"
        );
        st.merge_at(
            Path::new("differ"),
            &package,
            MergeOptions {
                allow_overwrite: true,
                ..MergeOptions::default()
            },
        )
        .await
        .unwrap();

        // The same differing base under `KeepLeft`: no conflict, and the base
        // keeps its own dirmeta.
        st.make_dir(Path::new("keep"), &dir_meta()).await.unwrap();
        st.merge_at(Path::new("keep"), &package, keep_left)
            .await
            .unwrap();

        let mut built = st.close().unwrap();
        built.set_metadata_checksum(root_dm);
        let built_root = txn.write_mtree(&mut built).await.unwrap();
        let root_dirtree = *built_root.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&root).await.unwrap();
        for base in ["equal", "equal_kept", "differ"] {
            let (dt, dm) = dirtree_subdir(&repo, &root_dirtree, base).await;
            assert_eq!(dm, novel_csum, "{base} carries the right root's dirmeta");
            let (_, sub_dm) = dirtree_subdir(&repo, &dt, "sub").await;
            assert_eq!(sub_dm, novel_csum, "{base}/sub reconciled its own dirmeta");
        }
        let (keep_dt, keep_dm) = dirtree_subdir(&repo, &root_dirtree, "keep").await;
        assert_eq!(keep_dm, base_dm, "KeepLeft kept the base's own dirmeta");
        let (_, keep_sub_dm) = dirtree_subdir(&repo, &keep_dt, "sub").await;
        assert_eq!(
            keep_sub_dm, novel_csum,
            "a directory below the root reconciles under KeepLeft too"
        );
    });
}

/// A missing `merge_at` base is created under the implied dirmeta and stays in
/// the tree when the merge then conflicts on it. `KeepLeft` keeps the policy
/// dirmeta and lands the right side under it. Without a policy, an absent base
/// is `PathNotFound`, a file at the base and a symlink to one are
/// `NotADirectory`, and a symlink to a directory is a valid base.
#[test]
fn merge_at_creates_its_base_under_the_implied_policy() {
    let tmp = TmpDir::new("staging-merge-at-implied-base");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_dm = stage_dir_meta(&txn).await;
        let policy = dir_meta_mode(0o040750);
        let policy_csum = txn
            .write_metadata(ObjectType::DirMeta, None, &policy.serialize().unwrap())
            .await
            .unwrap();
        let novel = dir_meta_mode(0o040700);
        let novel_csum = txn
            .write_metadata(ObjectType::DirMeta, None, &novel.serialize().unwrap())
            .await
            .unwrap();

        let pkg_st = txn.staging_tree(None).await.unwrap();
        pkg_st
            .write_file_content(Path::new("f"), &reg(), b"pkg")
            .await
            .unwrap();
        let mut package = pkg_st.close().unwrap();
        package.set_metadata_checksum(novel_csum);

        let st = txn
            .staging_tree(None)
            .await
            .unwrap()
            .with_implied_dirmeta(policy);

        // The base's every component is created under the policy, its own
        // final component included. The right root's dirmeta is not the policy
        // dirmeta, so `Reconcile` conflicts on it.
        match st
            .merge_at(Path::new("pool/x"), &package, MergeOptions::default())
            .await
        {
            Err(Error::MergeConflict(msg)) => assert_eq!(
                msg, "directory metadata differs at pool/x",
                "the conflict names the created base"
            ),
            other => panic!("the policy dirmeta conflicts with the right root: {other:?}"),
        }
        assert_eq!(
            st.lookup(Path::new("pool/x"), false).await.unwrap(),
            StagingLookup::Dir,
            "the refused merge keeps the base the policy created"
        );

        // `KeepLeft` is the case that needs the policy dirmeta kept.
        st.merge_at(
            Path::new("pool/y"),
            &package,
            MergeOptions {
                root_dirmeta: RootDirmeta::KeepLeft,
                ..MergeOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            read_all(&st.read_file(Path::new("pool/y/f"), false).await.unwrap()).await,
            b"pkg",
            "the right side landed under the created base"
        );

        // Without a policy, the base must exist and must be a directory.
        let plain = txn.staging_tree(None).await.unwrap();
        plain
            .write_file_content(Path::new("file"), &reg(), b"x")
            .await
            .unwrap();
        match plain
            .merge_at(Path::new("absent/base"), &package, MergeOptions::default())
            .await
        {
            Err(Error::PathNotFound { path }) => assert_eq!(path, "absent"),
            other => panic!("an absent base without a policy is PathNotFound: {other:?}"),
        }
        match plain
            .merge_at(Path::new("file"), &package, MergeOptions::default())
            .await
        {
            Err(Error::NotADirectory { path }) => assert_eq!(path, "file"),
            other => panic!("a file at the base is NotADirectory: {other:?}"),
        }
        plain
            .symlink(Path::new("to_file"), Path::new("file"), &symlink_meta())
            .await
            .unwrap();
        match plain
            .merge_at(Path::new("to_file"), &package, MergeOptions::default())
            .await
        {
            Err(Error::NotADirectory { path }) => assert_eq!(path, "file"),
            other => panic!("a symlink to a file is NotADirectory: {other:?}"),
        }

        // A base that is a dangling symlink names the symlink either way: the
        // creating walk and the plain walk agree on the variant, so a policy
        // does not change the condition a caller branches on.
        for (tree, label) in [(&plain, "without a policy"), (&st, "under a policy")] {
            tree.symlink(Path::new("gone"), Path::new("nowhere"), &symlink_meta())
                .await
                .unwrap();
            match tree
                .merge_at(Path::new("gone"), &package, MergeOptions::default())
                .await
            {
                Err(Error::DanglingSymlink { path, target }) => {
                    assert_eq!(path, "gone");
                    assert_eq!(target, "nowhere");
                }
                other => panic!("a dangling base {label} is DanglingSymlink: {other:?}"),
            }
        }

        // A symlink to a directory is a valid base, and the base's final
        // component follows without `follow_symlinks`. The right root's
        // dirmeta is the one `real` carries, so the base reconciles silently.
        plain.make_dir(Path::new("real"), &novel).await.unwrap();
        plain
            .symlink(Path::new("to_dir"), Path::new("real"), &symlink_meta())
            .await
            .unwrap();
        plain
            .merge_at(Path::new("to_dir"), &package, MergeOptions::default())
            .await
            .unwrap();
        assert_eq!(
            read_all(&plain.read_file(Path::new("real/f"), false).await.unwrap()).await,
            b"pkg",
            "the right side landed in the symlink's target directory"
        );
        assert!(
            matches!(
                plain.lookup(Path::new("to_dir"), false).await.unwrap(),
                StagingLookup::File { .. }
            ),
            "the base symlink is still a symlink"
        );
        plain.close().unwrap();

        let mut built = st.close().unwrap();
        built.set_metadata_checksum(root_dm);
        let built_root = txn.write_mtree(&mut built).await.unwrap();
        let root_dirtree = *built_root.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&root).await.unwrap();
        let (pool_dt, pool_dm) = dirtree_subdir(&repo, &root_dirtree, "pool").await;
        assert_eq!(
            pool_dm, policy_csum,
            "the base's ancestor carries the policy"
        );
        let (_, x_dm) = dirtree_subdir(&repo, &pool_dt, "x").await;
        assert_eq!(
            x_dm, policy_csum,
            "the refused merge left the base's dirmeta as the policy set it"
        );
        let (_, y_dm) = dirtree_subdir(&repo, &pool_dt, "y").await;
        assert_eq!(y_dm, policy_csum, "KeepLeft kept the policy dirmeta");
    });
}

/// The writer guard covers the merge arms that drop a directory and no others.
/// A right-side directory arriving over an absent name or over a file drops no
/// directory, so both land with a writer live; a right-side file over a
/// directory is refused. The branch where the name holds a directory the merge
/// did not read has no cell: one task reaches the re-read with no await between
/// it and the read, so only another task can put a directory there.
#[test]
fn merge_at_guards_only_the_arms_that_drop_a_directory() {
    let tmp = TmpDir::new("staging-merge-at-guard-scope");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();

        // One right side holds directories at `f` and `e`, the other a file at
        // `d`. They merge separately, since the merge applies a directory's
        // file entries before it descends into its subdirectories.
        let dirs_st = txn.staging_tree(None).await.unwrap();
        dirs_st.make_dir(Path::new("f"), &dir_meta()).await.unwrap();
        dirs_st
            .write_file_content(Path::new("f/x"), &reg(), b"x")
            .await
            .unwrap();
        dirs_st.make_dir(Path::new("e"), &dir_meta()).await.unwrap();
        dirs_st
            .write_file_content(Path::new("e/y"), &reg(), b"y")
            .await
            .unwrap();
        let dirs_pkg = dirs_st.close().unwrap();

        let file_st = txn.staging_tree(None).await.unwrap();
        file_st
            .write_file_content(Path::new("d"), &reg(), b"a file where the dir was")
            .await
            .unwrap();
        let file_pkg = file_st.close().unwrap();

        // The left side: a file at `f`, nothing at `e`, a directory at `d`.
        let st = txn.staging_tree(None).await.unwrap();
        st.write_file_content(Path::new("f"), &reg(), b"left")
            .await
            .unwrap();
        st.make_dir(Path::new("d"), &dir_meta()).await.unwrap();
        st.write_file_content(Path::new("d/keep.txt"), &reg(), b"keep")
            .await
            .unwrap();
        st.make_dir(Path::new("w"), &dir_meta()).await.unwrap();
        let mut writer = st.write_file(Path::new("w/pending"), &reg()).await.unwrap();
        writer.write_all(b"pending").await.unwrap();

        let opts = MergeOptions {
            allow_overwrite: true,
            ..MergeOptions::default()
        };
        // A directory over a file and a directory over an absent entry drop no
        // directory, so the live writer blocks neither.
        st.merge_at(Path::new("."), &dirs_pkg, opts).await.unwrap();
        assert_eq!(
            read_all(&st.read_file(Path::new("f/x"), false).await.unwrap()).await,
            b"x",
            "a directory replaced the file with the writer live"
        );
        assert_eq!(
            read_all(&st.read_file(Path::new("e/y"), false).await.unwrap()).await,
            b"y",
            "a directory landed at an absent name with the writer live"
        );

        // A file over a directory drops one, so the same writer blocks it.
        match st.merge_at(Path::new("."), &file_pkg, opts).await {
            Err(Error::Staging(msg)) => assert_eq!(
                msg, "cannot drop the directory at d: 1 file writer(s) still outstanding",
                "the refusal names the directory and the count"
            ),
            other => panic!("the file over the directory is refused: {other:?}"),
        }
        staged_file(&st, "d/keep.txt").await;

        writer.finish().await.unwrap();
        st.merge_at(Path::new("."), &file_pkg, opts).await.unwrap();
        assert!(
            matches!(
                st.lookup(Path::new("d"), false).await.unwrap(),
                StagingLookup::File { .. }
            ),
            "once the writer finished, the file replaces the directory"
        );
        st.close().unwrap();
        txn.abort().await.unwrap();
    });
}
