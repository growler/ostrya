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
    FileMeta, FileObject, MergeOptions, MutableTree, Repo, RepoMode, StagingEntry, Transaction,
    TreeEntry,
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
            matches!(err, Error::Staging(_)),
            "a loop is an error: {err:?}"
        );

        // A dangling target fails.
        st.symlink(Path::new("dangling"), Path::new("nowhere"), &symlink_meta())
            .await
            .unwrap();
        let err = st.read_file(Path::new("dangling"), true).await.unwrap_err();
        assert!(
            matches!(err, Error::Staging(_)),
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
                assert!(msg.contains("a.txt"), "the conflict names the path: {msg}");
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
        assert!(
            matches!(st.close(), Err(Error::Staging(_))),
            "close is refused while a writer is outstanding"
        );
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

/// The new value types are `Send + Sync` (the lifetime-bearing types are pinned
/// by compile-time assertions inside the crate).
#[test]
fn value_types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MergeOptions>();
    assert_send_sync::<StagingEntry>();
}
