//! Commit-assembly, refs, and detached-metadata integration tests (Phase 7d).
//!
//! These replay the fixture source tree through the 7a-7d write path and check
//! the commit object byte-for-byte against the tool's fixtures: the sizes-free
//! commit across archive, bare-user, and bare-user-shared (the commit object is
//! mode-independent), the archive `--generate-sizes` commit, the ref files the
//! tool resolves, detached-metadata round-trips, immediate ref writes,
//! concurrent commits, and tool acceptance of a port-built repository.

mod common;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{
    COMMIT, CONTENT, ROOT_DIRMETA, ROOT_DIRTREE, SIZES_COMMIT, TmpDir, fixture_repo,
    ostree_available,
};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DirMeta, FileMeta,
    MutableTree, ObjectType, Repo, RepoMode, RepoTree, Transaction, TreeEntry, Type, Value,
};
use ostrya_core::{Xattrs, loose_path};
use ostrya_rt::block_on;
use std::os::fd::AsFd;

const SUBJECT: &str = "fixture commit";

fn csum(hex: &str) -> Checksum {
    Checksum::from_hex(hex).unwrap()
}

/// The `ostree.ref-binding` metadata dict the tool writes for a branch commit:
/// a single `as` entry naming the branch. Reproducing the fixture commit
/// byte-for-byte requires supplying it in the tool's key order.
fn ref_binding(refs: &[&str]) -> Value {
    let names = refs.iter().map(|r| Value::Str((*r).to_owned())).collect();
    Value::Array(vec![Value::Tuple(vec![
        Value::Str("ostree.ref-binding".to_owned()),
        Value::variant(Type::parse("as").unwrap(), Value::Array(names)),
    ])])
}

/// The commit options that reproduce the fixture commit: the branch binding,
/// the fixture subject, and the fixed timestamp.
fn fixture_commit_options() -> CommitOptions {
    CommitOptions {
        subject: Some(SUBJECT.to_owned()),
        timestamp: Some(1_700_000_000),
        metadata: Some(ref_binding(&["test/main"])),
        ..CommitOptions::default()
    }
}

/// Build the fixture source tree (hello/empty/nested/link) under `base/src`.
fn build_fixture_source(base: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let set_mode = |p: &Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    };
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
}

/// Ingest `base/src` into a fresh root tree, forcing owner 0:0 with canonical
/// permissions so it matches the tool's owner-0:0 fixture. Returns the staged
/// root. Adds `GENERATE_SIZES` when requested.
async fn ingest_fixture(txn: &Transaction, base: &Path, generate_sizes: bool) -> ostrya::RepoTree {
    let mut flags = CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS;
    if generate_sizes {
        flags |= CommitModifierFlags::GENERATE_SIZES;
    }
    let mut modifier = CommitModifier::new(flags);
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
    txn.write_mtree(&mut mtree).await.unwrap()
}

/// The on-disk bytes of a loose object in a repository rooted at `root`.
fn object_bytes(root: &Path, hex: &str, ty: ObjectType, mode: RepoMode) -> Vec<u8> {
    std::fs::read(root.join("objects").join(loose_path(&csum(hex), ty, mode))).unwrap()
}

#[test]
fn commit_object_is_byte_identical_across_modes() {
    // The commit object is mode-independent, so replaying the fixture input
    // through 7a-7d in each mode reproduces the archive fixture's commit bytes,
    // its checksum, and a ref the port resolves.
    let fixture_commit = object_bytes(
        &fixture_repo("archive"),
        COMMIT,
        ObjectType::Commit,
        RepoMode::Archive,
    );

    for mode in [
        RepoMode::Archive,
        RepoMode::BareUser,
        RepoMode::BareUserShared,
    ] {
        let tmp = TmpDir::new("commit-bytes");
        let base = tmp.path();
        build_fixture_source(base);
        let root_dir = base.join("repo");
        block_on(async {
            let repo = Repo::create(&root_dir, CreateOptions::new(mode))
                .await
                .unwrap();
            let txn = repo.transaction().await.unwrap();
            let root = ingest_fixture(&txn, base, false).await;
            assert_eq!(
                root.dirtree_checksum(),
                &csum(ROOT_DIRTREE),
                "{mode:?} root dirtree"
            );
            assert_eq!(
                root.dirmeta_checksum(),
                &csum(ROOT_DIRMETA),
                "{mode:?} root dirmeta"
            );

            let commit = txn
                .write_commit(fixture_commit_options(), &root)
                .await
                .unwrap();
            assert_eq!(
                commit,
                csum(COMMIT),
                "{mode:?} commit checksum matches the tool"
            );
            txn.set_ref("test/main", Some(&commit));
            txn.commit().await.unwrap();

            assert_eq!(
                object_bytes(&root_dir, COMMIT, ObjectType::Commit, mode),
                fixture_commit,
                "{mode:?} commit object is byte-identical to the fixture"
            );

            // The ref file resolves, in this handle and a freshly opened one.
            assert_eq!(
                repo.resolve_rev("test/main", false).await.unwrap(),
                Some(csum(COMMIT)),
                "{mode:?} ref resolves"
            );
            let reopened = Repo::open(&root_dir).await.unwrap();
            assert_eq!(
                reopened.resolve_rev("test/main", false).await.unwrap(),
                Some(csum(COMMIT))
            );
        });
    }
}

#[test]
fn generate_sizes_commit_matches_the_fixture() {
    // An archive commit with GENERATE_SIZES reproduces the sizes fixture's
    // commit bytes and checksum: ostree.sizes covers every object (content and
    // metadata) and is appended after the caller's ref-binding.
    let fixture_commit = object_bytes(
        &fixture_repo("sizes"),
        SIZES_COMMIT,
        ObjectType::Commit,
        RepoMode::Archive,
    );

    let tmp = TmpDir::new("commit-sizes");
    let base = tmp.path();
    build_fixture_source(base);
    let root_dir = base.join("repo");
    block_on(async {
        let repo = Repo::create(&root_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root = ingest_fixture(&txn, base, true).await;
        let commit = txn
            .write_commit(fixture_commit_options(), &root)
            .await
            .unwrap();
        assert_eq!(commit, csum(SIZES_COMMIT), "generate-sizes commit checksum");
        txn.set_ref("test/main", Some(&commit));
        txn.commit().await.unwrap();

        assert_eq!(
            object_bytes(
                &root_dir,
                SIZES_COMMIT,
                ObjectType::Commit,
                RepoMode::Archive
            ),
            fixture_commit,
            "the ostree.sizes commit is byte-identical to the fixture"
        );
    });
}

#[test]
fn generate_sizes_is_a_noop_outside_archive() {
    // In bare-user the size-generation request never marks the transaction, so
    // the commit is byte-identical with and without it.
    let commit_with = |generate_sizes: bool| {
        let tmp = TmpDir::new("commit-sizes-bare");
        let base = tmp.path();
        build_fixture_source(base);
        let root_dir = base.join("repo");
        block_on(async {
            let repo = Repo::create(&root_dir, CreateOptions::new(RepoMode::BareUser))
                .await
                .unwrap();
            let txn = repo.transaction().await.unwrap();
            let root = ingest_fixture(&txn, base, generate_sizes).await;
            let commit = txn
                .write_commit(fixture_commit_options(), &root)
                .await
                .unwrap();
            txn.abort().await.unwrap();
            commit
        })
    };
    assert_eq!(
        commit_with(true),
        commit_with(false),
        "GENERATE_SIZES is a no-op in bare-user, so the commit is unchanged"
    );
    // And it equals the mode-independent fixture commit (no sizes key).
    assert_eq!(commit_with(true), csum(COMMIT));
}

#[test]
fn detached_metadata_round_trips() {
    // Writing an a{sv} and reading it back yields the same value; writing None
    // yields the zero-length "no metadata" file, read back as None.
    let tmp = TmpDir::new("commit-detached");
    let root_dir = tmp.path().join("repo");
    let commit = csum(COMMIT);
    let meta = Value::Array(vec![Value::Tuple(vec![
        Value::Str("ostree.sign.dummy".to_owned()),
        Value::variant(
            Type::parse("aay").unwrap(),
            Value::Array(vec![Value::Bytes(b"a-signature-blob".to_vec())]),
        ),
    ])]);

    block_on(async {
        let repo = Repo::create(&root_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();

        assert_eq!(
            repo.read_commit_detached_metadata(&commit).await.unwrap(),
            None,
            "absent detached metadata reads as None"
        );

        repo.write_commit_detached_metadata(&commit, Some(&meta))
            .await
            .unwrap();
        assert_eq!(
            repo.read_commit_detached_metadata(&commit).await.unwrap(),
            Some(meta.clone()),
            "detached metadata round-trips"
        );

        // A None write is the documented zero-length file, read back as None.
        repo.write_commit_detached_metadata(&commit, None)
            .await
            .unwrap();
        let path = root_dir.join("objects").join(loose_path(
            &commit,
            ObjectType::CommitMeta,
            RepoMode::Archive,
        ));
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            0,
            "None writes a zero-length file, not a deletion"
        );
        assert_eq!(
            repo.read_commit_detached_metadata(&commit).await.unwrap(),
            None,
            "a zero-length file reads as None, not an empty dict"
        );
    });
}

#[test]
fn set_ref_immediate_writes_and_removes() {
    let tmp = TmpDir::new("commit-immediate");
    let root_dir = tmp.path().join("repo");
    let commit = csum(COMMIT);
    block_on(async {
        let repo = Repo::create(&root_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        repo.set_ref_immediate("branch/one", Some(&commit))
            .await
            .unwrap();
        assert_eq!(
            repo.resolve_rev("branch/one", false).await.unwrap(),
            Some(commit)
        );
        // The ref file is the 65-byte hex-plus-newline form.
        let ref_path = root_dir.join("refs/heads/branch/one");
        assert_eq!(std::fs::metadata(&ref_path).unwrap().len(), 65);

        repo.set_ref_immediate("branch/one", None).await.unwrap();
        assert!(!ref_path.exists(), "a None checksum removes the ref");
        assert_eq!(repo.resolve_rev("branch/one", true).await.unwrap(), None);
    });
}

#[test]
fn set_ref_over_alias_replaces_symlink() {
    // Observed with the tool (2026.1): writing a ref whose file is a relative
    // symlink alias replaces the symlink with a regular ref file and leaves the
    // alias target unchanged, both when committing onto the alias and via
    // `ostree refs --create --force`. See docs/format-reference.md. The port's
    // rename-over-target write reproduces this; this test pins the behavior.
    let tmp = TmpDir::new("commit-alias");
    let root_dir = tmp.path().join("repo");
    let a = csum(COMMIT);
    let b = csum(CONTENT);
    block_on(async {
        let repo = Repo::create(&root_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        // A concrete ref test/bar -> A, then an alias test/foo -> bar, mirroring
        // the tool's relative-symlink alias.
        repo.set_ref_immediate("test/bar", Some(&a)).await.unwrap();
        let heads = root_dir.join("refs/heads/test");
        std::os::unix::fs::symlink("bar", heads.join("foo")).unwrap();
        // The read path follows the alias to A.
        assert_eq!(repo.resolve_rev("test/foo", false).await.unwrap(), Some(a));

        // Writing B onto the alias replaces the symlink with a regular file.
        repo.set_ref_immediate("test/foo", Some(&b)).await.unwrap();
        let foo_meta = std::fs::symlink_metadata(heads.join("foo")).unwrap();
        assert!(
            foo_meta.file_type().is_file(),
            "the alias symlink is replaced by a regular ref file"
        );
        assert_eq!(repo.resolve_rev("test/foo", false).await.unwrap(), Some(b));

        // The alias target is untouched: test/bar still points at A.
        let bar_meta = std::fs::symlink_metadata(heads.join("bar")).unwrap();
        assert!(bar_meta.file_type().is_file());
        assert_eq!(repo.resolve_rev("test/bar", false).await.unwrap(), Some(a));
    });
}

#[test]
fn two_transactions_commit_concurrently() {
    // The Phase 6 concurrency promise completes: two transactions in one
    // process publish their objects and refs independently, both intact.
    let tmp = TmpDir::new("commit-concurrent");
    let root_dir = tmp.path().join("repo");
    let repo = block_on(Repo::create(
        &root_dir,
        CreateOptions::new(RepoMode::BareUser),
    ))
    .unwrap();

    let commit_one = |branch: &'static str, payload: &'static [u8]| {
        let repo = repo.clone();
        move || {
            block_on(async {
                let txn = repo.transaction().await.unwrap();
                let content = txn
                    .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o644), payload)
                    .await
                    .unwrap();
                let dirmeta_bytes = DirMeta {
                    uid: 0,
                    gid: 0,
                    mode: 0o040755,
                    xattrs: Xattrs::empty(),
                }
                .serialize()
                .unwrap();
                let dirmeta = txn
                    .write_metadata(ObjectType::DirMeta, None, &dirmeta_bytes)
                    .await
                    .unwrap();
                let mut mtree = MutableTree::new();
                mtree.set_metadata_checksum(dirmeta);
                mtree.replace_file("file.txt", content).unwrap();
                let root = txn.write_mtree(&mut mtree).await.unwrap();
                let commit = txn
                    .write_commit(
                        CommitOptions {
                            subject: Some("concurrent".to_owned()),
                            timestamp: Some(1_700_000_000),
                            ..CommitOptions::default()
                        },
                        &root,
                    )
                    .await
                    .unwrap();
                txn.set_ref(branch, Some(&commit));
                txn.commit().await.unwrap();
                commit
            })
        }
    };

    let (a, b) = std::thread::scope(|scope| {
        let ha = scope.spawn(commit_one("branch/a", b"payload a\n"));
        let hb = scope.spawn(commit_one("branch/b", b"payload b\n"));
        (ha.join().unwrap(), hb.join().unwrap())
    });
    assert_ne!(a, b, "distinct trees yield distinct commits");

    block_on(async {
        let repo = Repo::open(&root_dir).await.unwrap();
        assert_eq!(repo.resolve_rev("branch/a", false).await.unwrap(), Some(a));
        assert_eq!(repo.resolve_rev("branch/b", false).await.unwrap(), Some(b));
        // Both commit objects are present and load.
        repo.load_commit(&a).await.unwrap();
        repo.load_commit(&b).await.unwrap();
    });
}

#[test]
fn tool_accepts_a_port_created_commit() {
    if !ostree_available() {
        eprintln!("skipping tool_accepts_a_port_created_commit: the ostree tool is unavailable");
        return;
    }
    let tmp = TmpDir::new("commit-tool");
    let base = tmp.path();
    build_fixture_source(base);
    let root_dir = base.join("repo");
    block_on(async {
        let repo = Repo::create(&root_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root = ingest_fixture(&txn, base, false).await;
        let commit = txn
            .write_commit(fixture_commit_options(), &root)
            .await
            .unwrap();
        txn.set_ref("test/main", Some(&commit));
        txn.commit().await.unwrap();
    });

    let repo_arg = format!("--repo={}", root_dir.display());
    // fsck, show, and a recursive listing all accept the port's repository.
    run_ostree(&[&repo_arg, "fsck"]);
    run_ostree(&[&repo_arg, "show", "test/main"]);
    run_ostree(&[&repo_arg, "ls", "-R", "test/main"]);

    // A checkout reproduces the committed tree. `-U` (user mode) skips the
    // ownership restore, which would need root for the objects' 0:0 owner.
    let out = base.join("checkout");
    run_ostree(&[
        &repo_arg,
        "checkout",
        "-U",
        "test/main",
        out.to_str().unwrap(),
    ]);
    assert_eq!(
        std::fs::read(out.join("hello.txt")).unwrap(),
        b"hello ostree\n"
    );
    assert_eq!(
        std::fs::read(out.join("subdir/nested.txt")).unwrap(),
        b"nested\n"
    );
    assert_eq!(
        std::fs::read_link(out.join("link")).unwrap(),
        PathBuf::from("hello.txt")
    );
}

#[test]
fn multi_commit_sizes_are_scoped_to_each_root() {
    // Two distinct trees committed in one transaction with GENERATE_SIZES. Each
    // commit's ostree.sizes must list exactly the objects reachable from its own
    // root, not the union of everything the transaction staged. Under the old
    // whole-transaction scope the second commit's key would also carry the first
    // commit's objects.
    let tmp = TmpDir::new("commit-multi-sizes");
    let base = tmp.path();
    build_flat_source(&base.join("srcA"), "a.txt", b"alpha payload\n");
    build_flat_source(&base.join("srcB"), "b.txt", b"bravo payload\n");
    let root_dir = base.join("repo");

    block_on(async {
        let repo = Repo::create(&root_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_a = ingest_flat(&txn, base, "srcA").await;
        let root_b = ingest_flat(&txn, base, "srcB").await;
        assert_ne!(
            root_a.dirtree_checksum(),
            root_b.dirtree_checksum(),
            "the two source trees are distinct"
        );

        let commit_a = txn
            .write_commit(multi_commit_options(), &root_a)
            .await
            .unwrap();
        let commit_b = txn
            .write_commit(multi_commit_options(), &root_b)
            .await
            .unwrap();
        assert_ne!(commit_a, commit_b);
        txn.set_ref("multi/a", Some(&commit_a));
        txn.set_ref("multi/b", Some(&commit_b));
        txn.commit().await.unwrap();

        let sizes_a = decode_sizes_checksums(&repo, &commit_a).await;
        let sizes_b = decode_sizes_checksums(&repo, &commit_b).await;
        let reachable_a = walk_reachable(&repo, "multi/a").await;
        let reachable_b = walk_reachable(&repo, "multi/b").await;

        assert_eq!(
            sizes_a, reachable_a,
            "commit A's ostree.sizes covers exactly A's reachable objects"
        );
        assert_eq!(
            sizes_b, reachable_b,
            "commit B's ostree.sizes covers exactly B's reachable objects"
        );

        // The keys do not leak across commits: objects unique to one tree never
        // appear in the other's sizes.
        let a_only: HashSet<Checksum> = reachable_a.difference(&reachable_b).copied().collect();
        let b_only: HashSet<Checksum> = reachable_b.difference(&reachable_a).copied().collect();
        assert!(
            !a_only.is_empty() && !b_only.is_empty(),
            "the trees have objects unique to each"
        );
        assert!(
            sizes_b.is_disjoint(&a_only),
            "B's sizes must exclude objects unique to A"
        );
        assert!(
            sizes_a.is_disjoint(&b_only),
            "A's sizes must exclude objects unique to B"
        );
    });
}

#[test]
fn multi_commit_sizes_match_separate_tool_commits() {
    // The reachable scope is cross-checked against the tool: committing each tree
    // alone into its own repository yields the same set of sized-object checksums
    // the port's multi-commit transaction records for that tree. Object
    // checksums are content-addressed and compression-independent, so the sets
    // compare directly.
    if !ostree_available() {
        eprintln!("skipping multi_commit_sizes_match_separate_tool_commits: no ostree tool");
        return;
    }
    let tmp = TmpDir::new("commit-multi-sizes-tool");
    let base = tmp.path();
    build_flat_source(&base.join("srcA"), "a.txt", b"alpha payload\n");
    build_flat_source(&base.join("srcB"), "b.txt", b"bravo payload\n");
    let root_dir = base.join("repo");

    let (port_a, port_b) = block_on(async {
        let repo = Repo::create(&root_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_a = ingest_flat(&txn, base, "srcA").await;
        let root_b = ingest_flat(&txn, base, "srcB").await;
        let commit_a = txn
            .write_commit(multi_commit_options(), &root_a)
            .await
            .unwrap();
        let commit_b = txn
            .write_commit(multi_commit_options(), &root_b)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        (
            decode_sizes_checksums(&repo, &commit_a).await,
            decode_sizes_checksums(&repo, &commit_b).await,
        )
    });

    let tool_a = tool_commit_sizes(&base.join("toolA"), &base.join("srcA"), "a");
    let tool_b = tool_commit_sizes(&base.join("toolB"), &base.join("srcB"), "b");
    assert_eq!(
        port_a, tool_a,
        "A's sized objects match a standalone tool commit of A"
    );
    assert_eq!(
        port_b, tool_b,
        "B's sized objects match a standalone tool commit of B"
    );
}

#[test]
fn incremental_commit_sizes_cover_deduplicated_objects() {
    // An incremental commit into an existing archive repository. v2 shares
    // hello.txt (an unchanged leaf) and the whole keep/ subtree (an unchanged,
    // deduplicated dirtree) with v1, and changes change/x.txt. Every object
    // reachable from v2 -- including the objects that deduplicated against
    // objects/ -- must appear in v2's ostree.sizes, not only the objects v2
    // freshly staged.
    let tmp = TmpDir::new("commit-incremental-sizes");
    let base = tmp.path();
    build_incremental_source(&base.join("v1"), b"first revision\n");
    build_incremental_source(&base.join("v2"), b"second revision\n");
    let root_dir = base.join("repo");

    block_on(async {
        let repo = Repo::create(&root_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();

        // v1 in its own transaction, published to objects/.
        let txn = repo.transaction().await.unwrap();
        let root_v1 = ingest_flat(&txn, base, "v1").await;
        let commit_v1 = txn
            .write_commit(multi_commit_options(), &root_v1)
            .await
            .unwrap();
        txn.set_ref("inc/main", Some(&commit_v1));
        txn.commit().await.unwrap();

        // v2 in a fresh transaction: the shared objects now deduplicate against
        // objects/ instead of being freshly staged.
        let txn = repo.transaction().await.unwrap();
        let root_v2 = ingest_flat(&txn, base, "v2").await;
        let commit_v2 = txn
            .write_commit(
                CommitOptions {
                    parent: Some(commit_v1),
                    ..multi_commit_options()
                },
                &root_v2,
            )
            .await
            .unwrap();
        txn.set_ref("inc/main", Some(&commit_v2));
        txn.commit().await.unwrap();
        assert_ne!(commit_v1, commit_v2, "v2 is a distinct revision");

        let sizes_v2 = decode_sizes_checksums(&repo, &commit_v2).await;
        let reachable_v2 = walk_reachable(&repo, "inc/main").await;
        assert_eq!(
            sizes_v2, reachable_v2,
            "v2 ostree.sizes must cover every object reachable from v2, \
             including the shared objects that deduplicated against objects/"
        );
    });
}

#[test]
fn incremental_commit_sizes_match_a_tool_incremental_commit() {
    // Cross-check the incremental scope against the tool: the port and the tool
    // each commit v1 then v2 into their own archive repository, and the port's
    // decoded v2 ostree.sizes entries equal the tool's -- same objects, and the
    // same recovered compressed and unpacked sizes and object types. Object
    // checksums are content-addressed and the port's compression matches the
    // tool's, so the loose objects and their entries compare directly.
    if !ostree_available() {
        eprintln!(
            "skipping incremental_commit_sizes_match_a_tool_incremental_commit: no ostree tool"
        );
        return;
    }
    let tmp = TmpDir::new("commit-incremental-sizes-tool");
    let base = tmp.path();
    build_incremental_source(&base.join("v1"), b"first revision\n");
    build_incremental_source(&base.join("v2"), b"second revision\n");
    let root_dir = base.join("repo");

    let port_v2 = block_on(async {
        let repo = Repo::create(&root_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root_v1 = ingest_flat(&txn, base, "v1").await;
        let commit_v1 = txn
            .write_commit(multi_commit_options(), &root_v1)
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let txn = repo.transaction().await.unwrap();
        let root_v2 = ingest_flat(&txn, base, "v2").await;
        let commit_v2 = txn
            .write_commit(
                CommitOptions {
                    parent: Some(commit_v1),
                    ..multi_commit_options()
                },
                &root_v2,
            )
            .await
            .unwrap();
        txn.commit().await.unwrap();
        decode_sizes_entries(&repo, &commit_v2).await
    });

    let tool_v2 = tool_incremental_v2_sizes(&base.join("tool"), &base.join("v1"), &base.join("v2"));
    assert_eq!(
        port_v2, tool_v2,
        "the port's incremental v2 ostree.sizes entries match the tool's"
    );
}

/// A three-entry source tree used by the incremental tests: a shared top-level
/// file `hello.txt`, an unchanged subtree `keep/`, and a `change/x.txt` whose
/// content is `x`. Permissions are already canonical (file `0o644`, directory
/// `0o755`).
fn build_incremental_source(dir: &Path, x: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    let set_mode = |p: &Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    };
    std::fs::create_dir_all(dir.join("keep")).unwrap();
    std::fs::create_dir_all(dir.join("change")).unwrap();
    std::fs::write(dir.join("hello.txt"), b"hello ostree\n").unwrap();
    std::fs::write(dir.join("keep/stable.txt"), b"stable payload\n").unwrap();
    std::fs::write(dir.join("change/x.txt"), x).unwrap();
    for p in [
        dir.join("hello.txt"),
        dir.join("keep/stable.txt"),
        dir.join("change/x.txt"),
    ] {
        set_mode(&p, 0o644);
    }
    for p in [dir.to_path_buf(), dir.join("keep"), dir.join("change")] {
        set_mode(&p, 0o755);
    }
}

/// Commit `v1` then `v2` into one fresh archive repository with the tool under
/// `--generate-sizes`, then decode the second commit's `ostree.sizes` entries.
fn tool_incremental_v2_sizes(
    repo_dir: &Path,
    v1: &Path,
    v2: &Path,
) -> HashMap<Checksum, ostrya_core::sizes::SizeEntry> {
    let repo_arg = format!("--repo={}", repo_dir.display());
    run_ostree(&[&repo_arg, "init", "--mode=archive-z2"]);
    let commit = |src: &Path| {
        run_ostree(&[
            &repo_arg,
            "commit",
            "-b",
            "inc",
            "-s",
            "tool",
            "--owner-uid=0",
            "--owner-gid=0",
            "--no-xattrs",
            "--generate-sizes",
            src.to_str().unwrap(),
        ]);
    };
    commit(v1);
    commit(v2);
    block_on(async {
        let repo = Repo::open(repo_dir).await.unwrap();
        let commit = repo.resolve_rev("inc", false).await.unwrap().unwrap();
        decode_sizes_entries(&repo, &commit).await
    })
}

/// Commit options for the multi-commit test: `ostree.sizes` is the sole
/// metadata entry, over a fixed timestamp.
fn multi_commit_options() -> CommitOptions {
    CommitOptions {
        subject: Some("multi".to_owned()),
        timestamp: Some(1_700_000_000),
        ..CommitOptions::default()
    }
}

/// A single-file source directory with already-canonical permissions (file
/// `0o644`, directory `0o755`), so the port's `CANONICAL_PERMISSIONS` ingest and
/// an owner-0:0 tool commit produce identical objects.
fn build_flat_source(dir: &Path, name: &str, content: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).unwrap();
    let file = dir.join(name);
    std::fs::write(&file, content).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Ingest `base/sub` into a fresh root under `GENERATE_SIZES`, forcing owner
/// 0:0 with canonical permissions. Returns the staged root.
async fn ingest_flat(txn: &Transaction, base: &Path, sub: &str) -> RepoTree {
    let flags = CommitModifierFlags::CANONICAL_PERMISSIONS
        | CommitModifierFlags::SKIP_XATTRS
        | CommitModifierFlags::GENERATE_SIZES;
    let mut modifier = CommitModifier::new(flags);
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new(sub), &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    txn.write_mtree(&mut mtree).await.unwrap()
}

/// The decoded `ostree.sizes` entries of a commit, keyed by object checksum.
/// Carries the full record (compressed size, unpacked size, object type), so a
/// comparison against the tool checks the recovered sizes, not only which
/// objects are listed.
async fn decode_sizes_entries(
    repo: &Repo,
    commit: &Checksum,
) -> HashMap<Checksum, ostrya_core::sizes::SizeEntry> {
    let value = repo.load_variant(ObjectType::Commit, commit).await.unwrap();
    let Value::Tuple(fields) = value else {
        panic!("a commit object is a tuple");
    };
    let Value::Array(entries) = &fields[0] else {
        panic!("commit metadata is an a{{sv}} array");
    };
    for entry in entries {
        let Value::Tuple(kv) = entry else { continue };
        let Value::Str(key) = &kv[0] else { continue };
        if key != "ostree.sizes" {
            continue;
        }
        let Value::Variant(boxed) = &kv[1] else {
            panic!("ostree.sizes is a variant");
        };
        let Value::Array(elements) = &boxed.1 else {
            panic!("ostree.sizes wraps an aay array");
        };
        return elements
            .iter()
            .map(|element| {
                let Value::Bytes(bytes) = element else {
                    panic!("each ostree.sizes element is an ay buffer");
                };
                let entry = ostrya_core::sizes::unpack_entry(bytes).unwrap();
                (entry.checksum, entry)
            })
            .collect();
    }
    panic!("commit {} has no ostree.sizes key", commit.to_hex());
}

/// The set of object checksums listed in a commit's `ostree.sizes` key.
async fn decode_sizes_checksums(repo: &Repo, commit: &Checksum) -> HashSet<Checksum> {
    decode_sizes_entries(repo, commit)
        .await
        .into_keys()
        .collect()
}

/// The set of object checksums reachable from a commit's root, walked through
/// the public read API: each directory's dirmeta and dirtree, and every file
/// entry.
async fn walk_reachable(repo: &Repo, rev: &str) -> HashSet<Checksum> {
    let (root, _) = repo.read_commit(rev).await.unwrap();
    let mut set = HashSet::new();
    let mut stack = vec![root];
    while let Some(tree) = stack.pop() {
        set.insert(*tree.dirmeta_checksum());
        set.insert(*tree.dirtree_checksum());
        for entry in tree.read_dir().await.unwrap() {
            match entry {
                TreeEntry::File { checksum, .. } => {
                    set.insert(checksum);
                }
                TreeEntry::Dir { tree, .. } => stack.push(tree),
            }
        }
    }
    set
}

/// Commit `src` alone into a fresh archive repository with the tool under
/// `--generate-sizes`, then decode the sized-object checksum set from the
/// resulting commit.
fn tool_commit_sizes(repo_dir: &Path, src: &Path, branch: &str) -> HashSet<Checksum> {
    let repo_arg = format!("--repo={}", repo_dir.display());
    run_ostree(&[&repo_arg, "init", "--mode=archive-z2"]);
    run_ostree(&[
        &repo_arg,
        "commit",
        "-b",
        branch,
        "-s",
        "tool",
        "--owner-uid=0",
        "--owner-gid=0",
        "--no-xattrs",
        "--generate-sizes",
        src.to_str().unwrap(),
    ]);
    block_on(async {
        let repo = Repo::open(repo_dir).await.unwrap();
        let commit = repo.resolve_rev(branch, false).await.unwrap().unwrap();
        decode_sizes_checksums(&repo, &commit).await
    })
}

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
