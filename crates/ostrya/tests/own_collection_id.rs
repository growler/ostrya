//! Tests of the `[core] collection-id` of a repository as its local
//! namespace. Each writer of a collection ref of that id writes
//! `refs/heads/NAME` and no file under `refs/mirrors/ID/`. The readers ignore
//! `refs/mirrors/ID/` of that id, and the fsck lists each ref there as a
//! note.

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use common::modes::object_path;
use common::{TmpDir, file_inventory};
use ostrya::{
    Checksum, CollectionRefEntry, CommitModifier, CommitModifierFlags, CommitOptions,
    CreateOptions, DictBuilder, FsckBindingErrorKind, FsckFailure, FsckOptions, MutableTree,
    ObjectType, Ref, Repo, RepoMode,
};
use ostrya_rt::block_on;

/// The `[core] collection-id` of the repositories of the tests.
const OWN: &str = "org.example.Own";

/// A collection id that is not the id of the repository.
const OTHER: &str = "org.example.Other";

/// A fixed timestamp, so the commits are reproducible.
const FIXED_TS: u64 = 1_700_000_000;

/// Creates an archive repository at `<tmp>/repo` with the collection id
/// [`OWN`], and returns its path and its handle.
async fn create(tmp: &TmpDir) -> (PathBuf, Repo) {
    let path = tmp.path().join("repo");
    let repo = Repo::create(
        &path,
        CreateOptions::new(RepoMode::Archive).collection_id(OWN),
    )
    .await
    .unwrap();
    (path, repo)
}

fn checksum(byte: u8) -> Checksum {
    Checksum::from_bytes([byte; 32])
}

/// Writes `checksum` to `refs/mirrors/OWN/name` of the repository at `path`
/// by hand, as a source outside the port does.
fn put_own_mirror(path: &Path, name: &str, checksum: &Checksum) {
    let file = path.join("refs/mirrors").join(OWN).join(name);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, format!("{}\n", checksum.to_hex())).unwrap();
}

/// Returns the ref files under `refs/heads` of the repository at `path`, by
/// their paths, each with its commit.
fn heads(path: &Path) -> Vec<(String, String)> {
    file_inventory(path, "refs/heads")
        .into_iter()
        .map(|(name, bytes)| (name, String::from_utf8(bytes).unwrap()))
        .collect()
}

/// Asserts that the repository at `path` holds the one local ref `name` at
/// `commit`, and no file under `refs/mirrors`.
fn assert_local_alone(path: &Path, name: &str, commit: &Checksum, case: &str) {
    assert_eq!(
        heads(path),
        [(
            format!("refs/heads/{name}"),
            format!("{}\n", commit.to_hex())
        )],
        "{case}"
    );
    assert!(file_inventory(path, "refs/mirrors").is_empty(), "{case}");
}

/// Commits a tree of one file with the content `content` into `repo`, with
/// the collection binding `bound` and the ref bindings `refs`, and writes no
/// ref.
async fn commit(
    repo: &Repo,
    base: &Path,
    content: &str,
    bound: Option<&str>,
    refs: &[&str],
) -> Checksum {
    let sub = format!("tree-{content}");
    std::fs::create_dir_all(base.join(&sub)).unwrap();
    std::fs::write(base.join(&sub).join("file"), content).unwrap();
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new(&sub),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let metadata = (bound.is_some() || !refs.is_empty()).then(|| {
        let mut dict = DictBuilder::new();
        if let Some(id) = bound {
            dict.insert_str("ostree.collection-binding", id);
        }
        if !refs.is_empty() {
            let names: Vec<String> = refs.iter().map(|name| (*name).to_owned()).collect();
            dict.insert_strv("ostree.ref-binding", &names);
        }
        dict.build()
    });
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some(content.to_owned()),
                timestamp: Some(FIXED_TS),
                metadata,
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.commit().await.unwrap();
    commit
}

/// Each writer of a collection ref of the own collection id writes
/// `refs/heads/NAME`, and no file under `refs/mirrors`. A removal through
/// each writer removes `refs/heads/NAME`.
#[test]
fn each_writer_of_the_own_collection_id_writes_the_local_ref() {
    let tmp = TmpDir::new("own-id-writers");
    block_on(async {
        let (path, repo) = create(&tmp).await;
        let cref = Ref::collection(OWN, "app/main");
        let commit = checksum(1);

        let txn = repo.transaction().await.unwrap();
        txn.set_ref(&cref, Some(&commit));
        txn.commit().await.unwrap();
        assert_local_alone(&path, "app/main", &commit, "transaction");
        let txn = repo.transaction().await.unwrap();
        txn.set_ref(&cref, None);
        txn.commit().await.unwrap();
        assert!(heads(&path).is_empty(), "transaction removal");

        repo.set_ref_immediate(&cref, Some(&commit)).await.unwrap();
        assert_local_alone(&path, "app/main", &commit, "immediate");
        repo.set_ref_immediate(&cref, None).await.unwrap();
        assert!(heads(&path).is_empty(), "immediate removal");

        let guard = repo.begin_update().await.unwrap();
        guard.set_ref(&cref, Some(&commit)).await.unwrap();
        assert_eq!(guard.read_ref(&cref).await.unwrap(), Some(commit));
        guard.finish().await.unwrap();
        assert_local_alone(&path, "app/main", &commit, "guard");
        let guard = repo.begin_update().await.unwrap();
        guard.set_ref(&cref, None).await.unwrap();
        assert_eq!(guard.read_ref(&cref).await.unwrap(), None);
        guard.finish().await.unwrap();
        assert!(heads(&path).is_empty(), "guard removal");

        // Another collection id writes its mirror ref.
        let other = Ref::collection(OTHER, "app/main");
        repo.set_ref_immediate(&other, Some(&commit)).await.unwrap();
        assert!(heads(&path).is_empty());
        assert_eq!(
            file_inventory(&path, "refs/mirrors"),
            [(
                format!("refs/mirrors/{OTHER}/app/main"),
                format!("{}\n", commit.to_hex()).into_bytes()
            )]
        );
    });
}

/// A removal through a writer of the own collection id removes the local ref
/// and keeps a mirror ref of the name.
#[test]
fn a_removal_of_the_own_collection_id_keeps_the_mirror_ref() {
    let tmp = TmpDir::new("own-id-removal");
    block_on(async {
        let (path, repo) = create(&tmp).await;
        put_own_mirror(&path, "main", &checksum(1));
        repo.set_ref_immediate(&Ref::local("main"), Some(&checksum(2)))
            .await
            .unwrap();
        repo.set_ref_immediate(&Ref::collection(OWN, "main"), None)
            .await
            .unwrap();
        assert!(heads(&path).is_empty());
        assert_eq!(
            file_inventory(&path, "refs/mirrors"),
            [(
                format!("refs/mirrors/{OWN}/main"),
                format!("{}\n", checksum(1).to_hex()).into_bytes()
            )]
        );
    });
}

/// The guard read and the collection ref listing of the own collection id
/// read `refs/heads` and ignore `refs/mirrors/ID/` of that id.
#[test]
fn the_readers_of_the_own_collection_id_ignore_the_mirror_refs() {
    let tmp = TmpDir::new("own-id-readers");
    block_on(async {
        let (path, repo) = create(&tmp).await;
        put_own_mirror(&path, "main", &checksum(1));
        put_own_mirror(&path, "shadow", &checksum(1));
        repo.set_ref_immediate(&Ref::local("main"), Some(&checksum(2)))
            .await
            .unwrap();
        repo.set_ref_immediate(&Ref::collection(OTHER, "x"), Some(&checksum(3)))
            .await
            .unwrap();

        let guard = repo.begin_update().await.unwrap();
        for (name, want) in [("main", Some(checksum(2))), ("shadow", None)] {
            let cref = Ref::collection(OWN, name);
            assert_eq!(guard.read_ref(&cref).await.unwrap(), want, "{name}");
        }
        guard.finish().await.unwrap();

        let entry = |collection: &str, name: &str, byte: u8, local: bool| CollectionRefEntry {
            collection: collection.to_owned(),
            name: name.to_owned(),
            commit: checksum(byte),
            local,
        };
        assert_eq!(
            repo.list_collection_refs().await.unwrap(),
            [entry(OTHER, "x", 3, false), entry(OWN, "main", 2, true)]
        );
        let mut mirrors = repo.list_mirror_refs().await.unwrap();
        mirrors.sort();
        assert_eq!(mirrors.len(), 3, "the mirror listing holds each file");
    });
}

/// The collection ref listing does not read `refs/mirrors/ID/` of the own
/// collection id, so a malformed file there does not fail it. The mirror
/// listing reads each file and fails.
#[test]
fn the_collection_ref_listing_does_not_read_the_mirror_refs_of_the_own_id() {
    let tmp = TmpDir::new("own-id-listing-malformed");
    block_on(async {
        let (path, repo) = create(&tmp).await;
        let dir = path.join("refs/mirrors").join(OWN);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("text"), "no checksum\n").unwrap();
        std::fs::write(dir.join("sub/bytes"), [0xff, 0xfe, b'\n']).unwrap();
        repo.set_ref_immediate(&Ref::local("main"), Some(&checksum(2)))
            .await
            .unwrap();
        repo.set_ref_immediate(&Ref::collection(OTHER, "x"), Some(&checksum(3)))
            .await
            .unwrap();

        let entry = |collection: &str, name: &str, byte: u8, local: bool| CollectionRefEntry {
            collection: collection.to_owned(),
            name: name.to_owned(),
            commit: checksum(byte),
            local,
        };
        assert_eq!(
            repo.list_collection_refs().await.unwrap(),
            [entry(OTHER, "x", 3, false), entry(OWN, "main", 2, true)]
        );
        assert!(repo.list_mirror_refs().await.is_err());
    });
}

/// The back-ref check of the fsck finds the collection ref of the own
/// collection id under `refs/heads` alone. A ref under `refs/mirrors/ID/` of
/// that id gives no collection ref.
#[test]
fn the_fsck_back_ref_check_ignores_the_mirror_refs_of_the_own_id() {
    let tmp = TmpDir::new("own-id-fsck-back-refs");
    block_on(async {
        let (path, repo) = create(&tmp).await;
        let main = commit(&repo, tmp.path(), "main", Some(OWN), &["main"]).await;
        let mirrored = commit(&repo, tmp.path(), "mirrored", Some(OTHER), &[]).await;
        repo.set_ref_immediate(&Ref::local("main"), Some(&main))
            .await
            .unwrap();
        put_own_mirror(&path, "main", &mirrored);
        let opts = FsckOptions {
            verify_back_refs: true,
            ..FsckOptions::default()
        };

        let report = repo.fsck(&opts).await.unwrap();
        assert!(report.failure.is_none(), "{report:?}");
        assert_eq!(report.own_mirror_refs, ["main"]);

        // A remote ref gives the ref binding a ref, and `refs/heads` holds no
        // collection ref of the name.
        repo.set_ref_immediate(&Ref::local("main"), None)
            .await
            .unwrap();
        let remote = path.join("refs/remotes/origin/main");
        std::fs::create_dir_all(remote.parent().unwrap()).unwrap();
        std::fs::write(&remote, format!("{}\n", main.to_hex())).unwrap();
        let report = repo.fsck(&opts).await.unwrap();
        match &report.failure {
            Some(FsckFailure::Binding(error)) => {
                assert_eq!(error.commit, main);
                match &error.kind {
                    FsckBindingErrorKind::BackCollectionRefMissing {
                        collection_id,
                        ref_name,
                    } => {
                        assert_eq!(collection_id, OWN);
                        assert_eq!(ref_name, "main");
                    }
                    other => panic!("{other:?}"),
                }
            }
            other => panic!("{other:?}"),
        }
    });
}

/// The fsck lists each ref under `refs/mirrors/ID/` of the own collection id
/// in `own_mirror_refs`, and the list does not stop a pass. The fsck checks
/// the commit of such a ref: an absent commit ends the run, and a binding
/// mismatch under `verify_bindings` ends it too.
#[test]
fn the_fsck_lists_the_mirror_refs_of_the_own_collection_id() {
    let tmp = TmpDir::new("own-id-fsck");
    block_on(async {
        let (path, repo) = create(&tmp).await;
        let main = commit(&repo, tmp.path(), "main", Some(OWN), &[]).await;
        repo.set_ref_immediate(&Ref::local("main"), Some(&main))
            .await
            .unwrap();
        let mirrored = commit(&repo, tmp.path(), "mirrored", Some(OTHER), &[]).await;
        put_own_mirror(&path, "main", &mirrored);
        put_own_mirror(&path, "a/b", &mirrored);

        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert_eq!(report.own_mirror_refs, ["a/b", "main"]);
        assert!(report.is_ok(), "{report:?}");
        assert_eq!(report.commits_checked, 2);

        let opts = FsckOptions {
            verify_bindings: true,
            ..FsckOptions::default()
        };
        let report = repo.fsck(&opts).await.unwrap();
        match &report.failure {
            Some(FsckFailure::Binding(error)) => {
                assert_eq!(error.commit, mirrored);
                match &error.kind {
                    FsckBindingErrorKind::CollectionMismatch { bound, found_under } => {
                        assert_eq!(bound, OTHER);
                        assert_eq!(found_under, OWN);
                    }
                    other => panic!("{other:?}"),
                }
            }
            other => panic!("{other:?}"),
        }
        assert!(!report.is_ok());

        std::fs::remove_file(path.join(object_path(ObjectType::Commit, &mirrored))).unwrap();
        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert_eq!(report.own_mirror_refs, ["a/b", "main"]);
        match &report.failure {
            Some(FsckFailure::RefTarget {
                ref_name, commit, ..
            }) => {
                assert_eq!(ref_name, &format!("({OWN}, a/b)"));
                assert_eq!(commit, &mirrored);
            }
            other => panic!("{other:?}"),
        }
        assert!(!report.is_ok());
    });
}

/// A handle keeps the collection id that its open read. After a guard writes
/// a new `[core] collection-id`, `set_ref` of a ref of the new id on the same
/// guard writes `refs/mirrors/ID/NAME`. A guard of a new open writes
/// `refs/heads/NAME`.
#[test]
fn a_new_collection_id_applies_to_a_handle_of_a_new_open() {
    let tmp = TmpDir::new("own-id-new-open");
    block_on(async {
        let path = tmp.path().join("repo");
        let repo = Repo::create(&path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let cref = Ref::collection(OWN, "main");
        let commit = checksum(1);

        let guard = repo.begin_update().await.unwrap();
        let mut keyfile = repo.config().keyfile().clone();
        keyfile.set_value("core", "collection-id", OWN).unwrap();
        guard.write_config(&keyfile).await.unwrap();
        guard.set_ref(&cref, Some(&commit)).await.unwrap();
        guard.finish().await.unwrap();
        let mirror = [(
            format!("refs/mirrors/{OWN}/main"),
            format!("{}\n", commit.to_hex()).into_bytes(),
        )];
        assert!(heads(&path).is_empty());
        assert_eq!(file_inventory(&path, "refs/mirrors"), mirror);

        let repo = Repo::open(&path).await.unwrap();
        let guard = repo.begin_update().await.unwrap();
        guard.set_ref(&cref, Some(&commit)).await.unwrap();
        guard.finish().await.unwrap();
        assert_eq!(
            heads(&path),
            [(
                "refs/heads/main".to_owned(),
                format!("{}\n", commit.to_hex())
            )]
        );
        // The write of the new open leaves the file of the first handle.
        assert_eq!(file_inventory(&path, "refs/mirrors"), mirror);
    });
}
