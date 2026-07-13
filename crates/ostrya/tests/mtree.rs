//! Mutable-tree and write_mtree integration tests (Phase 7b).
//!
//! These build trees in memory and serialize them through `write_mtree`:
//! reproducing the fixture's dirtree and dirmeta objects byte-for-byte from
//! known checksums, the clean-tree short-circuit (`from_commit` then
//! `write_mtree` stages nothing), the spine-only rewrite when one nested file
//! changes, the unset-dirmeta contract, and insertion-time validation.

mod common;

use std::path::Path;
use std::process::Command;

use common::{
    EMPTY_TXT, HELLO_TXT, LINK, NESTED_TXT, ROOT_DIRMETA, ROOT_DIRTREE, SUBDIR_DIRTREE, TmpDir,
    fixture_repo,
};
use futures_lite::io::Cursor;
use ostrya::{Checksum, CreateOptions, Error, FileMeta, MutableTree, Repo, RepoMode};
use ostrya_core::{DirMeta, ObjectType, Xattrs, loose_path};
use ostrya_rt::block_on;

fn csum(hex: &str) -> Checksum {
    Checksum::from_hex(hex).unwrap()
}

/// The dirmeta shared by every directory in the fixture tree: a 0755 directory
/// owned 0:0 with no xattrs.
fn fixture_dirmeta() -> DirMeta {
    DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040755,
        xattrs: Xattrs::empty(),
    }
}

/// The bytes of a loose object in a repository rooted at `root`.
fn object_bytes(root: &Path, hex: &str, ty: ObjectType, mode: RepoMode) -> Vec<u8> {
    std::fs::read(root.join("objects").join(loose_path(&csum(hex), ty, mode))).unwrap()
}

/// The bytes of a loose object in the checked-in bare-user fixture repository.
fn fixture_bytes(hex: &str, ty: ObjectType) -> Vec<u8> {
    std::fs::read(fixture_repo("bare-user").join("objects").join(loose_path(
        &csum(hex),
        ty,
        RepoMode::BareUser,
    )))
    .unwrap()
}

/// Copy the bare-user fixture repository into `dst`, giving a writable repo that
/// already holds a committed tree resolvable as `test/main`.
fn copy_bare_user_fixture(dst: &Path) {
    let src = fixture_repo("bare-user");
    let status = Command::new("cp")
        .arg("-a")
        .arg(&src)
        .arg(dst)
        .status()
        .expect("run cp");
    assert!(status.success(), "cp -a of the bare-user fixture failed");
}

#[test]
fn assembles_the_fixture_tree_byte_for_byte() {
    let tmp = TmpDir::new("mtree-assemble");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();

        // Stage the shared dirmeta from its value; its identity is the fixture's
        // root dirmeta, and its bytes are byte-for-byte the fixture's.
        let dirmeta_bytes = fixture_dirmeta().serialize().unwrap();
        let dirmeta = txn
            .write_metadata(ObjectType::DirMeta, None, &dirmeta_bytes)
            .await
            .unwrap();
        assert_eq!(dirmeta, csum(ROOT_DIRMETA), "dirmeta identity");

        // Build the fixture tree from the known content checksums.
        let mut mtree = MutableTree::new();
        mtree.set_metadata_checksum(dirmeta);
        mtree.replace_file("empty.txt", csum(EMPTY_TXT)).unwrap();
        mtree.replace_file("hello.txt", csum(HELLO_TXT)).unwrap();
        mtree.replace_file("link", csum(LINK)).unwrap();
        let subdir = mtree.ensure_dir("subdir").await.unwrap();
        subdir.set_metadata_checksum(dirmeta);
        subdir.replace_file("nested.txt", csum(NESTED_TXT)).unwrap();

        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        assert_eq!(rt.dirtree_checksum(), &csum(ROOT_DIRTREE), "root dirtree");
        assert_eq!(rt.dirmeta_checksum(), &csum(ROOT_DIRMETA), "root dirmeta");

        let stats = txn.commit().await.unwrap();
        // Two dirtrees plus the one shared dirmeta.
        assert_eq!(stats.metadata_written, 3);
        assert_eq!(stats.content_written, 0);

        // The published dirtree and dirmeta objects are byte-for-byte the
        // fixture's.
        for hex in [ROOT_DIRTREE, SUBDIR_DIRTREE] {
            assert_eq!(
                object_bytes(&root, hex, ObjectType::DirTree, RepoMode::BareUser),
                fixture_bytes(hex, ObjectType::DirTree),
                "dirtree {hex}"
            );
        }
        assert_eq!(
            object_bytes(&root, ROOT_DIRMETA, ObjectType::DirMeta, RepoMode::BareUser),
            fixture_bytes(ROOT_DIRMETA, ObjectType::DirMeta),
            "dirmeta {ROOT_DIRMETA}"
        );
    });
}

#[test]
fn from_commit_then_write_mtree_without_mutation_is_a_noop() {
    let tmp = TmpDir::new("mtree-noop");
    let root = tmp.path().join("repo");
    copy_bare_user_fixture(&root);
    block_on(async {
        let repo = Repo::open(&root).await.unwrap();
        let txn = repo.transaction().await.unwrap();

        let mut mtree = MutableTree::from_commit(&repo, "test/main").await.unwrap();
        let rt = txn.write_mtree(&mut mtree).await.unwrap();

        // The unmutated root keeps its committed checksums.
        assert_eq!(rt.dirtree_checksum(), &csum(ROOT_DIRTREE));
        assert_eq!(rt.dirmeta_checksum(), &csum(ROOT_DIRMETA));

        let stats = txn.commit().await.unwrap();
        assert_eq!(stats.metadata_written, 0, "nothing re-serialized");
        assert_eq!(stats.content_written, 0);
    });
}

#[test]
fn mutating_one_nested_file_rewrites_only_the_spine() {
    let tmp = TmpDir::new("mtree-spine");
    let root = tmp.path().join("repo");
    copy_bare_user_fixture(&root);
    block_on(async {
        let repo = Repo::open(&root).await.unwrap();
        let txn = repo.transaction().await.unwrap();

        // Stage a new content object for the nested file.
        let new_nested = txn
            .write_content(
                None,
                &FileMeta::regular(0, 0, 0o644),
                Cursor::new(b"nested v2\n".to_vec()),
            )
            .await
            .unwrap();

        // Descend into the committed subdirectory (hydrating it) and replace
        // one file.
        let mut mtree = MutableTree::from_commit(&repo, "test/main").await.unwrap();
        let subdir = mtree.ensure_dir("subdir").await.unwrap();
        subdir.replace_file("nested.txt", new_nested).unwrap();

        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let new_root = *rt.dirtree_checksum();
        assert_ne!(new_root, csum(ROOT_DIRTREE), "root dirtree changed");
        // The dirmeta is shared and unchanged.
        assert_eq!(rt.dirmeta_checksum(), &csum(ROOT_DIRMETA));

        let stats = txn.commit().await.unwrap();
        // The spine is exactly the subdir dirtree and the root dirtree; the
        // shared dirmeta is reused, so only two metadata objects are new.
        assert_eq!(stats.metadata_written, 2, "only the spine dirtrees");
        assert_eq!(stats.content_written, 1, "the new nested content object");

        // The new root keeps the sibling files verbatim and points subdir at a
        // fresh dirtree whose sole file is the new content.
        let repo = Repo::open(&root).await.unwrap();
        let root_tree = repo.load_dirtree(&new_root).await.unwrap();
        assert_eq!(
            root_tree.files,
            vec![
                ("empty.txt".to_owned(), csum(EMPTY_TXT)),
                ("hello.txt".to_owned(), csum(HELLO_TXT)),
                ("link".to_owned(), csum(LINK)),
            ],
            "sibling files unchanged"
        );
        assert_eq!(root_tree.dirs.len(), 1);
        let (name, new_subdir, subdir_dirmeta) = &root_tree.dirs[0];
        assert_eq!(name, "subdir");
        assert_ne!(*new_subdir, csum(SUBDIR_DIRTREE), "subdir dirtree changed");
        assert_eq!(*subdir_dirmeta, csum(ROOT_DIRMETA), "subdir dirmeta reused");

        let subdir_tree = repo.load_dirtree(new_subdir).await.unwrap();
        assert_eq!(
            subdir_tree.files,
            vec![("nested.txt".to_owned(), new_nested)]
        );
        assert!(subdir_tree.dirs.is_empty());
    });
}

#[test]
fn write_mtree_requires_a_dirmeta_checksum() {
    let tmp = TmpDir::new("mtree-nodirmeta");
    let root = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();

        // The root directory has files but no dirmeta checksum.
        let mut mtree = MutableTree::new();
        mtree.replace_file("hello.txt", csum(HELLO_TXT)).unwrap();
        let err = txn.write_mtree(&mut mtree).await.unwrap_err();
        match err {
            Error::MutableTree(msg) => assert!(msg.contains('/'), "error names the path: {msg}"),
            other => panic!("expected a mutable-tree error, got {other:?}"),
        }
        txn.abort().await.unwrap();
    });
}

#[test]
fn rejects_invalid_names_and_collisions() {
    block_on(async {
        let some = csum(HELLO_TXT);

        // Invalid single-component names are rejected on insertion.
        let mut mtree = MutableTree::new();
        for name in ["", ".", "..", "a/b"] {
            assert!(
                matches!(mtree.replace_file(name, some), Err(Error::MutableTree(_))),
                "replace_file rejects {name:?}"
            );
            assert!(
                matches!(mtree.ensure_dir(name).await, Err(Error::MutableTree(_))),
                "ensure_dir rejects {name:?}"
            );
        }

        // A name cannot be both a file and a directory.
        let mut mtree = MutableTree::new();
        mtree.replace_file("x", some).unwrap();
        assert!(
            matches!(mtree.ensure_dir("x").await, Err(Error::MutableTree(_))),
            "ensure_dir over an existing file"
        );

        let mut mtree = MutableTree::new();
        mtree.ensure_dir("d").await.unwrap();
        assert!(
            matches!(mtree.replace_file("d", some), Err(Error::MutableTree(_))),
            "replace_file over an existing directory"
        );

        // Removing an absent entry honors allow_noent.
        let mut mtree = MutableTree::new();
        assert!(matches!(
            mtree.remove("gone", false),
            Err(Error::MutableTree(_))
        ));
        assert!(mtree.remove("gone", true).is_ok());
    });
}
