//! Integration tests of `MutableTree` and `write_mtree`.
//!
//! The tests build trees in memory and write them with `write_mtree`. They
//! check these behaviors:
//!
//! - From known checksums, `write_mtree` writes the dirtree and dirmeta
//!   objects of the fixture byte for byte.
//! - A clean tree stages nothing: `from_commit` and then `write_mtree` write
//!   no object.
//! - If one nested file changes, `write_mtree` rewrites only the spine: the
//!   dirtrees on the path from the file to the root.
//! - Each directory must have a dirmeta checksum.
//! - Each insertion checks the name.

mod common;

use std::path::Path;
use std::process::Command;

use common::{
    EMPTY_TXT, HELLO_TXT, LINK, NESTED_TXT, ROOT_DIRMETA, ROOT_DIRTREE, SUBDIR_DIRTREE, TmpDir,
    fixture_repo,
};
use futures_lite::io::Cursor;
use ostrya::{
    Checksum, CommitOptions, CreateOptions, Error, FileMeta, MutableTree, Repo, RepoMode,
};
use ostrya_core::{DirMeta, ObjectType, Xattrs, loose_path};
use ostrya_rt::block_on;

fn csum(hex: &str) -> Checksum {
    Checksum::from_hex(hex).unwrap()
}

/// Returns the dirmeta of each directory in the fixture tree: a 0755 directory
/// with owner 0:0 and no xattrs.
fn fixture_dirmeta() -> DirMeta {
    DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040755,
        xattrs: Xattrs::empty(),
    }
}

/// Returns the bytes of a loose object in the repository at `root`.
fn object_bytes(root: &Path, hex: &str, ty: ObjectType, mode: RepoMode) -> Vec<u8> {
    std::fs::read(root.join("objects").join(loose_path(&csum(hex), ty, mode))).unwrap()
}

/// Returns the bytes of a loose object in the bare-user fixture repository.
fn fixture_bytes(hex: &str, ty: ObjectType) -> Vec<u8> {
    std::fs::read(fixture_repo("bare-user").join("objects").join(loose_path(
        &csum(hex),
        ty,
        RepoMode::BareUser,
    )))
    .unwrap()
}

/// Copies the bare-user fixture repository into `dst`. The copy is a writable
/// repository that holds a committed tree at the ref `test/main`.
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

        // Stage the shared dirmeta from its value. Its checksum is the root
        // dirmeta of the fixture, and its bytes are the bytes of the fixture.
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
        // Two dirtrees and the one shared dirmeta.
        assert_eq!(stats.metadata_written, 3);
        assert_eq!(stats.content_written, 0);

        // The published dirtree and dirmeta objects are byte for byte the
        // objects of the fixture.
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

        // The root has no change, so it keeps its committed checksums.
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

        // Descend into the committed subdirectory and replace one file. The
        // descent hydrates the subdirectory.
        let mut mtree = MutableTree::from_commit(&repo, "test/main").await.unwrap();
        let subdir = mtree.ensure_dir("subdir").await.unwrap();
        subdir.replace_file("nested.txt", new_nested).unwrap();

        let rt = txn.write_mtree(&mut mtree).await.unwrap();
        let new_root = *rt.dirtree_checksum();
        assert_ne!(new_root, csum(ROOT_DIRTREE), "root dirtree changed");
        // The dirmeta is shared and has no change.
        assert_eq!(rt.dirmeta_checksum(), &csum(ROOT_DIRMETA));

        let stats = txn.commit().await.unwrap();
        // The spine is exactly the subdir dirtree and the root dirtree. The
        // transaction reuses the shared dirmeta, so only two metadata objects
        // are new.
        assert_eq!(stats.metadata_written, 2, "only the spine dirtrees");
        assert_eq!(stats.content_written, 1, "the new nested content object");

        // The new root keeps the sibling files with no change. It points
        // `subdir` at a new dirtree whose only file is the new content.
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

/// Creates a repository at `root` with one commit at the ref `test/main`.
///
/// The tree of the commit holds `a/b/leaf.txt`, a top-level `top.txt`, and a
/// top-level symlink `to_a -> a`. Each directory has the fixture dirmeta, so
/// `ROOT_DIRMETA` identifies a hydrated level. Returns the handle and the root
/// dirtree checksum of the commit.
async fn two_level_repo(root: &Path) -> (Repo, Checksum) {
    let repo = Repo::create(root, CreateOptions::new(RepoMode::BareUser))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let dirmeta_bytes = fixture_dirmeta().serialize().unwrap();
    let dirmeta = txn
        .write_metadata(ObjectType::DirMeta, None, &dirmeta_bytes)
        .await
        .unwrap();
    let content = txn
        .write_content(
            None,
            &FileMeta::regular(0, 0, 0o644),
            Cursor::new(b"leaf\n".to_vec()),
        )
        .await
        .unwrap();

    // The tree stores a symlink as a file entry that names a content object.
    // The entry `to_a` is a file of the tree, although its target is the
    // directory `a`.
    let to_a = txn
        .write_symlink("a", &FileMeta::regular(0, 0, 0), None)
        .await
        .unwrap();

    let mut mtree = MutableTree::new();
    mtree.set_metadata_checksum(dirmeta);
    mtree.replace_file("top.txt", content).unwrap();
    mtree.replace_file("to_a", to_a).unwrap();
    {
        let a = mtree.ensure_dir("a").await.unwrap();
        a.set_metadata_checksum(dirmeta);
        let b = a.ensure_dir("b").await.unwrap();
        b.set_metadata_checksum(dirmeta);
        b.replace_file("leaf.txt", content).unwrap();
    }

    let rt = txn.write_mtree(&mut mtree).await.unwrap();
    let root_dirtree = *rt.dirtree_checksum();
    let commit = txn
        .write_commit(CommitOptions::default(), &rt)
        .await
        .unwrap();
    txn.set_ref("test/main", Some(&commit));
    txn.commit().await.unwrap();
    (repo, root_dirtree)
}

/// Asserts that `mtree` still holds exactly the committed tree.
///
/// The assertion has two parts:
///
/// - `mtree` writes the root dirtree checksum of the commit.
/// - A tree hydrated again from the same commit writes the same checksum.
///
/// If a refusal creates a directory, this assertion fails. A new directory
/// with no dirmeta makes the write fail. A new directory with a dirmeta
/// changes the root dirtree.
///
/// Each refusal test also reads the entry itself, which is the direct
/// observation. This function checks the whole tree.
async fn assert_matches_commit(repo: &Repo, mtree: &mut MutableTree, root_dirtree: Checksum) {
    let txn = repo.transaction().await.unwrap();
    let rt = txn.write_mtree(mtree).await.unwrap();
    assert_eq!(
        *rt.dirtree_checksum(),
        root_dirtree,
        "the tree still writes the committed root dirtree"
    );
    let mut fresh = MutableTree::from_commit(repo, "test/main").await.unwrap();
    let fresh_rt = txn.write_mtree(&mut fresh).await.unwrap();
    assert_eq!(
        fresh_rt.dirtree_checksum(),
        rt.dirtree_checksum(),
        "a fresh hydration of the same commit agrees"
    );
    txn.abort().await.unwrap();
}

#[test]
fn subtree_resolves_both_levels_of_a_hydrated_tree() {
    let tmp = TmpDir::new("mtree-subtree");
    block_on(async {
        let (repo, _) = two_level_repo(&tmp.path().join("repo")).await;

        let mut mtree = MutableTree::from_commit(&repo, "test/main").await.unwrap();
        let a = mtree.subtree("a").await.unwrap();
        assert_eq!(
            a.metadata_checksum(),
            Some(csum(ROOT_DIRMETA)),
            "the first level hydrated with its committed dirmeta"
        );
        let b = a.subtree("b").await.unwrap();
        assert_eq!(
            b.metadata_checksum(),
            Some(csum(ROOT_DIRMETA)),
            "the second level hydrated with its committed dirmeta"
        );
        // The directory loaded the leaf file with it, so `remove` of the file
        // succeeds.
        b.remove("leaf.txt", false).unwrap();

        // A second descent gets the child that is already loaded, and gives the
        // same result.
        let a = mtree.subtree("a").await.unwrap();
        assert_eq!(a.metadata_checksum(), Some(csum(ROOT_DIRMETA)));
        let b = a.subtree("b").await.unwrap();
        assert!(
            b.remove("leaf.txt", false).is_err(),
            "the loaded child is the one the first descent mutated"
        );
    });
}

#[test]
fn subtree_refuses_an_absent_name_at_either_level() {
    let tmp = TmpDir::new("mtree-subtree-absent");
    block_on(async {
        let (repo, root_dirtree) = two_level_repo(&tmp.path().join("repo")).await;

        let mut mtree = MutableTree::from_commit(&repo, "test/main").await.unwrap();
        match mtree.subtree("nope").await {
            Err(Error::PathNotFound { path }) => assert_eq!(path, "nope"),
            other => panic!("expected PathNotFound at the root, got {other:?}"),
        }
        {
            let a = mtree.subtree("a").await.unwrap();
            match a.subtree("nope").await {
                Err(Error::PathNotFound { path }) => assert_eq!(path, "nope"),
                other => panic!("expected PathNotFound one level down, got {other:?}"),
            }
            // Neither directory holds an entry of that name, so there is
            // nothing to remove. This assertion reads the entry that the
            // refusal names.
            assert!(
                matches!(a.remove("nope", false), Err(Error::MutableTree(_))),
                "the refusal one level down created no entry"
            );
        }
        assert!(
            matches!(mtree.remove("nope", false), Err(Error::MutableTree(_))),
            "the refusal at the root created no entry"
        );

        // Neither refusal changed the tree as a whole.
        assert_matches_commit(&repo, &mut mtree, root_dirtree).await;
    });
}

#[test]
fn subtree_refuses_a_file_name() {
    let tmp = TmpDir::new("mtree-subtree-file");
    block_on(async {
        let (repo, root_dirtree) = two_level_repo(&tmp.path().join("repo")).await;

        let mut mtree = MutableTree::from_commit(&repo, "test/main").await.unwrap();
        match mtree.subtree("top.txt").await {
            Err(Error::NotADirectory { path }) => assert_eq!(path, "top.txt"),
            other => panic!("expected NotADirectory at the root, got {other:?}"),
        }
        {
            let a = mtree.subtree("a").await.unwrap();
            let b = a.subtree("b").await.unwrap();
            match b.subtree("leaf.txt").await {
                Err(Error::NotADirectory { path }) => assert_eq!(path, "leaf.txt"),
                other => panic!("expected NotADirectory two levels down, got {other:?}"),
            }
            // The entry is still a file. `ensure_dir` reports this error on a
            // name that the tree holds as a file.
            assert!(
                matches!(
                    b.ensure_dir("leaf.txt").await,
                    Err(Error::ReplaceFileWithDir(name)) if name == "leaf.txt"
                ),
                "the refusal two levels down left the file in place"
            );
        }
        assert!(
            matches!(
                mtree.ensure_dir("top.txt").await,
                Err(Error::ReplaceFileWithDir(name)) if name == "top.txt"
            ),
            "the refusal at the root left the file in place"
        );

        // Neither refusal replaced a file with a directory.
        assert_matches_commit(&repo, &mut mtree, root_dirtree).await;
    });
}

#[test]
fn subtree_refuses_a_symlink_to_a_directory() {
    let tmp = TmpDir::new("mtree-subtree-symlink");
    block_on(async {
        let (repo, root_dirtree) = two_level_repo(&tmp.path().join("repo")).await;

        // `to_a` names the directory `a`. The mutable tree holds a symlink as a
        // file entry and reads no target, so the descent refuses the name.
        let mut mtree = MutableTree::from_commit(&repo, "test/main").await.unwrap();
        match mtree.subtree("to_a").await {
            Err(Error::NotADirectory { path }) => assert_eq!(path, "to_a"),
            other => panic!("expected NotADirectory for the symlink, got {other:?}"),
        }
        assert!(
            matches!(
                mtree.ensure_dir("to_a").await,
                Err(Error::ReplaceFileWithDir(name)) if name == "to_a"
            ),
            "the symlink is still a file entry"
        );

        assert_matches_commit(&repo, &mut mtree, root_dirtree).await;
    });
}

#[test]
fn rejects_invalid_names_and_collisions() {
    block_on(async {
        let some = csum(HELLO_TXT);

        // Each insertion refuses a name that is not a valid single component.
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
            assert!(
                matches!(mtree.subtree(name).await, Err(Error::MutableTree(_))),
                "subtree rejects {name:?}"
            );
        }

        // A name cannot be both a file and a directory. The two refusals name
        // the entry. A command that overlays one tree source on another
        // reports these refusals.
        let mut mtree = MutableTree::new();
        mtree.replace_file("x", some).unwrap();
        assert!(
            matches!(mtree.ensure_dir("x").await, Err(Error::ReplaceFileWithDir(name)) if name == "x"),
            "ensure_dir over an existing file"
        );

        let mut mtree = MutableTree::new();
        mtree.ensure_dir("d").await.unwrap();
        assert!(
            matches!(mtree.replace_file("d", some), Err(Error::ReplaceDirWithFile(name)) if name == "d"),
            "replace_file over an existing directory"
        );

        // If the entry is absent, `remove` obeys `allow_noent`.
        let mut mtree = MutableTree::new();
        assert!(matches!(
            mtree.remove("gone", false),
            Err(Error::MutableTree(_))
        ));
        assert!(mtree.remove("gone", true).is_ok());
    });
}
