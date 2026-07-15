//! Phase 10 tar import/export integration tests.
//!
//! The gate is interoperability and round-trip stability, not byte-identity
//! with `ostree export` (the tool writes old-GNU-magic headers; smol-tar writes
//! POSIX ustar/pax). `imports_tool_export_into_matching_tree` proves the tool ->
//! port direction against a checked-in `export.tar`; the round-trip test proves
//! the port reproduces a tree, including xattrs, through its own export and
//! import.

mod common;

use common::{
    COMMIT, ROOT_DIRMETA, ROOT_DIRTREE, TmpDir, fixture_repo, fixture_root, ostree_available,
};
use futures_lite::StreamExt;
use futures_lite::io::Cursor;
use ostrya::{
    Checksum, CommitOptions, CreateOptions, Repo, RepoMode, TarExportOptions, TarImportOptions,
    TreeEntry,
};
use ostrya_rt::block_on;
use smol_tar::{TarDevice, TarDirectory, TarEntry, TarFifo, TarReader, TarRegularFile, TarWriter};
use std::path::Path;
use std::process::Command;

fn csum(hex: &str) -> Checksum {
    Checksum::from_hex(hex).unwrap()
}

/// The body-reader type used when building test archives with [`TarWriter`].
type TestBody = Cursor<Vec<u8>>;

/// Importing the tool's `ostree export` reproduces the fixture commit's root
/// dirtree and dirmeta exactly, proving tool -> port tree fidelity.
#[test]
fn imports_tool_export_into_matching_tree() {
    let Ok(tar_bytes) = std::fs::read(fixture_root().join("export.tar")) else {
        eprintln!("export.tar fixture absent; skipping");
        return;
    };
    let tmp = TmpDir::new("tar-import-tool");
    block_on(async {
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let txn = repo.transaction().await.unwrap();
        let mut mtree = repo
            .import_tar(&txn, TarImportOptions::new(), Cursor::new(tar_bytes))
            .await
            .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        assert_eq!(root.dirtree_checksum(), &csum(ROOT_DIRTREE), "root dirtree");
        assert_eq!(root.dirmeta_checksum(), &csum(ROOT_DIRMETA), "root dirmeta");
        txn.commit().await.unwrap();
    });
}

/// A port export followed by a port import reproduces the source tree, including
/// the `user.demo` xattr, which only survives if it travels as a SCHILY record
/// and rebuilds the same content object.
#[test]
fn export_import_roundtrip_preserves_xattr_tree() {
    let tmp = TmpDir::new("tar-roundtrip");
    block_on(async {
        let src = Repo::open(&fixture_repo("xattr")).await.unwrap();
        let (src_root, commit) = src.read_commit("test/main").await.unwrap();

        let mut sink = Cursor::new(Vec::new());
        src.export_tar(&commit, TarExportOptions::new(), &mut sink)
            .await
            .unwrap();
        let tar_bytes = sink.into_inner();

        let dest = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let txn = dest.transaction().await.unwrap();
        let mut mtree = dest
            .import_tar(&txn, TarImportOptions::new(), Cursor::new(tar_bytes))
            .await
            .unwrap();
        let dest_root = txn.write_mtree(&mut mtree).await.unwrap();

        assert_eq!(
            dest_root.dirtree_checksum(),
            src_root.dirtree_checksum(),
            "round-trip root dirtree"
        );
        assert_eq!(
            dest_root.dirmeta_checksum(),
            src_root.dirmeta_checksum(),
            "round-trip root dirmeta"
        );
        txn.commit().await.unwrap();
    });
}

/// Two byte-identical files import to one content object and export coalesces
/// the repeat into a hardlink to the first.
#[test]
fn identical_files_dedup_to_hardlink() {
    let tmp = TmpDir::new("tar-dedup");
    block_on(async {
        let mut sink = Cursor::new(Vec::new());
        {
            let mut writer = TarWriter::<'_, '_, _, TestBody>::new(&mut sink);
            writer.write(TarDirectory::new("./").into()).await.unwrap();
            writer
                .write(TarRegularFile::new("a.txt", 5, Cursor::new(b"dup!\n".to_vec())).into())
                .await
                .unwrap();
            writer
                .write(TarRegularFile::new("b.txt", 5, Cursor::new(b"dup!\n".to_vec())).into())
                .await
                .unwrap();
            writer.finish().await.unwrap();
        }
        let built = sink.into_inner();

        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let commit = {
            let txn = repo.transaction().await.unwrap();
            let mut mtree = repo
                .import_tar(&txn, TarImportOptions::new(), Cursor::new(built))
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

        // The two paths share one content object.
        let (root, _) = repo.read_commit(&commit.to_hex()).await.unwrap();
        let mut a = None;
        let mut b = None;
        for entry in root.read_dir().await.unwrap() {
            if let TreeEntry::File { name, checksum } = entry {
                match name.as_str() {
                    "a.txt" => a = Some(checksum),
                    "b.txt" => b = Some(checksum),
                    _ => {}
                }
            }
        }
        assert_eq!(a.unwrap(), b.unwrap(), "identical imports share one object");

        // Export coalesces the repeat into a hardlink.
        let mut out = Cursor::new(Vec::new());
        repo.export_tar(&commit, TarExportOptions::new(), &mut out)
            .await
            .unwrap();
        let exported = out.into_inner();

        let (mut regulars, mut links) = (0u32, 0u32);
        let mut reader = TarReader::new(Cursor::new(exported));
        while let Some(entry) = reader.next().await {
            match entry.unwrap() {
                TarEntry::File(file) if matches!(file.path(), "a.txt" | "b.txt") => regulars += 1,
                TarEntry::Link(link) if matches!(link.path(), "a.txt" | "b.txt") => {
                    assert!(matches!(link.link(), "a.txt" | "b.txt"), "hardlink target");
                    links += 1;
                }
                _ => {}
            }
        }
        assert_eq!((regulars, links), (1, 1), "one real file and one hardlink");
    });
}

/// `etc_to_usr_etc` rewrites a top-level `etc` component to `usr/etc`.
#[test]
fn etc_migration_remaps_top_level_etc() {
    let tmp = TmpDir::new("tar-etc");
    block_on(async {
        let mut sink = Cursor::new(Vec::new());
        {
            let mut writer = TarWriter::<'_, '_, _, TestBody>::new(&mut sink);
            writer
                .write(TarDirectory::new("etc/").into())
                .await
                .unwrap();
            writer
                .write(
                    TarRegularFile::new("etc/hostname", 5, Cursor::new(b"host\n".to_vec())).into(),
                )
                .await
                .unwrap();
            writer.finish().await.unwrap();
        }
        let built = sink.into_inner();

        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let commit = {
            let txn = repo.transaction().await.unwrap();
            let mut mtree = repo
                .import_tar(
                    &txn,
                    TarImportOptions::new().with_etc_migration(true),
                    Cursor::new(built),
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

        let (root, _) = repo.read_commit(&commit.to_hex()).await.unwrap();
        assert!(
            root.lookup(Path::new("usr/etc/hostname"))
                .await
                .unwrap()
                .is_some(),
            "etc/hostname was remapped under usr/etc"
        );
        assert!(
            root.lookup(Path::new("etc")).await.unwrap().is_none(),
            "no top-level etc remains"
        );
    });
}

/// The port's export is read by GNU tar and re-imported by the `ostree` tool
/// into a tree identical to the fixture -- the port -> tool interoperability
/// direction. Skipped where the tool is unavailable.
#[test]
fn tool_reimports_port_export() {
    if !ostree_available() {
        eprintln!("ostree tool unavailable; skipping port -> tool cross-check");
        return;
    }
    let tmp = TmpDir::new("tar-tool-reimport");
    let tar_path = tmp.path().join("port.tar");

    block_on(async {
        let repo = Repo::open(&fixture_repo("archive")).await.unwrap();
        let mut sink = Cursor::new(Vec::new());
        repo.export_tar(&csum(COMMIT), TarExportOptions::new(), &mut sink)
            .await
            .unwrap();
        std::fs::write(&tar_path, sink.into_inner()).unwrap();
    });

    // GNU tar reads the port's archive.
    let listing = Command::new("tar")
        .arg("-tf")
        .arg(&tar_path)
        .output()
        .expect("run GNU tar");
    assert!(
        listing.status.success(),
        "GNU tar could not read the port's tar"
    );
    let names = String::from_utf8_lossy(&listing.stdout);
    assert!(
        names.contains("hello.txt") && names.contains("subdir/nested.txt"),
        "unexpected tar listing: {names}"
    );

    // The tool re-imports it into an identical tree.
    let repo2 = tmp.path().join("repo2");
    let repo2_arg = format!("--repo={}", repo2.display());
    assert!(
        Command::new("ostree")
            .args([&repo2_arg, "init", "--mode=archive"])
            .status()
            .unwrap()
            .success(),
        "ostree init failed"
    );
    assert!(
        Command::new("ostree")
            .args([
                &repo2_arg,
                "commit",
                "-b",
                "imported",
                &format!("--tree=tar={}", tar_path.display()),
            ])
            .status()
            .unwrap()
            .success(),
        "ostree commit --tree=tar failed"
    );

    block_on(async {
        let repo = Repo::open(&repo2).await.unwrap();
        let (root, _) = repo.read_commit("imported").await.unwrap();
        assert_eq!(
            root.dirtree_checksum(),
            &csum(ROOT_DIRTREE),
            "tool re-import of the port's tar reproduces the fixture root dirtree"
        );
        assert_eq!(root.dirmeta_checksum(), &csum(ROOT_DIRMETA), "root dirmeta");
    });
}

/// Device and FIFO members cannot enter an ostree tree and are rejected.
#[test]
fn import_rejects_unsupported_nodes() {
    block_on(async {
        let device = single_entry_tar(TarDevice::new_char("dev/null", 1, 3).into()).await;
        let fifo = single_entry_tar(TarFifo::new("run/pipe").into()).await;
        for built in [device, fifo] {
            let tmp = TmpDir::new("tar-reject");
            let repo = Repo::create(
                &tmp.path().join("repo"),
                CreateOptions::new(RepoMode::Archive),
            )
            .await
            .unwrap();
            let txn = repo.transaction().await.unwrap();
            let err = repo
                .import_tar(&txn, TarImportOptions::new(), Cursor::new(built))
                .await
                .unwrap_err();
            assert!(matches!(err, ostrya::Error::Tar(_)), "got {err:?}");
            txn.abort().await.unwrap();
        }
    });
}

/// Build a one-member archive from a metadata-only entry.
async fn single_entry_tar(entry: TarEntry<'static, TestBody>) -> Vec<u8> {
    let mut sink = Cursor::new(Vec::new());
    {
        let mut writer = TarWriter::<'_, '_, _, TestBody>::new(&mut sink);
        writer.write(entry).await.unwrap();
        writer.finish().await.unwrap();
    }
    sink.into_inner()
}
