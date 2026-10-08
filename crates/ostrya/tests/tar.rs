//! Integration tests for tar import and export.
//!
//! The tests check interoperability and round-trip stability. The archive
//! bytes of ostrya differ from the output of `ostree export`. The `ostree`
//! command writes headers with the old GNU magic. The `smol-tar` crate writes
//! POSIX ustar and pax headers.
//!
//! `imports_tool_export_into_matching_tree` checks the direction from the
//! `ostree` command to ostrya with the checked-in `export.tar`. The round-trip
//! test checks that ostrya reproduces a tree, with its xattrs, through its own
//! export and import.

mod common;

use common::{
    COMMIT, ROOT_DIRMETA, ROOT_DIRTREE, TmpDir, fixture_repo, fixture_root, ostree_available,
};
use futures_lite::StreamExt;
use futures_lite::io::Cursor;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, FilterResult,
    MutableTree, Repo, RepoMode, TarExportOptions, TarImportOptions, TreeEntry,
};
use ostrya_rt::block_on;
use smol_tar::{TarDevice, TarDirectory, TarEntry, TarFifo, TarReader, TarRegularFile, TarWriter};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn csum(hex: &str) -> Checksum {
    Checksum::from_hex(hex).unwrap()
}

/// Returns `value` unchanged. The bound checks at compile time that the type
/// is `Send`. The tests pass the import futures, with their callbacks, through
/// it.
fn assert_send<T: Send>(value: T) -> T {
    value
}

/// The type of the body reader in the test archives that [`TarWriter`] builds.
type TestBody = Cursor<Vec<u8>>;

/// An import of the archive that `ostree export` wrote gives the root dirtree
/// and the root dirmeta of the fixture commit. This test checks the tree
/// fidelity from the `ostree` command to ostrya.
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

/// An export and an import by ostrya reproduce the source tree with the
/// `user.demo` xattr. The xattr survives only if it travels as a SCHILY record
/// and the import rebuilds the same content object.
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

/// Two byte-identical files import to one content object. The export writes the
/// second file as a hardlink to the first file.
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

        // The export writes the repeated file as a hardlink.
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
            // The archive has no root member and no `usr/` member, so the
            // import must synthesize both parents of the remapped member.
            let mut opts = TarImportOptions::new().with_etc_migration(true);
            opts.autocreate_parents = true;
            let mut mtree = repo
                .import_tar(&txn, opts, Cursor::new(built))
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

/// The import futures are `Send` with a rename hook, parent synthesis, and a
/// modifier with callbacks. The archive has no parent member, so the import
/// must synthesize both parents of the renamed path. The filter and the mode
/// callback of the modifier each run at least once.
#[test]
fn import_futures_are_send() {
    let tmp = TmpDir::new("tar-send");
    block_on(async {
        let built = single_entry_tar(
            TarRegularFile::new("a/hello", 5, Cursor::new(b"send\n".to_vec())).into(),
        )
        .await;
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let txn = repo.transaction().await.unwrap();

        // The pin needs only the type of the future, so the test does not
        // await it.
        let opts = TarImportOptions {
            rename: Some(Box::new(|name| Ok(name.to_owned()))),
            autocreate_parents: true,
            ..Default::default()
        };
        drop(assert_send(repo.import_tar(&txn, opts, &built[..])));

        let opts = TarImportOptions {
            rename: Some(Box::new(|name| Ok(format!("b/{name}")))),
            autocreate_parents: true,
            ..Default::default()
        };
        let mut modifier = CommitModifier::new(CommitModifierFlags::empty());
        let filter_calls = Arc::new(AtomicUsize::new(0));
        let mode_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&filter_calls);
        modifier.filter = Some(Box::new(move |_path, _meta| {
            calls.fetch_add(1, Ordering::Relaxed);
            FilterResult::Allow
        }));
        let calls = Arc::clone(&mode_calls);
        modifier.mode_callback = Some(Box::new(move |_path, meta| {
            calls.fetch_add(1, Ordering::Relaxed);
            meta.mode
        }));
        let mut mtree = MutableTree::new();
        assert_send(repo.import_tar_into(
            &txn,
            opts,
            Cursor::new(built),
            &mut mtree,
            Some(&mut modifier),
        ))
        .await
        .unwrap();
        assert!(filter_calls.load(Ordering::Relaxed) > 0, "the filter ran");
        assert!(
            mode_calls.load(Ordering::Relaxed) > 0,
            "the mode callback ran"
        );
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let commit = txn
            .write_commit(CommitOptions::default(), &root)
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let (root, _) = repo.read_commit(&commit.to_hex()).await.unwrap();
        assert!(
            root.lookup(Path::new("b/a/hello")).await.unwrap().is_some(),
            "the member was renamed under synthesized parents"
        );
    });
}

/// GNU tar reads the export of ostrya. The `ostree` command imports it again
/// into a tree that is identical to the fixture. This test checks the direction
/// from ostrya to the `ostree` command. If the command is not available, the
/// test skips.
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

    // GNU tar reads the archive of ostrya.
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

    // The `ostree` command imports the archive into an identical tree.
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

/// The import refuses device and FIFO members, because an ostree tree cannot
/// hold them.
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

/// The import refuses a member with a pathname that is not valid UTF-8. This
/// crate stores pathnames as text. The decode failure of the reader returns as
/// [`ostrya::Error::TarPathname`]. The message of this error is the line that
/// the CLI prints.
#[test]
fn import_rejects_a_pathname_that_is_not_utf8() {
    let tmp = TmpDir::new("tar-pathname");
    block_on(async {
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let txn = repo.transaction().await.unwrap();
        let err = repo
            .import_tar(
                &txn,
                TarImportOptions::new(),
                Cursor::new(invalid_pathname_tar()),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ostrya::Error::TarPathname), "got {err:?}");
        txn.abort().await.unwrap();
    });
}

/// Returns an archive with a `./` root member and one regular file with the
/// byte `0xFF` in its name. [`TarWriter`] takes each pathname as text, so this
/// function writes the two header blocks directly.
fn invalid_pathname_tar() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&ustar_header(b"./", 0o755, b'5', 0));
    let body = b"hello\n";
    out.extend_from_slice(&ustar_header(b"./b\xFFd.txt", 0o644, b'0', body.len()));
    out.extend_from_slice(body);
    out.resize(out.len().next_multiple_of(512), 0);
    // Two zero blocks end the stream. Then the function pads the archive to the
    // size of a tar record.
    out.resize(out.len() + 1024, 0);
    out.resize(out.len().next_multiple_of(10240), 0);
    out
}

/// Returns one 512-byte ustar header block. The function takes the name as
/// bytes, so the name can hold bytes that are not valid UTF-8.
fn ustar_header(name: &[u8], mode: u32, typeflag: u8, size: usize) -> [u8; 512] {
    let mut h = [0u8; 512];
    let put = |h: &mut [u8; 512], at: usize, bytes: &[u8]| {
        h[at..at + bytes.len()].copy_from_slice(bytes);
    };
    put(&mut h, 0, name);
    put(&mut h, 100, format!("{mode:07o}\0").as_bytes());
    put(&mut h, 108, b"0000000\0");
    put(&mut h, 116, b"0000000\0");
    put(&mut h, 124, format!("{size:011o}\0").as_bytes());
    put(&mut h, 136, b"00000000000\0");
    // The sum counts the checksum field as eight spaces. The function writes
    // the field after the sum.
    put(&mut h, 148, b"        ");
    h[156] = typeflag;
    put(&mut h, 257, b"ustar\0");
    put(&mut h, 263, b"00");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    put(&mut h, 148, format!("{sum:06o}\0 ").as_bytes());
    h
}

/// Builds a one-member archive from a metadata-only entry.
async fn single_entry_tar(entry: TarEntry<'static, TestBody>) -> Vec<u8> {
    let mut sink = Cursor::new(Vec::new());
    {
        let mut writer = TarWriter::<'_, '_, _, TestBody>::new(&mut sink);
        writer.write(entry).await.unwrap();
        writer.finish().await.unwrap();
    }
    sink.into_inner()
}
