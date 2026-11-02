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

/// The export writes the body of each regular file with the same bytes. The
/// files are smaller and larger than the 64 KiB body buffer, and a small file
/// follows a large file, so the export uses one buffer for files of different
/// sizes. The repositories are in the `archive` mode, which inflates each
/// payload, and in the `bare-user` mode, which reads each payload raw.
#[test]
fn export_writes_file_bodies_of_each_size() {
    use futures_lite::AsyncReadExt;

    let files: Vec<(&str, Vec<u8>)> = [("a", 1), ("b", 200_000), ("c", 3), ("d", 70_000)]
        .into_iter()
        .map(|(name, len)| {
            let body = (0..len).map(|i| (i * 7 + name.len()) as u8 ^ name.as_bytes()[0]);
            (name, body.collect())
        })
        .collect();
    let mut sink = Cursor::new(Vec::new());
    block_on(async {
        let mut writer = TarWriter::<'_, '_, _, TestBody>::new(&mut sink);
        writer.write(TarDirectory::new("./").into()).await.unwrap();
        for (name, body) in &files {
            let entry = TarRegularFile::new(*name, body.len() as u64, Cursor::new(body.clone()));
            writer.write(entry.into()).await.unwrap();
        }
        writer.finish().await.unwrap();
    });
    let built = sink.into_inner();

    for mode in [RepoMode::Archive, RepoMode::BareUser] {
        let tmp = TmpDir::new("tar-export-sizes");
        block_on(async {
            let repo = Repo::create(&tmp.path().join("repo"), CreateOptions::new(mode))
                .await
                .unwrap();
            let txn = repo.transaction().await.unwrap();
            let mut mtree = repo
                .import_tar(&txn, TarImportOptions::new(), Cursor::new(built.clone()))
                .await
                .unwrap();
            let root = txn.write_mtree(&mut mtree).await.unwrap();
            let commit = txn
                .write_commit(CommitOptions::default(), &root)
                .await
                .unwrap();
            txn.commit().await.unwrap();

            let mut out = Cursor::new(Vec::new());
            repo.export_tar(&commit, TarExportOptions::new(), &mut out)
                .await
                .unwrap();
            let exported = out.into_inner();
            let mut reader = TarReader::new(Cursor::new(exported));
            let mut seen = Vec::new();
            while let Some(entry) = reader.next().await {
                if let TarEntry::File(mut file) = entry.unwrap() {
                    let name = file.path().to_owned();
                    let mut body = Vec::new();
                    file.read_to_end(&mut body).await.unwrap();
                    seen.push((name, body));
                }
            }
            let want: Vec<(String, Vec<u8>)> = files
                .iter()
                .map(|(name, body)| (name.to_string(), body.clone()))
                .collect();
            assert_eq!(seen, want, "{mode:?}: file bodies");
        });
    }
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

/// The import refuses each text field of a member that is not valid UTF-8.
/// The archives put the byte `0xFF` in the pathname, the GNU long name, the
/// PAX `path` record, the link target, the PAX `linkpath` record, and the
/// user name. Each decode failure of the reader returns as
/// [`ostrya::Error::Io`] with the kind `InvalidData`.
#[test]
fn import_rejects_text_fields_that_are_not_utf8() {
    let mut long_name = vec![b'd'; 120];
    long_name.extend_from_slice(b"\xFF\0");
    let pax_path = pax_body(&[(b"path", b"b\xFF")]);
    let pax_linkpath = pax_body(&[(b"linkpath", b"t\xFF")]);
    let cases: [(&str, Vec<u8>); 6] = [
        ("ustar name", invalid_pathname_tar()),
        (
            "GNU long name",
            raw_tar(&[
                (
                    header_block(GNU, b"././@LongLink", 0o644, b'L', long_name.len(), &[]),
                    &long_name,
                ),
                (
                    header_block(GNU, &long_name[..99], 0o644, b'0', 0, &[]),
                    b"",
                ),
            ]),
        ),
        (
            "PAX path",
            raw_tar(&[
                (
                    header_block(USTAR, b"./PaxHeaders/b", 0o644, b'x', pax_path.len(), &[]),
                    &pax_path,
                ),
                (header_block(USTAR, b"b", 0o644, b'0', 0, &[]), b""),
            ]),
        ),
        (
            "ustar linkname",
            raw_tar(&[(
                header_block(USTAR, b"l", 0o777, b'2', 0, &[(LINKNAME, b"t\xFF")]),
                b"",
            )]),
        ),
        (
            "PAX linkpath",
            raw_tar(&[
                (
                    header_block(
                        USTAR,
                        b"./PaxHeaders/l",
                        0o644,
                        b'x',
                        pax_linkpath.len(),
                        &[],
                    ),
                    &pax_linkpath,
                ),
                (
                    header_block(USTAR, b"l", 0o777, b'2', 0, &[(LINKNAME, b"t")]),
                    b"",
                ),
            ]),
        ),
        (
            "ustar uname",
            raw_tar(&[(
                header_block(USTAR, b"u", 0o644, b'0', 0, &[(UNAME, b"r\xFF")]),
                b"",
            )]),
        ),
    ];
    block_on(async {
        for (case, built) in cases {
            let tmp = TmpDir::new("tar-text-field");
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
            assert!(
                matches!(&err, ostrya::Error::Io(e) if e.kind() == std::io::ErrorKind::InvalidData),
                "{case}: got {err:?}"
            );
            txn.abort().await.unwrap();
        }
    });
}

/// The import refuses a symlink member with a size that is not 0. The member
/// has the size 6 and one data block that holds the target. The reader refuses
/// the member, and the error returns as [`ostrya::Error::Io`]. The `ostree`
/// command also refuses this archive, because it reads the data block as the
/// next header.
#[test]
fn import_rejects_a_symlink_with_a_data_block() {
    let built = raw_tar(&[(
        header_block(USTAR, b"l", 0o777, b'2', 6, &[(LINKNAME, b"target")]),
        b"target",
    )]);
    let tmp = TmpDir::new("tar-symlink-data");
    block_on(async {
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
        assert!(matches!(err, ostrya::Error::Io(_)), "got {err:?}");
        txn.abort().await.unwrap();
    });
}

/// A PAX extended header holds two records for one xattr:
/// `SCHILY.xattr.user.a=1` and then `SCHILY.xattr.user.a=2`. The import keeps
/// the last record. The file object carries one xattr `user.a` with the value
/// `2`. The `ostree` command stores both values, so the port writes a
/// different file object. This is a recorded divergence.
#[test]
fn import_keeps_the_last_pax_record_of_an_xattr() {
    let pax = pax_body(&[
        (b"SCHILY.xattr.user.a", b"1"),
        (b"SCHILY.xattr.user.a", b"2"),
    ]);
    let body = b"xattr\n";
    let built = raw_tar(&[
        (
            header_block(USTAR, b"./PaxHeaders/f", 0o644, b'x', pax.len(), &[]),
            &pax,
        ),
        (
            header_block(USTAR, b"f", 0o644, b'0', body.len(), &[]),
            body,
        ),
    ]);
    let tmp = TmpDir::new("tar-xattr-twice");
    block_on(async {
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let txn = repo.transaction().await.unwrap();
        let mut mtree = repo
            .import_tar(&txn, TarImportOptions::new(), Cursor::new(built))
            .await
            .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        txn.commit().await.unwrap();

        let tree = repo.load_dirtree(root.dirtree_checksum()).await.unwrap();
        let file = tree.files.iter().find(|(n, _)| n == "f").unwrap().1;
        let file = repo.load_file(&file).await.unwrap();
        let xattrs: Vec<(&[u8], &[u8])> = file.xattrs.iter().collect();
        assert_eq!(xattrs, [(b"user.a\0".as_slice(), b"2".as_slice())]);
    });
}

/// Returns an archive with a `./` root member and one regular file with the
/// byte `0xFF` in its name. [`TarWriter`] takes each pathname as text, so this
/// function writes the two header blocks directly.
fn invalid_pathname_tar() -> Vec<u8> {
    raw_tar(&[(
        header_block(USTAR, b"./b\xFFd.txt", 0o644, b'0', 6, &[]),
        b"hello\n",
    )])
}

/// Returns an archive with a `./` root member and then each member of
/// `members`. A member is a header block and its data. The function pads the
/// data of each member to a full block.
fn raw_tar(members: &[([u8; 512], &[u8])]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&header_block(USTAR, b"./", 0o755, b'5', 0, &[]));
    for (header, data) in members {
        out.extend_from_slice(header);
        out.extend_from_slice(data);
        out.resize(out.len().next_multiple_of(512), 0);
    }
    // Two zero blocks end the stream. Then the function pads the archive to the
    // size of a tar record.
    out.resize(out.len() + 1024, 0);
    out.resize(out.len().next_multiple_of(10240), 0);
    out
}

/// The magic and version fields of a POSIX ustar header, at offset 257.
const USTAR: &[u8; 8] = b"ustar\x0000";
/// The magic and version fields of an old GNU header, at offset 257.
const GNU: &[u8; 8] = b"ustar  \0";
/// The offset of the link target field in a header block.
const LINKNAME: usize = 157;
/// The offset of the user name field in a header block.
const UNAME: usize = 265;

/// Returns one 512-byte header block with the magic and version `magic`. The
/// function takes the name as bytes, so the name can hold bytes that are not
/// valid UTF-8. Each item of `fields` is an offset and the bytes that the
/// function writes there.
fn header_block(
    magic: &[u8; 8],
    name: &[u8],
    mode: u32,
    typeflag: u8,
    size: usize,
    fields: &[(usize, &[u8])],
) -> [u8; 512] {
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
    put(&mut h, 257, magic);
    for (at, bytes) in fields {
        put(&mut h, *at, bytes);
    }
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    put(&mut h, 148, format!("{sum:06o}\0 ").as_bytes());
    h
}

/// Returns the data of a PAX extended header with one record for each item of
/// `records`. A record is `<len> key=value\n`. The length counts the whole
/// record, with its own digits.
fn pax_body(records: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in records {
        // The space, the `=`, and the newline.
        let rest = key.len() + value.len() + 3;
        let mut len = rest;
        while rest + len.to_string().len() != len {
            len = rest + len.to_string().len();
        }
        out.extend_from_slice(format!("{len} ").as_bytes());
        out.extend_from_slice(key);
        out.push(b'=');
        out.extend_from_slice(value);
        out.push(b'\n');
    }
    out
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
