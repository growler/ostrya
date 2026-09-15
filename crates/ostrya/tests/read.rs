//! Reading-path integration tests against the checked-in tool fixtures.
//!
//! These exercise the Phase 5 gate: read objects, refs, and full trees from a
//! tool-created repository and match the tool's own view. The metadata and
//! traversal assertions are mode-independent (the fixtures share object bytes),
//! so they run for both fixture repositories. The bare-user `load_file` path
//! depends on the `user.ostreemeta` xattr; the bare-user fixture ships as a
//! tarball that carries it (unpacked on demand), so these assertions always run.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use futures_lite::AsyncReadExt;
use ostrya::{
    Checksum, CommitState, CreateOptions, FileKind, MAX_METADATA_SIZE, ObjectType, Repo, RepoMode,
    TreeEntry, loose_path,
};
use ostrya_core::{ContentHasher, FileHeader};
use ostrya_rt::block_on;

fn repo_path(mode_dir: &str) -> PathBuf {
    fixture_repo(mode_dir)
}

fn csum(hex: &str) -> Checksum {
    Checksum::from_hex(hex).unwrap()
}

/// Read a file object's whole payload through its streaming reader.
async fn read_payload(file: &ostrya::FileObject) -> Vec<u8> {
    let mut reader = file.reader().await.expect("open reader");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await.expect("read payload");
    buf
}

/// Recompute a file object's content-object checksum from its reconstructed
/// header and streamed payload; this must equal the object name, proving the
/// port reads back exactly what the tool wrote.
async fn recomputed_checksum(file: &ostrya::FileObject) -> Checksum {
    match &file.kind {
        FileKind::Regular { .. } => {
            let header = FileHeader {
                uid: file.uid,
                gid: file.gid,
                mode: file.mode,
                symlink_target: String::new(),
                xattrs: file.xattrs.clone(),
            };
            let mut hasher = ContentHasher::new(&header).unwrap();
            hasher.update(&read_payload(file).await);
            hasher.finish()
        }
        FileKind::Symlink { target } => {
            let header = FileHeader {
                uid: file.uid,
                gid: file.gid,
                mode: file.mode,
                symlink_target: target.clone(),
                xattrs: file.xattrs.clone(),
            };
            ContentHasher::new(&header).unwrap().finish()
        }
    }
}

#[test]
fn resolves_and_lists_refs() {
    for mode_dir in ["archive", "bare-user"] {
        block_on(async {
            let repo = Repo::open(&repo_path(mode_dir)).await.expect("open repo");

            assert_eq!(
                repo.resolve_rev("test/main", false).await.unwrap(),
                Some(csum(COMMIT)),
                "{mode_dir}: resolve test/main"
            );
            // A bare commit checksum resolves to itself.
            assert_eq!(
                repo.resolve_rev(COMMIT, false).await.unwrap(),
                Some(csum(COMMIT))
            );
            // Unknown refs honor allow_noent.
            assert_eq!(repo.resolve_rev("no/such", true).await.unwrap(), None);
            assert!(repo.resolve_rev("no/such", false).await.is_err());

            let refs = repo.list_refs(None).await.unwrap();
            assert_eq!(refs, vec![("test/main".to_owned(), csum(COMMIT))]);
            // Prefix filtering keeps the nested ref.
            assert_eq!(repo.list_refs(Some("test")).await.unwrap(), refs);
            assert!(repo.list_refs(Some("other")).await.unwrap().is_empty());
        });
    }
}

#[test]
fn loads_commit_dirtree_and_dirmeta() {
    for mode_dir in ["archive", "bare-user"] {
        block_on(async {
            let repo = Repo::open(&repo_path(mode_dir)).await.expect("open repo");

            let (commit, state) = repo.load_commit(&csum(COMMIT)).await.unwrap();
            assert_eq!(state, CommitState::Normal);
            assert_eq!(commit.root_dirtree, csum(ROOT_DIRTREE));
            assert_eq!(commit.root_dirmeta, csum(ROOT_DIRMETA));
            assert_eq!(commit.timestamp, 1_700_000_000);
            assert_eq!(commit.content_checksum(), csum(CONTENT));

            let root = repo.load_dirtree(&csum(ROOT_DIRTREE)).await.unwrap();
            let files: Vec<&str> = root.files.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(files, ["empty.txt", "hello.txt", "link"]);
            let dirs: Vec<&str> = root.dirs.iter().map(|(n, _, _)| n.as_str()).collect();
            assert_eq!(dirs, ["subdir"]);

            let meta = repo.load_dirmeta(&csum(ROOT_DIRMETA)).await.unwrap();
            // `ostree ls` reports the root as d00755 owned 0:0.
            assert_eq!((meta.uid, meta.gid, meta.mode), (0, 0, 0o40755));

            assert!(
                repo.has_object(ObjectType::Commit, &csum(COMMIT))
                    .await
                    .unwrap()
            );
            assert!(
                !repo
                    .has_object(ObjectType::Commit, &csum(&"00".repeat(32)))
                    .await
                    .unwrap()
            );

            // A missing object is reported as ObjectNotFound, not a bare I/O error.
            let err = repo
                .load_dirtree(&csum(&"11".repeat(32)))
                .await
                .unwrap_err();
            assert!(matches!(err, ostrya::Error::ObjectNotFound { .. }));

            // load_variant yields the dynamic tree for a metadata object.
            let value = repo
                .load_variant(ObjectType::DirMeta, &csum(ROOT_DIRMETA))
                .await
                .unwrap();
            assert!(value.as_tuple().is_some());
        });
    }
}

#[test]
fn traverses_the_commit_tree() {
    for mode_dir in ["archive", "bare-user"] {
        block_on(async {
            let repo = Repo::open(&repo_path(mode_dir)).await.expect("open repo");
            let (root, commit) = repo.read_commit("test/main").await.unwrap();
            assert_eq!(commit, csum(COMMIT));
            assert_eq!(root.dirtree_checksum(), &csum(ROOT_DIRTREE));

            // read_dir yields files first, then directories, each name-sorted.
            let entries = root.read_dir().await.unwrap();
            let names: Vec<&str> = entries
                .iter()
                .map(|e| match e {
                    TreeEntry::File { name, .. } => name.as_str(),
                    TreeEntry::Dir { name, .. } => name.as_str(),
                })
                .collect();
            assert_eq!(names, ["empty.txt", "hello.txt", "link", "subdir"]);

            // Descend into the subdirectory.
            let TreeEntry::Dir { tree: subdir, .. } = &entries[3] else {
                panic!("subdir entry is not a directory");
            };
            assert_eq!(subdir.dirtree_checksum(), &csum(SUBDIR_DIRTREE));
            let nested = subdir.read_dir().await.unwrap();
            assert_eq!(nested.len(), 1);
            assert!(matches!(&nested[0], TreeEntry::File { name, checksum }
                if name == "nested.txt" && *checksum == csum(NESTED_TXT)));

            // lookup resolves files, nested files, directories, and symlinks.
            assert!(matches!(
                root.lookup(Path::new("hello.txt")).await.unwrap(),
                Some(TreeEntry::File { checksum, .. }) if checksum == csum(HELLO_TXT)
            ));
            assert!(matches!(
                root.lookup(Path::new("subdir/nested.txt")).await.unwrap(),
                Some(TreeEntry::File { checksum, .. }) if checksum == csum(NESTED_TXT)
            ));
            assert!(matches!(
                root.lookup(Path::new("subdir")).await.unwrap(),
                Some(TreeEntry::Dir { .. })
            ));
            assert!(matches!(
                root.lookup(Path::new("link")).await.unwrap(),
                Some(TreeEntry::File { checksum, .. }) if checksum == csum(LINK)
            ));
            // Missing entry, and descending through a file, both resolve to None.
            assert!(root.lookup(Path::new("missing")).await.unwrap().is_none());
            assert!(
                root.lookup(Path::new("hello.txt/x"))
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }
}

#[test]
fn reads_archive_file_content() {
    block_on(async {
        let repo = Repo::open(&repo_path("archive")).await.expect("open repo");
        assert_eq!(repo.mode(), RepoMode::Archive);

        let hello = repo.load_file(&csum(HELLO_TXT)).await.unwrap();
        assert_eq!(hello.mode, 0o100644);
        assert_eq!(hello.kind, FileKind::Regular { size: 13 });
        assert!(hello.xattrs.is_empty());
        assert_eq!(read_payload(&hello).await, b"hello ostree\n");
        assert_eq!(recomputed_checksum(&hello).await, csum(HELLO_TXT));

        let empty = repo.load_file(&csum(EMPTY_TXT)).await.unwrap();
        assert_eq!(empty.kind, FileKind::Regular { size: 0 });
        assert_eq!(read_payload(&empty).await, b"");
        assert_eq!(recomputed_checksum(&empty).await, csum(EMPTY_TXT));

        let nested = repo.load_file(&csum(NESTED_TXT)).await.unwrap();
        assert_eq!(read_payload(&nested).await, b"nested\n");

        let link = repo.load_file(&csum(LINK)).await.unwrap();
        assert_eq!(link.mode, 0o120777);
        assert_eq!(
            link.kind,
            FileKind::Symlink {
                target: "hello.txt".to_owned()
            }
        );
        assert!(link.is_symlink());
        // A symlink has no payload.
        assert_eq!(read_payload(&link).await, b"");
        assert_eq!(recomputed_checksum(&link).await, csum(LINK));
    });
}

#[test]
fn reads_bare_user_file_content() {
    // The bare-user fixture tarball carries the `user.ostreemeta` xattr these
    // objects rely on, so this cross-check always runs.
    block_on(async {
        let repo = Repo::open(&repo_path("bare-user"))
            .await
            .expect("open repo");
        assert_eq!(repo.mode(), RepoMode::BareUser);

        let hello = repo.load_file(&csum(HELLO_TXT)).await.unwrap();
        assert_eq!(hello.mode, 0o100644);
        assert_eq!(hello.kind, FileKind::Regular { size: 13 });
        assert_eq!(read_payload(&hello).await, b"hello ostree\n");
        assert_eq!(recomputed_checksum(&hello).await, csum(HELLO_TXT));

        let link = repo.load_file(&csum(LINK)).await.unwrap();
        assert_eq!(
            link.kind,
            FileKind::Symlink {
                target: "hello.txt".to_owned()
            }
        );
        assert_eq!(recomputed_checksum(&link).await, csum(LINK));

        let empty = repo.load_file(&csum(EMPTY_TXT)).await.unwrap();
        assert_eq!(empty.kind, FileKind::Regular { size: 0 });
        assert_eq!(read_payload(&empty).await, b"");
    });
}

/// Place a file of `size` bytes at the loose path of a commit object under
/// `repo_dir`, and return that path.
///
/// `set_len` is `ftruncate`, so the file reads back as zeros and the test writes
/// no payload. A size at the metadata cap therefore costs no disk space.
fn place_sparse_object(repo_dir: &Path, mode: RepoMode, checksum: &Checksum, size: u64) -> PathBuf {
    let path = repo_dir
        .join("objects")
        .join(loose_path(checksum, ObjectType::Commit, mode));
    std::fs::create_dir_all(
        path.parent()
            .expect("the loose path has a prefix directory"),
    )
    .expect("create the object prefix directory");
    let file = std::fs::File::create(&path).expect("create the loose object");
    file.set_len(size).expect("size the loose object");
    path
}

/// The streaming reader hands over exactly the bytes the buffered loader
/// returns, whatever chunk size the caller reads in.
#[test]
fn streams_a_metadata_object_in_chunks() {
    for mode_dir in ["archive", "bare-user"] {
        block_on(async {
            let repo = Repo::open(&repo_path(mode_dir)).await.expect("open repo");

            let buffered = repo
                .load_object_bytes(ObjectType::Commit, &csum(COMMIT))
                .await
                .expect("load the commit bytes");
            assert!(
                !buffered.is_empty(),
                "{mode_dir}: the commit object carries bytes"
            );

            let mut reader = repo
                .metadata_reader(ObjectType::Commit, &csum(COMMIT))
                .await
                .expect("open the metadata reader");
            // An empty buffer takes no bytes and disturbs no position: the
            // stream below still hands over the whole object.
            assert_eq!(
                reader
                    .read(&mut [])
                    .await
                    .expect("read into an empty buffer"),
                0,
                "{mode_dir}: an empty buffer takes nothing"
            );

            // A chunk far smaller than the object, so the assertion covers many
            // reads and a partial final read.
            let mut chunk = [0u8; 7];
            let mut streamed = Vec::new();
            loop {
                let n = reader.read(&mut chunk).await.expect("read a chunk");
                if n == 0 {
                    break;
                }
                assert!(
                    n <= chunk.len(),
                    "{mode_dir}: a read stays inside the buffer"
                );
                streamed.extend_from_slice(&chunk[..n]);
            }
            assert_eq!(streamed, buffered, "{mode_dir}: streamed commit bytes");

            // A missing object surfaces the refusal the buffered loader gives.
            // `MetadataReader` carries no `Debug`, matching `ContentReader`, so
            // the refusal is taken by a match rather than `unwrap_err`.
            let err = match repo
                .metadata_reader(ObjectType::Commit, &csum(&"11".repeat(32)))
                .await
            {
                Ok(_) => panic!("{mode_dir}: a missing object opened a reader"),
                Err(e) => e,
            };
            assert!(
                matches!(err, ostrya::Error::ObjectNotFound { .. }),
                "{mode_dir}: a missing object is ObjectNotFound, got {err:?}"
            );
        });
    }
}

/// An object the `fstat` already measures above the cap is refused at the open,
/// with the error the buffered loader raises for the same object.
#[test]
fn metadata_reader_refuses_an_oversized_object_at_the_open() {
    let tmp = TmpDir::new("meta-cap-open");
    block_on(async {
        let repo_dir = tmp.path().join("repo");
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .expect("create repo");
        let key = csum(&"22".repeat(32));
        place_sparse_object(&repo_dir, repo.mode(), &key, MAX_METADATA_SIZE + 1);

        let err = match repo.metadata_reader(ObjectType::Commit, &key).await {
            Ok(_) => panic!("the open accepted an oversized object"),
            Err(e) => e,
        };
        let ostrya::Error::Io(io_err) = &err else {
            panic!("expected an I/O refusal, got {err:?}");
        };
        assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            io_err
                .to_string()
                .contains("object exceeds the metadata size cap"),
            "message: {io_err}"
        );

        // The buffered loader refuses the same object with the same message, so
        // the two paths agree.
        let buffered = repo
            .load_object_bytes(ObjectType::Commit, &key)
            .await
            .expect_err("the buffered loader refuses an oversized object");
        assert_eq!(buffered.to_string(), err.to_string());
    });
}

/// Under the `tokio` backend the reader also speaks the tokio I/O traits.
/// Driving that implementation directly -- `poll_read` over a `ReadBuf` --
/// proves it advances the filled region by exactly the bytes it wrote: a
/// mismatch there would drop or duplicate bytes against the buffered loader.
#[cfg(feature = "tokio")]
#[test]
fn streams_a_metadata_object_through_the_tokio_trait() {
    use ostrya_rt::tokio_io::{AsyncRead, ReadBuf};
    use std::pin::Pin;
    use std::task::Poll;

    block_on(async {
        let repo = Repo::open(&repo_path("archive")).await.expect("open repo");
        let buffered = repo
            .load_object_bytes(ObjectType::Commit, &csum(COMMIT))
            .await
            .expect("load the commit bytes");
        let mut reader = repo
            .metadata_reader(ObjectType::Commit, &csum(COMMIT))
            .await
            .expect("open the metadata reader");

        let mut streamed = Vec::new();
        loop {
            // A chunk far smaller than the object, so the assertion covers many
            // reads and a partial final read.
            let mut raw = [0u8; 7];
            let taken = futures_lite::future::poll_fn(|cx| {
                // A fresh `ReadBuf` on every poll: a `Pending` poll fills
                // nothing, so rebuilding it drops no byte.
                let mut buf = ReadBuf::new(&mut raw);
                match Pin::new(&mut reader).poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.filled().len())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
            .expect("read a chunk through the tokio trait");
            if taken == 0 {
                break;
            }
            streamed.extend_from_slice(&raw[..taken]);
        }
        assert_eq!(streamed, buffered, "tokio-trait streamed commit bytes");
    });
}

/// An object of exactly `MAX_METADATA_SIZE` bytes sits inside the cap. The
/// streaming reader hands over every byte and ends at `Ok(0)`, and the buffered
/// loader takes the same object, so the two paths put the bound on the same
/// byte.
#[test]
fn metadata_reader_reads_an_object_at_exactly_the_cap() {
    let tmp = TmpDir::new("meta-cap-exact");
    block_on(async {
        let repo_dir = tmp.path().join("repo");
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .expect("create repo");
        let key = csum(&"44".repeat(32));
        place_sparse_object(&repo_dir, repo.mode(), &key, MAX_METADATA_SIZE);

        let mut reader = repo
            .metadata_reader(ObjectType::Commit, &key)
            .await
            .expect("an object at the cap opens a reader");
        // A chunk size that does not divide the cap, so the reader ends on a
        // partial read rather than on a boundary.
        let mut chunk = vec![0u8; 1024 * 1024 - 1];
        let mut taken: u64 = 0;
        loop {
            let n = reader
                .read(&mut chunk)
                .await
                .expect("an object at the cap reads through");
            if n == 0 {
                break;
            }
            taken += n as u64;
        }
        assert_eq!(
            taken, MAX_METADATA_SIZE,
            "the reader hands over every byte of an object at the cap"
        );
        // The end of file is stable: the probe at the cap finds no further byte
        // however often it runs.
        for round in 0..3 {
            assert_eq!(
                reader.read(&mut chunk).await.expect("read past the end"),
                0,
                "read {round} past the end of an object at the cap"
            );
        }

        // The buffered loader takes the same object, so neither path refuses at
        // the cap itself.
        let buffered = repo
            .load_object_bytes(ObjectType::Commit, &key)
            .await
            .expect("the buffered loader takes an object at the cap");
        assert_eq!(buffered.len() as u64, MAX_METADATA_SIZE);
    });
}

/// An object that grows past the cap while the reader is open is refused by the
/// running total, and the reader hands over no more than `MAX_METADATA_SIZE`
/// bytes before it refuses.
#[test]
fn metadata_reader_refuses_an_object_that_grows_past_the_cap() {
    let tmp = TmpDir::new("meta-cap-grow");
    block_on(async {
        let repo_dir = tmp.path().join("repo");
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .expect("create repo");
        let key = csum(&"33".repeat(32));
        // One byte under the cap, so the `fstat` at the open passes.
        let path = place_sparse_object(&repo_dir, repo.mode(), &key, MAX_METADATA_SIZE - 1);
        let mut reader = repo
            .metadata_reader(ObjectType::Commit, &key)
            .await
            .expect("open the metadata reader");

        // Grow the object past the cap before the first read, the way a writer
        // racing the reader does.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("reopen the loose object for writing")
            .set_len(MAX_METADATA_SIZE + 1)
            .expect("grow the loose object past the cap");

        // A chunk size that does not divide the cap, so the last read below the
        // cap asks for more bytes than the cap leaves. Without the clamp that
        // read would carry the total past the cap, and the per-read assertion
        // catches it.
        let mut chunk = vec![0u8; 1024 * 1024 - 1];
        let mut taken: u64 = 0;
        let err = loop {
            match reader.read(&mut chunk).await {
                Ok(0) => panic!("the reader reported end of file after {taken} bytes"),
                Ok(n) => {
                    taken += n as u64;
                    assert!(
                        taken <= MAX_METADATA_SIZE,
                        "the reader handed over {taken} bytes, above the cap"
                    );
                }
                Err(e) => break e,
            }
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .contains("object exceeds the metadata size cap"),
            "message: {err}"
        );
        assert_eq!(
            taken, MAX_METADATA_SIZE,
            "the reader stops at the cap, having handed over every byte up to it"
        );

        // The refusal is terminal. A caller that polls again takes the same
        // error, never a clean end of file that would present the object as
        // having ended at the cap.
        for round in 0..3 {
            match reader.read(&mut chunk).await {
                Ok(n) => panic!("read {round} after the refusal returned {n} bytes"),
                Err(again) => {
                    assert_eq!(again.kind(), std::io::ErrorKind::InvalidData);
                    assert!(
                        again
                            .to_string()
                            .contains("object exceeds the metadata size cap"),
                        "message: {again}"
                    );
                }
            }
        }
    });
}

#[test]
fn matches_the_tool_cat_and_ls() {
    // A live comparison against the `ostree` tool, when it is on PATH: what the
    // port reads from the archive fixture must equal what the tool prints. The
    // archive fixture needs no xattrs, so this is self-contained.
    if !ostree_available() {
        eprintln!("skipping tool cross-check: ostree not on PATH");
        return;
    }
    let repo_dir = repo_path("archive");
    let repo_arg = format!("--repo={}", repo_dir.display());

    let cat = |path: &str| -> Vec<u8> {
        let out = std::process::Command::new("ostree")
            .arg(&repo_arg)
            .args(["cat", "test/main", path])
            .output()
            .expect("run ostree cat");
        assert!(out.status.success(), "ostree cat {path} failed");
        out.stdout
    };

    block_on(async {
        let repo = Repo::open(&repo_dir).await.expect("open repo");
        let (root, _) = repo.read_commit("test/main").await.unwrap();

        for path in ["/hello.txt", "/empty.txt", "/subdir/nested.txt"] {
            let entry = root
                .lookup(Path::new(path.trim_start_matches('/')))
                .await
                .unwrap()
                .expect("entry present");
            let TreeEntry::File { checksum, .. } = entry else {
                panic!("{path} is not a file");
            };
            let file = repo.load_file(&checksum).await.unwrap();
            assert_eq!(read_payload(&file).await, cat(path), "content of {path}");
        }

        // The symlink target the tool reports matches the port's.
        let link = repo.load_file(&csum(LINK)).await.unwrap();
        let ls = std::process::Command::new("ostree")
            .arg(&repo_arg)
            .args(["ls", "test/main", "/link"])
            .output()
            .expect("run ostree ls");
        let ls = String::from_utf8_lossy(&ls.stdout);
        assert!(ls.contains("-> hello.txt"), "tool ls: {ls}");
        assert_eq!(
            link.kind,
            FileKind::Symlink {
                target: "hello.txt".to_owned()
            }
        );
    });
}
