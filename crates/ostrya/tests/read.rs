//! Reading-path integration tests against the checked-in tool fixtures.
//!
//! These exercise the Phase 5 gate: read objects, refs, and full trees from a
//! tool-created repository and match the tool's own view. The metadata and
//! traversal assertions are mode-independent (the fixtures share object bytes),
//! so they run for both fixture repositories. The archive `load_file` path is
//! fully self-contained and is the CI gate for file reading. The bare-user
//! `load_file` path depends on the `user.ostreemeta` xattr, which git does not
//! preserve, so its assertions run only when the xattr is present.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use futures_lite::AsyncReadExt;
use ostrya::{Checksum, CommitState, FileKind, ObjectType, Repo, RepoMode, TreeEntry};
use ostrya_core::{ContentHasher, FileHeader};
use ostrya_rt::block_on;

fn repo_path(mode_dir: &str) -> PathBuf {
    fixture_root().join(mode_dir).join("repo")
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
    // git does not preserve the `user.ostreemeta` xattr the bare-user objects
    // rely on, so this cross-check runs only when the xattr survived (e.g. right
    // after generate.sh). Otherwise it is skipped.
    let hello_obj = repo_path("bare-user")
        .join("objects")
        .join(&HELLO_TXT[..2])
        .join(format!("{}.file", &HELLO_TXT[2..]));
    if !xattr_present(&hello_obj) {
        eprintln!("skipping bare-user load_file: user.ostreemeta xattr not present");
        return;
    }

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

/// Whether the object carries a `user.ostreemeta` xattr, growing the buffer as
/// needed.
fn xattr_present(path: &Path) -> bool {
    let mut buf = vec![0u8; 256];
    loop {
        match rustix::fs::getxattr(path, "user.ostreemeta", &mut buf[..]) {
            Ok(_) => return true,
            Err(rustix::io::Errno::RANGE) => buf.resize(buf.len() * 2, 0),
            Err(_) => return false,
        }
    }
}
