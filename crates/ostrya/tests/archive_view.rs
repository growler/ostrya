//! `ArchiveView` over a repository of each mode: the built `config`, the
//! stored files, the `.filez` objects built on request, and the paths it
//! refuses or does not find.

mod common;

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use async_compression::futures::bufread::DeflateDecoder;
use common::TmpDir;
use common::modes::{
    WRITABLE, build_tree, current_owner, file_objects, object_path, repo_of, write_split_object,
};
use futures_lite::AsyncReadExt;
use futures_lite::io::{BufReader, Cursor};
use ostrya::{
    ArchiveAnswer, ArchiveHead, ArchiveView, Checksum, CreateOptions, FileKind, ObjectType, Repo,
    RepoMode, SummaryOptions, loose_path,
};
use ostrya_core::{ContentHasher, DeflateReader, FileHeader, Xattrs};
use ostrya_rt::block_on;

const BASE_CONFIG: &[u8] = b"[core]\nrepo_version=1\nmode=archive-z2\n";

async fn read_all(answer: ArchiveAnswer) -> (Option<u64>, Vec<u8>) {
    match answer {
        ArchiveAnswer::Bytes(bytes) => (Some(bytes.len() as u64), bytes),
        ArchiveAnswer::Stream { len, mut body } => {
            let mut out = Vec::new();
            body.read_to_end(&mut out).await.unwrap();
            (len, out)
        }
        other => panic!("not served: {other:?}"),
    }
}

async fn get(view: &ArchiveView, path: &str) -> (Option<u64>, Vec<u8>) {
    read_all(view.get(path).await.unwrap()).await
}

/// Split a `.filez` into its header, its declared size, and its inflated
/// payload.
async fn parse_filez(bytes: &[u8]) -> (FileHeader, u64, Vec<u8>) {
    let header_len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(&bytes[4..8], &[0; 4]);
    let (header, size) = FileHeader::parse_archive(&bytes[8..8 + header_len]).unwrap();
    let compressed = &bytes[8 + header_len..];
    let mut payload = Vec::new();
    if !header.is_symlink() {
        DeflateDecoder::new(BufReader::new(Cursor::new(compressed.to_vec())))
            .read_to_end(&mut payload)
            .await
            .unwrap();
    } else {
        assert!(compressed.is_empty(), "a symlink carries no payload");
    }
    (header, size, payload)
}

/// The served `config` is the archive one in every mode, and it carries the
/// collection id and `indexed-deltas` of the repository once they are set. A
/// change to the repository `config` shows in the next answer.
#[test]
fn the_config_is_built_in_every_mode() {
    let tmp = TmpDir::new("view-config");
    block_on(async {
        for mode in WRITABLE {
            let path = tmp.path().join(mode.as_mode_str());
            let repo = Repo::create(&path, CreateOptions::new(mode)).await.unwrap();
            let view = ArchiveView::new(repo.clone());
            assert_eq!(get(&view, "config").await.1, BASE_CONFIG, "{mode:?}");

            let guard = repo.begin_update().await.unwrap();
            let mut keyfile = guard.read_config().await.unwrap().keyfile().clone();
            keyfile.set_value("core", "indexed-deltas", "true").unwrap();
            keyfile
                .set_value("core", "collection-id", "org.example.View")
                .unwrap();
            keyfile
                .set_value("remote \"o\"", "url", "http://x/")
                .unwrap();
            guard.write_config(&keyfile).await.unwrap();
            guard.finish().await.unwrap();
            assert_eq!(
                get(&view, "config").await.1,
                [
                    BASE_CONFIG,
                    b"collection-id=org.example.View\nindexed-deltas=true\n"
                ]
                .concat(),
                "{mode:?}"
            );

            // An edit in place keeps the inode and changes the size.
            let text = fs::read_to_string(path.join("config")).unwrap();
            let edited = text.replace("indexed-deltas=true", "indexed-deltas=false");
            fs::write(path.join("config"), edited).unwrap();
            assert_eq!(
                get(&view, "config").await.1,
                [
                    BASE_CONFIG,
                    b"collection-id=org.example.View\nindexed-deltas=false\n"
                ]
                .concat(),
                "{mode:?}"
            );
        }
    });
}

/// A `config` past the 1 MiB cap is refused, by the open of a handle and by
/// the read of the view.
#[test]
fn a_config_past_the_cap_is_refused() {
    let tmp = TmpDir::new("view-config-cap");
    block_on(async {
        let path = tmp.path().join("repo");
        let repo = Repo::create(&path, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let view = ArchiveView::new(repo);
        let text = fs::read(path.join("config")).unwrap();
        let cap = 1024 * 1024;
        let mut padded = text.clone();
        padded.push(b'#');
        padded.resize(cap - 1, b'x');
        padded.push(b'\n');
        fs::write(path.join("config"), &padded).unwrap();
        Repo::open(&path).await.unwrap();
        assert_eq!(get(&view, "config").await.1, BASE_CONFIG);

        padded.insert(text.len(), b'\n');
        fs::write(path.join("config"), &padded).unwrap();
        let err = Repo::open(&path).await.unwrap_err();
        assert!(
            matches!(&err, ostrya::Error::InvalidFormat(m) if m.contains("1048576")),
            "{err:?}"
        );
        let err = view.get("config").await.unwrap_err();
        assert!(matches!(err, ostrya::Error::InvalidFormat(_)), "{err:?}");
    });
}

/// A write of a `config` over the cap is refused and leaves the file as it
/// was, through the repository and through the update guard.
#[test]
fn a_config_write_past_the_cap_is_refused() {
    let tmp = TmpDir::new("view-config-write-cap");
    block_on(async {
        let path = tmp.path().join("repo");
        let repo = Repo::create(&path, CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let before = fs::read(path.join("config")).unwrap();
        let mut keyfile = repo.config().keyfile().clone();
        keyfile
            .set_value("ex-test", "pad", &"x".repeat(1024 * 1024))
            .unwrap();
        let err = repo.write_config(&keyfile).await.unwrap_err();
        assert!(matches!(err, ostrya::Error::InvalidFormat(_)), "{err:?}");
        let guard = repo.begin_update().await.unwrap();
        let err = guard.write_config(&keyfile).await.unwrap_err();
        assert!(matches!(err, ostrya::Error::InvalidFormat(_)), "{err:?}");
        guard.finish().await.unwrap();
        assert_eq!(fs::read(path.join("config")).unwrap(), before);
        Repo::open(&path).await.unwrap();
    });
}

/// Refs, metadata objects, the summary, extensions, and in `archive` the
/// stored `.filez`, come out byte for byte, with the length of the file.
#[test]
fn stored_files_are_served_as_stored() {
    let tmp = TmpDir::new("view-stored");
    let src = build_tree(tmp.path());
    block_on(async {
        for mode in WRITABLE {
            let (path, repo, commit) = repo_of(tmp.path(), mode, &src).await;
            repo.regenerate_summary(&SummaryOptions {
                last_modified: Some(1_700_000_000),
                ..SummaryOptions::default()
            })
            .await
            .unwrap();
            fs::create_dir_all(path.join("extensions/demo")).unwrap();
            fs::write(path.join("extensions/demo/x"), b"extension\n").unwrap();
            let view = ArchiveView::new(repo.clone());

            let mut paths = vec![
                "summary".to_owned(),
                "refs/heads/main".to_owned(),
                "extensions/demo/x".to_owned(),
            ];
            for name in repo.traverse_commit(&commit, 0).await.unwrap() {
                if name.ty != ObjectType::File {
                    paths.push(object_path(name.ty, &name.checksum));
                } else if mode == RepoMode::Archive {
                    paths.push(object_path(ObjectType::File, &name.checksum));
                }
            }
            for served in paths {
                let stored = fs::read(path.join(&served)).unwrap();
                let (len, bytes) = get(&view, &served).await;
                assert_eq!(len, Some(stored.len() as u64), "{mode:?} {served}");
                assert_eq!(bytes, stored, "{mode:?} {served}");
            }
        }
    });
}

/// A `.filez` built on request has no known length, carries the header the
/// repository content reader gives, and inflates to the payload. Its bytes
/// are those of the stored `.filez` of an `archive` repository with the same
/// objects, and a symlink object is its header alone.
#[test]
fn a_built_filez_matches_the_archive_object() {
    let tmp = TmpDir::new("view-built");
    let src = build_tree(tmp.path());
    block_on(async {
        let (archive_path, _, archive_commit) = repo_of(tmp.path(), RepoMode::Archive, &src).await;
        let mut compared = 0;
        for mode in &WRITABLE[1..] {
            let (_, repo, commit) = repo_of(tmp.path(), *mode, &src).await;
            let view = ArchiveView::new(repo.clone());
            let mut symlinks = 0;
            for checksum in file_objects(&repo, &commit).await {
                let answer = view.get(&object_path(ObjectType::File, &checksum)).await;
                let (len, bytes) = read_all(answer.unwrap()).await;
                assert_eq!(len, None);
                let (header, size, payload) = parse_filez(&bytes).await;
                let file = repo.load_file(&checksum).await.unwrap();
                assert_eq!(header, file.header(), "{mode:?}");
                let mut expected = Vec::new();
                file.reader()
                    .await
                    .unwrap()
                    .read_to_end(&mut expected)
                    .await
                    .unwrap();
                assert_eq!(payload, expected);
                assert_eq!(size, expected.len() as u64);
                let mut hasher = ContentHasher::new(&header).unwrap();
                hasher.update(&payload);
                assert_eq!(hasher.finish(), checksum);
                if let FileKind::Symlink { target } = &file.kind {
                    symlinks += 1;
                    assert_eq!(target, "hello");
                }
                // The objects of a mode that keeps the owner are those of the
                // archive repository.
                if commit == archive_commit {
                    compared += 1;
                    let stored =
                        fs::read(archive_path.join(object_path(ObjectType::File, &checksum)))
                            .unwrap();
                    assert_eq!(bytes, stored, "{mode:?}");
                }
            }
            assert_eq!(symlinks, 1);
        }
        // `bare`, `bare-user`, and `bare-user-shared` keep the owner, so their
        // five objects each are compared.
        assert_eq!(compared, 15);
    });
}

/// `[archive] zlib-level` of the repository `config` sets the level of the
/// next `.filez` built, with no new view.
#[test]
fn the_zlib_level_of_the_config_applies_to_the_next_filez() {
    let tmp = TmpDir::new("view-level");
    let src = build_tree(tmp.path());
    block_on(async {
        let (path, repo, commit) = repo_of(tmp.path(), RepoMode::BareUser, &src).await;
        let view = ArchiveView::new(repo.clone());
        let mut big = None;
        for checksum in file_objects(&repo, &commit).await {
            if repo.load_file(&checksum).await.unwrap().kind
                == (FileKind::Regular { size: 300_000 })
            {
                big = Some(checksum);
            }
        }
        let big = big.unwrap();
        let filez = object_path(ObjectType::File, &big);
        let payload = fs::read(tmp.path().join("src/big")).unwrap();
        let deflated = |level: u8| {
            let payload = payload.clone();
            async move {
                let mut out = Vec::new();
                DeflateReader::new(Cursor::new(payload), level)
                    .read_to_end(&mut out)
                    .await
                    .unwrap();
                out
            }
        };
        let header_len =
            |bytes: &[u8]| 8 + u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;

        let bytes = get(&view, &filez).await.1;
        assert_eq!(bytes[header_len(&bytes)..], deflated(6).await);
        let mut text = fs::read_to_string(path.join("config")).unwrap();
        text.push_str("[archive]\nzlib-level=1\n");
        fs::write(path.join("config"), text).unwrap();
        let bytes = get(&view, &filez).await.1;
        assert_eq!(bytes[header_len(&bytes)..], deflated(1).await);
        assert_ne!(deflated(1).await, deflated(6).await);
    });
}

/// In `bare-split-xattrs` the header carries the owner and the mode of the
/// inode and the extended attributes of the split object. The config is the
/// archive one.
#[test]
fn a_built_filez_carries_the_split_xattrs() {
    let tmp = TmpDir::new("view-split");
    block_on(async {
        let root = tmp.path().join("repo");
        let repo = Repo::create(&root, CreateOptions::new(RepoMode::BareSplitXattrs))
            .await
            .unwrap();
        let demo = Xattrs::new([(b"user.demo\0".to_vec(), b"bar".to_vec())]).unwrap();
        let regular = write_split_object(&root, 0o100644, "", &demo, b"split payload\n");
        let link = write_split_object(&root, 0o120777, "elsewhere", &Xattrs::empty(), b"");
        let view = ArchiveView::new(repo);
        assert_eq!(get(&view, "config").await.1, BASE_CONFIG);

        let (uid, gid) = current_owner(&root);
        let bytes = get(&view, &object_path(ObjectType::File, &regular)).await.1;
        let (header, size, payload) = parse_filez(&bytes).await;
        assert_eq!((header.uid, header.gid, header.mode), (uid, gid, 0o100644));
        assert_eq!(header.xattrs, demo);
        assert_eq!(
            (size, payload.as_slice()),
            (14, b"split payload\n".as_slice())
        );

        let bytes = get(&view, &object_path(ObjectType::File, &link)).await.1;
        let (header, size, _) = parse_filez(&bytes).await;
        assert_eq!(header.symlink_target, "elsewhere");
        assert_eq!(size, 0);
        for id in [regular, link] {
            assert_eq!(
                view.head(&object_path(ObjectType::File, &id))
                    .await
                    .unwrap(),
                ArchiveHead::Found { len: None }
            );
        }

        // A `HEAD` reads no xattr: a link whose bytes do not parse fails the
        // `GET` and leaves the `HEAD` found.
        let other = write_split_object(
            &root,
            0o100644,
            "",
            &Xattrs::new([(b"user.other\0".to_vec(), b"x".to_vec())]).unwrap(),
            b"other\n",
        );
        let other_link = root.join("objects").join(loose_path(
            &other,
            ObjectType::FileXattrsLink,
            RepoMode::BareSplitXattrs,
        ));
        fs::remove_file(&other_link).unwrap();
        fs::write(&other_link, b"\xff").unwrap();
        let other_filez = object_path(ObjectType::File, &other);
        assert!(view.get(&other_filez).await.is_err());
        assert_eq!(
            view.head(&other_filez).await.unwrap(),
            ArchiveHead::Found { len: None }
        );

        // A symlink at the link object is refused, and the payload of the
        // file it names is not served.
        let link_path = root.join("objects").join(loose_path(
            &regular,
            ObjectType::FileXattrsLink,
            RepoMode::BareSplitXattrs,
        ));
        fs::remove_file(&link_path).unwrap();
        symlink("/etc/passwd", &link_path).unwrap();
        let filez = object_path(ObjectType::File, &regular);
        assert_both(&view, &filez, true).await;
    });
}

fn assert_answer(answer: ArchiveAnswer, refused: bool, path: &str) {
    match (answer, refused) {
        (ArchiveAnswer::Refused, true) | (ArchiveAnswer::NotFound, false) => {}
        (other, _) => panic!(
            "{path}: expected {}, got {other:?}",
            if refused { "Refused" } else { "NotFound" }
        ),
    }
}

/// [`assert_answer`] for the `GET` and the `HEAD` of `path`.
async fn assert_both(view: &ArchiveView, path: &str, refused: bool) {
    assert_answer(view.get(path).await.unwrap(), refused, path);
    let expected = if refused {
        ArchiveHead::Refused
    } else {
        ArchiveHead::NotFound
    };
    assert_eq!(view.head(path).await.unwrap(), expected, "HEAD {path}");
}

/// The paths the view refuses and the paths it does not find, each by its own
/// answer.
#[test]
fn private_and_absent_paths_are_refused_or_not_found() {
    let tmp = TmpDir::new("view-refuse");
    let src = build_tree(tmp.path());
    block_on(async {
        for mode in WRITABLE {
            let (path, repo, commit) = repo_of(tmp.path(), mode, &src).await;
            repo.set_ref_alias_immediate("alias", "main").await.unwrap();
            let heads = path.join("refs/heads");
            symlink("alias", heads.join("alias2")).unwrap();
            symlink("../../summary", heads.join("out")).unwrap();
            symlink("/etc/passwd", heads.join("abs")).unwrap();
            fs::create_dir_all(path.join("refs/remotes/o")).unwrap();
            fs::write(path.join("refs/remotes/o/x"), b"x\n").unwrap();
            symlink("../remotes/o", heads.join("dir")).unwrap();
            symlink("main/", heads.join("slash")).unwrap();
            fs::create_dir_all(path.join("extensions")).unwrap();
            fs::write(path.join("extensions/real"), b"real\n").unwrap();
            symlink("real", path.join("extensions/inside")).unwrap();
            symlink("/etc/passwd", path.join("extensions/outside")).unwrap();
            rustix::fs::mknodat(
                rustix::fs::CWD,
                heads.join("fifo"),
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::from_raw_mode(0o644),
                0,
            )
            .unwrap();
            let view = ArchiveView::new(repo.clone());

            // A ref alias inside `refs/` serves the ref it names.
            let main = fs::read(heads.join("main")).unwrap();
            assert_eq!(get(&view, "refs/heads/alias").await.1, main);
            assert_eq!(
                view.head("refs/heads/alias").await.unwrap(),
                ArchiveHead::Found {
                    len: Some(main.len() as u64)
                }
            );
            let file = file_objects(&repo, &commit).await[0];
            let file_path = format!(
                "objects/{}",
                loose_path(&file, ObjectType::File, RepoMode::Bare)
            );
            let refused = [
                ".lock",
                ".update.lock",
                "tmp/x",
                "state/x",
                "a/../config",
                "refs/heads/alias2",
                "refs/heads/out",
                "refs/heads/abs",
                "refs/heads/dir/x",
                "refs/heads/slash",
                "extensions/inside",
                "extensions/outside",
                "refs/heads/main/a//b",
                "refs/heads/main/",
                "/refs/heads/main",
                "refs/heads/./main",
            ];
            let long = "x".repeat(300);
            let long_ref = format!("refs/heads/{long}");
            let long_dir = format!("refs/{long}/x");
            let long_extension = format!("extensions/{long}");
            // Deep paths: an absent directory, and a file at an inner
            // component.
            let deep_absent = format!("refs/heads/{}x", "a/".repeat(10_000));
            let deep_under_file = format!("refs/heads/main/{}x", "a/".repeat(10_000));
            let mut not_found = vec![
                "refs/heads/absent",
                "refs/heads/fifo",
                "refs/heads",
                "nothing",
                file_path.as_str(),
                long_ref.as_str(),
                long_dir.as_str(),
                long_extension.as_str(),
                deep_absent.as_str(),
                deep_under_file.as_str(),
            ];
            if mode != RepoMode::Archive {
                not_found.push("deltas/ab/cd/superblock");
                not_found.push("delta-indexes/ab.index");
            }
            for path in refused {
                assert_both(&view, path, true).await;
            }
            for path in not_found {
                assert_both(&view, path, false).await;
            }
            for ty in [ObjectType::Commit, ObjectType::File] {
                let absent = object_path(ty, &Checksum::sha256(b"absent"));
                assert_both(&view, &absent, false).await;
            }
        }
    });
}

/// Move the fan-out directory of `checksum` aside and put a symlink to it in
/// its place.
fn symlink_fanout(repo: &Path, checksum: &Checksum) -> String {
    let fanout = &checksum.to_hex()[..2];
    let objects = repo.join("objects");
    fs::rename(objects.join(fanout), repo.join("moved")).unwrap();
    symlink("../moved", objects.join(fanout)).unwrap();
    fanout.to_owned()
}

/// A symlink at the fan-out directory is refused for a stored object and for
/// a `.filez` built on request.
#[test]
fn a_symlinked_fanout_is_refused() {
    let tmp = TmpDir::new("view-fanout");
    let src = build_tree(tmp.path());
    block_on(async {
        let (path, repo, commit) = repo_of(tmp.path(), RepoMode::BareUser, &src).await;
        symlink_fanout(&path, &commit);
        let view = ArchiveView::new(repo);
        let commit_path = object_path(ObjectType::Commit, &commit);
        assert_both(&view, &commit_path, true).await;

        let tmp2 = TmpDir::new("view-fanout-built");
        let (path, repo, commit) = repo_of(tmp2.path(), RepoMode::BareUser, &src).await;
        let file = file_objects(&repo, &commit).await[0];
        let fanout = symlink_fanout(&path, &file);
        let view = ArchiveView::new(repo.clone());
        let filez = object_path(ObjectType::File, &file);
        assert_both(&view, &filez, true).await;
        assert!(filez.starts_with(&format!("objects/{fanout}/")));
    });
}

/// A symlink at the path of a `bare-user` object is refused, and none of the
/// bytes it leads to are served.
#[test]
fn a_symlink_at_a_bare_user_object_is_refused() {
    let tmp = TmpDir::new("view-bare-user-link");
    let src = build_tree(tmp.path());
    block_on(async {
        let (path, repo, commit) = repo_of(tmp.path(), RepoMode::BareUser, &src).await;
        let view = ArchiveView::new(repo.clone());
        for file in file_objects(&repo, &commit).await {
            let stored =
                path.join("objects")
                    .join(loose_path(&file, ObjectType::File, RepoMode::BareUser));
            let aside = path.join(format!("aside-{}", file.to_hex()));
            fs::rename(&stored, &aside).unwrap();
            symlink(&aside, &stored).unwrap();
            let filez = object_path(ObjectType::File, &file);
            assert_both(&view, &filez, true).await;
        }
    });
}
