//! Integration tests for `ArchiveView` over a repository of each mode.
//!
//! The tests cover the built `config` and the stored files. They also cover
//! the `.filez` objects that the view builds on request, the composefs image
//! of a commit, and the paths that the view refuses or does not find.

mod common;

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use async_compression::futures::bufread::DeflateDecoder;
use common::modes::{
    WRITABLE, build_tree, current_owner, file_objects, object_path, repo_of, write_split_object,
};
use common::{TmpDir, anyone, repo_access};
use futures_lite::AsyncReadExt;
use futures_lite::io::{BufReader, Cursor};
use ostrya::access::ReadAccess;
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
    read_all(view.get(path, &anyone()).await.unwrap()).await
}

/// Splits a `.filez` into its header, its declared size, and its inflated
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

/// In every mode, the view serves the `config` of an `archive` repository.
/// After the repository sets the collection id and `indexed-deltas`, the served
/// `config` carries them. A change to the repository `config` shows in the next
/// answer.
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

/// The open of a handle and the read of the view each refuse a `config` larger
/// than the 1 MiB cap.
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
        let err = view.get("config", &anyone()).await.unwrap_err();
        assert!(matches!(err, ostrya::Error::InvalidFormat(_)), "{err:?}");
    });
}

/// The repository and the update guard each refuse a write of a `config` larger
/// than the cap. The file stays unchanged.
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

/// The view serves refs, metadata objects, the summary, and extensions byte for
/// byte, with the length of the file. In `archive` mode, the view serves the
/// stored `.filez` the same way.
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

/// A `.filez` that the view builds on request has no known length. It carries
/// the header from the content reader of the repository and inflates to the
/// payload. Its bytes are the bytes of the stored `.filez` of an `archive`
/// repository with the same objects. The `.filez` of a symlink object holds
/// only its header.
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
                let answer = view
                    .get(&object_path(ObjectType::File, &checksum), &anyone())
                    .await;
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
                // In a mode that keeps the owner, the objects are identical to
                // the objects of the archive repository.
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
        // `bare`, `bare-user`, and `bare-user-shared` keep the owner, so the
        // test compares the five objects of each of these modes.
        assert_eq!(compared, 15);
    });
}

/// The key `[archive] zlib-level` of the repository `config` sets the level of
/// the next `.filez` that the view builds. The same view applies the new level.
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

/// In `bare-split-xattrs` mode, the header carries the owner and the mode of
/// the inode and the extended attributes of the split object. The served
/// `config` is the `config` of an `archive` repository.
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
                view.head(&object_path(ObjectType::File, &id), &anyone())
                    .await
                    .unwrap(),
                ArchiveHead::Found { len: None }
            );
        }

        // A `HEAD` reads no xattr. A link with bytes that do not parse fails
        // the `GET`, and the `HEAD` still answers found.
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
        assert!(view.get(&other_filez, &anyone()).await.is_err());
        assert_eq!(
            view.head(&other_filez, &anyone()).await.unwrap(),
            ArchiveHead::Found { len: None }
        );

        // The view refuses a symlink at the link object. It does not serve
        // the payload of the file that the symlink names.
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

/// Checks the answers to the `GET` and the `HEAD` of `path`, as
/// [`assert_answer`] does.
async fn assert_both(view: &ArchiveView, path: &str, refused: bool) {
    assert_answer(view.get(path, &anyone()).await.unwrap(), refused, path);
    let expected = if refused {
        ArchiveHead::Refused
    } else {
        ArchiveHead::NotFound
    };
    assert_eq!(
        view.head(path, &anyone()).await.unwrap(),
        expected,
        "HEAD {path}"
    );
}

/// The view answers `Refused` for each path that it refuses and `NotFound` for
/// each path that it does not find.
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
                view.head("refs/heads/alias", &anyone()).await.unwrap(),
                ArchiveHead::Found {
                    len: Some(main.len() as u64)
                }
            );
            let file = file_objects(&repo, &commit).await[0];
            let file_path = format!(
                "objects/{}",
                loose_path(&file, ObjectType::File, RepoMode::Bare)
            );
            let long = "x".repeat(300);
            let long_dir = format!("refs/{long}/x");
            // A path under `refs/` that names no ref is refused by its name.
            let refused = [
                "refs/heads",
                long_dir.as_str(),
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
            let long_ref = format!("refs/heads/{long}");
            let long_extension = format!("extensions/{long}");
            // Deep paths: an absent directory and a file at an inner
            // component.
            let deep_absent = format!("refs/heads/{}x", "a/".repeat(10_000));
            let deep_under_file = format!("refs/heads/main/{}x", "a/".repeat(10_000));
            let mut not_found = vec![
                "refs/heads/absent",
                "refs/heads/fifo",
                "nothing",
                file_path.as_str(),
                long_ref.as_str(),
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

/// Moves the fan-out directory of `checksum` aside and puts a symlink to it in
/// its place.
fn symlink_fanout(repo: &Path, checksum: &Checksum) -> String {
    let fanout = &checksum.to_hex()[..2];
    let objects = repo.join("objects");
    fs::rename(objects.join(fanout), repo.join("moved")).unwrap();
    symlink("../moved", objects.join(fanout)).unwrap();
    fanout.to_owned()
}

/// The view refuses a symlink at the fan-out directory, for a stored object and
/// for a `.filez` built on request.
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

/// The view refuses a symlink at the path of a `bare-user` object. It serves
/// none of the bytes that the symlink leads to.
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

/// Creates a `bare-user` repository at `dir` with a regular file at each
/// path of `files`, and appends `groups` to its config. Returns the
/// repository, opened again so its config holds the groups. `own` sets the
/// own collection id.
async fn repo_with_files(dir: &Path, own: Option<&str>, groups: &str, files: &[&str]) -> Repo {
    Repo::create(dir, CreateOptions::new(RepoMode::BareUser))
        .await
        .unwrap();
    for file in files {
        let path = dir.join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("{}\n", Checksum::sha256(file.as_bytes()))).unwrap();
    }
    let mut text = fs::read_to_string(dir.join("config")).unwrap();
    if let Some(own) = own {
        text = text.replacen("[core]\n", &format!("[core]\ncollection-id={own}\n"), 1);
    }
    text.push_str(groups);
    fs::write(dir.join("config"), text).unwrap();
    Repo::open(dir).await.unwrap()
}

/// Returns `true` if the view serves `path` to `access` on a `GET` and a
/// `HEAD`, and `false` if it refuses the path on both.
async fn serves(view: &ArchiveView, path: &str, access: &ReadAccess) -> bool {
    let get = view.get(path, access).await.unwrap();
    let head = view.head(path, access).await.unwrap();
    match (get, head) {
        (ArchiveAnswer::Stream { .. } | ArchiveAnswer::Bytes(_), ArchiveHead::Found { .. }) => true,
        (ArchiveAnswer::Refused, ArchiveHead::Refused) => false,
        (get, head) => panic!("{path}: {get:?} {head:?}"),
    }
}

/// A ref is served when the group of the item has `r` on its name, and
/// refused otherwise. An item with no group reads no ref.
#[test]
fn a_ref_without_read_is_refused() {
    let tmp = TmpDir::new("view-ref-rights");
    block_on(async {
        let repo = repo_with_files(
            tmp.path(),
            None,
            "[ex-ostrya client \"public\"]\nauth=anonymous\nallow=r:pub/**\n",
            &["refs/heads/pub/a", "refs/heads/secret"],
        )
        .await;
        let view = ArchiveView::new(repo.clone());
        let anonymous = repo_access(&repo, "anonymous");
        assert!(serves(&view, "refs/heads/pub/a", &anonymous).await);
        assert!(!serves(&view, "refs/heads/secret", &anonymous).await);
        let stored = fs::read(tmp.path().join("refs/heads/pub/a")).unwrap();
        let (len, bytes) = read_all(view.get("refs/heads/pub/a", &anonymous).await.unwrap()).await;
        assert_eq!((len, bytes), (Some(stored.len() as u64), stored));
        let stranger = repo_access(&repo, "ssh:u");
        assert!(!serves(&view, "refs/heads/pub/a", &stranger).await);
    });
}

/// An alias needs `r` on its name and on its target. A target in a
/// collection takes the group of that collection. A target under
/// `refs/remotes/` is never served.
#[test]
fn an_alias_needs_read_on_its_name_and_its_target() {
    let tmp = TmpDir::new("view-alias-rights");
    block_on(async {
        let repo = repo_with_files(
            tmp.path(),
            None,
            "[ex-ostrya client \"public\"]\nauth=anonymous\nallow=r:open/**\n\
             [ex-ostrya client \"mirrors\"]\nauth=anonymous\ncollection=a.b\nallow=r:m/**\n",
            &[
                "refs/heads/open/target",
                "refs/heads/hidden/target",
                "refs/remotes/o/open/x",
                "refs/mirrors/a.b/m/x",
                "refs/mirrors/a.b/n/x",
            ],
        )
        .await;
        let heads = tmp.path().join("refs/heads");
        for (alias, body) in [
            ("open/to-open", "target"),
            ("open/to-hidden", "../hidden/target"),
            ("hidden/to-open", "../open/target"),
            ("open/to-remote", "../../remotes/o/open/x"),
            ("open/to-mirror", "../../mirrors/a.b/m/x"),
            ("open/to-hidden-mirror", "../../mirrors/a.b/n/x"),
        ] {
            symlink(body, heads.join(alias)).unwrap();
        }
        let view = ArchiveView::new(repo.clone());
        let access = repo_access(&repo, "anonymous");
        for (alias, served) in [
            ("open/to-open", true),
            ("open/to-hidden", false),
            ("hidden/to-open", false),
            ("open/to-remote", false),
            ("open/to-mirror", true),
            ("open/to-hidden-mirror", false),
        ] {
            let path = format!("refs/heads/{alias}");
            assert_eq!(serves(&view, &path, &access).await, served, "{alias}");
        }
        let target = fs::read(tmp.path().join("refs/mirrors/a.b/m/x")).unwrap();
        let answer = view.get("refs/heads/open/to-mirror", &access).await;
        assert_eq!(read_all(answer.unwrap()).await.1, target);
    });
}

/// `refs/remotes/` and a path under `refs/` outside `refs/heads/` and
/// `refs/mirrors/` are never served, also under the implicit groups, which
/// serve each local ref and each collection ref.
#[test]
fn remote_and_other_ref_paths_are_never_served() {
    let tmp = TmpDir::new("view-remote-refs");
    block_on(async {
        let repo = repo_with_files(
            tmp.path(),
            None,
            "",
            &[
                "refs/heads/main",
                "refs/mirrors/a.b/x",
                "refs/remotes/o/x",
                "refs/x",
                "refs/tags/x",
            ],
        )
        .await;
        let view = ArchiveView::new(repo.clone());
        let access = repo_access(&repo, "anonymous");
        assert!(serves(&view, "refs/heads/main", &access).await);
        assert!(serves(&view, "refs/mirrors/a.b/x", &access).await);
        for path in ["refs/remotes/o/x", "refs/x", "refs/tags/x"] {
            assert!(!serves(&view, path, &access).await, "{path}");
        }
    });
}

/// `refs/mirrors/ID/NAME` with the own collection id is in the local
/// namespace: the group of the local refs decides, and a `collection=*`
/// group does not. Another collection takes its own group.
#[test]
fn a_mirror_of_the_own_collection_takes_the_local_rights() {
    let tmp = TmpDir::new("view-own-mirror");
    block_on(async {
        let repo = repo_with_files(
            tmp.path(),
            Some("own.id"),
            "[ex-ostrya client \"local\"]\nauth=anonymous\nallow=r:pub/**\n\
             [ex-ostrya client \"others\"]\nauth=anonymous\ncollection=*\nallow=r:**\n",
            &[
                "refs/mirrors/own.id/pub/a",
                "refs/mirrors/own.id/secret",
                "refs/mirrors/c.d/secret",
            ],
        )
        .await;
        let view = ArchiveView::new(repo.clone());
        let access = repo_access(&repo, "anonymous");
        assert!(serves(&view, "refs/mirrors/own.id/pub/a", &access).await);
        assert!(!serves(&view, "refs/mirrors/own.id/secret", &access).await);
        assert!(serves(&view, "refs/mirrors/c.d/secret", &access).await);
        let stranger = repo_access(&repo, "ssh:u");
        assert!(!serves(&view, "refs/mirrors/own.id/pub/a", &stranger).await);
    });
}

/// Creates a `bare-user` repository under `base` with a commit on `main`,
/// writes that commit to each ref path of `refs`, and appends `groups` to the
/// config. Returns the repository, opened again so its config holds the
/// groups, and the commit.
async fn repo_with_refs(base: &Path, groups: &str, refs: &[&str]) -> (Repo, Checksum) {
    let src = build_tree(base);
    let (path, _, commit) = repo_of(base, RepoMode::BareUser, &src).await;
    for rel in refs {
        let file = path.join(rel);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, format!("{commit}\n")).unwrap();
    }
    let mut text = fs::read_to_string(path.join("config")).unwrap();
    text.push_str(groups);
    fs::write(path.join("config"), text).unwrap();
    (Repo::open(&path).await.unwrap(), commit)
}

/// The path of the `.access` file of `item`, relative to the repository
/// root.
fn access_file(item: &str) -> String {
    format!(
        "extensions/ostrya/summary/{}.access",
        Checksum::sha256(item.as_bytes())
    )
}

/// The client groups of the summary tests: `anonymous` reads `pub/**` but
/// `pub/secret`, `ssh:ci` reads each ref, and `ssh:ops` has no summary.
const SUMMARY_GROUPS: &str = "[ex-ostrya client \"public\"]\nauth=anonymous\nallow=r:pub/**\n\
                              deny=pub/secret\nsummary=true\n\
                              [ex-ostrya client \"ci\"]\nauth=ssh:ci\nallow=r:**\nsummary=true\n\
                              [ex-ostrya client \"ops\"]\nauth=ssh:ops\nallow=r:**\n";

/// Returns the names of the refs in field 0 of a summary.
fn summary_names(bytes: &[u8]) -> Vec<String> {
    ostrya::Summary::parse(bytes)
        .unwrap()
        .refs
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

/// The view serves the summary of the item of the client: the files at the
/// root for `anonymous`, and the files under `extensions/ostrya/summary/` for
/// each other item. An item with no summary gets not found, and so does a
/// direct request of a file under `extensions/ostrya/`.
#[test]
fn the_summary_of_each_item_is_served() {
    let tmp = TmpDir::new("view-summary-items");
    block_on(async {
        let (repo, _) = repo_with_refs(
            tmp.path(),
            SUMMARY_GROUPS,
            &["refs/heads/pub/a", "refs/heads/pub/secret"],
        )
        .await;
        let signer = ostrya::DummySigner::new(b"sig".to_vec());
        repo.regenerate_summaries(&SummaryOptions::default(), &[&signer])
            .await
            .unwrap();
        let view = ArchiveView::new(repo.clone());
        let root = repo.path();

        let anonymous = repo_access(&repo, "anonymous");
        for path in ["summary", "summary.sig"] {
            assert!(serves(&view, path, &anonymous).await, "{path}");
            let (_, bytes) = read_all(view.get(path, &anonymous).await.unwrap()).await;
            assert_eq!(bytes, fs::read(root.join(path)).unwrap(), "{path}");
        }
        let (_, bytes) = read_all(view.get("summary", &anonymous).await.unwrap()).await;
        assert_eq!(summary_names(&bytes), ["pub/a"]);

        let ci = repo_access(&repo, "ssh:ci");
        let stem = Checksum::sha256(b"ssh:ci").to_hex();
        let (_, bytes) = read_all(view.get("summary", &ci).await.unwrap()).await;
        let stored = format!("extensions/ostrya/summary/{stem}");
        assert_eq!(bytes, fs::read(root.join(&stored)).unwrap());
        assert_eq!(summary_names(&bytes), ["main", "pub/a", "pub/secret"]);
        let (_, sig) = read_all(view.get("summary.sig", &ci).await.unwrap()).await;
        assert_eq!(sig, fs::read(root.join(format!("{stored}.sig"))).unwrap());
        assert_eq!(
            repo.read_summary_of(&ci.item().clone()).await.unwrap(),
            Some(bytes)
        );

        let ops = repo_access(&repo, "ssh:ops");
        for path in ["summary", "summary.sig"] {
            assert!(matches!(
                view.get(path, &ops).await.unwrap(),
                ArchiveAnswer::NotFound
            ));
            assert_eq!(view.head(path, &ops).await.unwrap(), ArchiveHead::NotFound);
        }
        let ops_stem = Checksum::sha256(b"ssh:ops").to_hex();
        assert!(
            !root
                .join(format!("extensions/ostrya/summary/{ops_stem}"))
                .exists()
        );

        for path in [stored.clone(), access_file("anonymous")] {
            assert!(matches!(
                view.get(&path, &ci).await.unwrap(),
                ArchiveAnswer::NotFound
            ));
        }
    });
}

/// A summary whose `.access` file holds another digest than the access
/// digest of the item, or does not exist while the summary exists, is stale
/// on a `GET` and a `HEAD`. With no `.access` file and no file, the file is
/// not found. A change to `allow` makes the summary stale until the
/// summaries are written again.
#[test]
fn a_summary_with_no_matching_access_file_is_stale() {
    let tmp = TmpDir::new("view-summary-stale");
    block_on(async {
        let (repo, _) = repo_with_refs(tmp.path(), SUMMARY_GROUPS, &["refs/heads/pub/a"]).await;
        repo.regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        let view = ArchiveView::new(repo.clone());
        let anonymous = repo_access(&repo, "anonymous");
        let stale = |answer: ArchiveAnswer| match answer {
            ArchiveAnswer::StaleSummary { item } => item.to_string(),
            other => panic!("{other:?}"),
        };
        let access = repo.path().join(access_file("anonymous"));
        let digest = fs::read(&access).unwrap();
        assert_eq!(digest.len(), 65);

        for body in [None, Some(b"0\n".to_vec()), Some(digest[..64].to_vec())] {
            let absent = body.is_none();
            match body {
                Some(body) => fs::write(&access, body).unwrap(),
                None => fs::remove_file(&access).unwrap(),
            }
            for path in ["summary", "summary.sig"] {
                // The repository holds no `summary.sig`.
                if absent && path == "summary.sig" {
                    let answer = view.get(path, &anonymous).await.unwrap();
                    assert!(matches!(answer, ArchiveAnswer::NotFound), "{answer:?}");
                    let head = view.head(path, &anonymous).await.unwrap();
                    assert_eq!(head, ArchiveHead::NotFound);
                    continue;
                }
                let answer = view.get(path, &anonymous).await.unwrap();
                assert_eq!(stale(answer), "anonymous", "{path}");
                let head = view.head(path, &anonymous).await.unwrap();
                assert_eq!(head, ArchiveHead::StaleSummary, "{path}");
            }
        }
        fs::write(&access, &digest).unwrap();
        assert!(serves(&view, "summary", &anonymous).await);

        let text = fs::read_to_string(repo.path().join("config")).unwrap();
        let changed = text.replace("allow=r:pub/**\n", "allow=r:pub/**;r:main\n");
        fs::write(repo.path().join("config"), changed).unwrap();
        let reopened = Repo::open(repo.path()).await.unwrap();
        let anonymous = repo_access(&reopened, "anonymous");
        let answer = view.get("summary", &anonymous).await.unwrap();
        assert_eq!(stale(answer), "anonymous");
        reopened
            .regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        let (_, bytes) = read_all(view.get("summary", &anonymous).await.unwrap()).await;
        assert_eq!(summary_names(&bytes), ["main", "pub/a"]);
    });
}

/// An exact group with `summary=false` under a group of `*` with
/// `summary=true` makes the summary stale. The exact group takes the refs of
/// its collection from the summary, so the summary that the group of `*`
/// gave holds refs that the item no more gets.
#[test]
fn an_exact_group_with_no_summary_makes_the_summary_stale() {
    let tmp = TmpDir::new("view-summary-exact");
    block_on(async {
        let any = "[ex-ostrya client \"any\"]\nauth=anonymous\ncollection=*\nallow=r:**\n\
                   summary=true\n";
        let refs = ["refs/mirrors/a.b/public", "refs/mirrors/a.b/secret"];
        let (repo, _) = repo_with_refs(tmp.path(), any, &refs).await;
        repo.regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        let view = ArchiveView::new(repo.clone());
        let anonymous = repo_access(&repo, "anonymous");
        let (_, bytes) = read_all(view.get("summary", &anonymous).await.unwrap()).await;
        let map = ostrya::Summary::parse(&bytes)
            .unwrap()
            .collection_map()
            .unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].1.len(), 2);

        let config = repo.path().join("config");
        let mut text = fs::read_to_string(&config).unwrap();
        text.push_str(
            "[ex-ostrya client \"exact\"]\nauth=anonymous\ncollection=a.b\nallow=r:public\n",
        );
        fs::write(&config, text).unwrap();
        let reopened = Repo::open(repo.path()).await.unwrap();
        let anonymous = repo_access(&reopened, "anonymous");
        for path in ["summary", "summary.sig"] {
            let answer = view.get(path, &anonymous).await.unwrap();
            assert!(
                matches!(answer, ArchiveAnswer::StaleSummary { .. }),
                "{path}: {answer:?}"
            );
        }
        reopened
            .regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        let (_, bytes) = read_all(view.get("summary", &anonymous).await.unwrap()).await;
        let summary = ostrya::Summary::parse(&bytes).unwrap();
        assert!(
            summary
                .metadata_value("ostree.summary.collection-map")
                .is_none()
        );
    });
}

/// A symlink at `extensions/ostrya` is refused: the view does not serve the
/// summary, and the writer does not write through it.
#[test]
fn a_symlink_at_the_summary_directory_is_refused() {
    let tmp = TmpDir::new("view-summary-symlink");
    block_on(async {
        let (repo, _) = repo_with_refs(tmp.path(), SUMMARY_GROUPS, &[]).await;
        repo.regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        fs::rename(repo.path().join("extensions/ostrya"), &elsewhere).unwrap();
        symlink(&elsewhere, repo.path().join("extensions/ostrya")).unwrap();
        let view = ArchiveView::new(repo.clone());
        for item in ["anonymous", "ssh:ci"] {
            let access = repo_access(&repo, item);
            assert!(!serves(&view, "summary", &access).await, "{item}");
        }
        let err = repo
            .regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("extensions/ostrya"), "{err}");
        let ci = ostrya::access::AuthItem::parse("ssh:ci").unwrap();
        assert!(repo.read_summary_of(&ci).await.is_err());
    });
}

/// An identified client with no read right on a ref gets `config`, the
/// metadata objects, and the built `.filez` objects. It gets no ref.
#[test]
fn objects_and_config_are_served_to_each_identified_client() {
    let tmp = TmpDir::new("view-objects-rights");
    let src = build_tree(tmp.path());
    block_on(async {
        let (path, _, commit) = repo_of(tmp.path(), RepoMode::BareUser, &src).await;
        let mut text = fs::read_to_string(path.join("config")).unwrap();
        text.push_str("[ex-ostrya client \"c\"]\nauth=ssh:u\n");
        fs::write(path.join("config"), text).unwrap();
        let repo = Repo::open(&path).await.unwrap();
        let view = ArchiveView::new(repo.clone());
        let access = repo_access(&repo, "ssh:u");
        let file = file_objects(&repo, &commit).await[0];
        for served in [
            "config".to_owned(),
            object_path(ObjectType::Commit, &commit),
            object_path(ObjectType::File, &file),
        ] {
            assert!(serves(&view, &served, &access).await, "{served}");
        }
        assert!(!serves(&view, "refs/heads/main", &access).await);
    });
}

/// `extensions/ostrya/` is not found. The other files under `extensions/`
/// are served as stored.
#[test]
fn the_extensions_of_the_port_are_not_found() {
    let tmp = TmpDir::new("view-port-extensions");
    block_on(async {
        let repo = repo_with_files(
            tmp.path(),
            None,
            "",
            &[
                "extensions/ostrya/x",
                "extensions/ostrya-other/x",
                "extensions/other/y",
            ],
        )
        .await;
        let view = ArchiveView::new(repo.clone());
        let access = repo_access(&repo, "anonymous");
        for path in ["extensions/ostrya/x", "extensions/ostrya"] {
            assert_answer(view.get(path, &access).await.unwrap(), false, path);
            assert_eq!(
                view.head(path, &access).await.unwrap(),
                ArchiveHead::NotFound
            );
        }
        assert!(serves(&view, "extensions/ostrya-other/x", &access).await);
        assert!(serves(&view, "extensions/other/y", &access).await);
    });
}

/// In each mode, the view serves the composefs image of a commit as stored.
/// A `HEAD` gives its length. The image of a commit that the repository does
/// not hold is not found.
#[test]
fn the_composefs_image_is_served_as_stored() {
    let tmp = TmpDir::new("view-cfs");
    let base = tmp.path().join("tree");
    common::composefs::build_owned_source(&base);
    block_on(async {
        for mode in [RepoMode::Archive, RepoMode::BareUser] {
            let root = tmp.path().join(mode.as_mode_str());
            let repo = common::composefs::new_repo(&root, mode, "").await;
            let (commit, _) = common::composefs::commit_tree(&repo, &base, 1, true, None).await;
            let view = ArchiveView::new(repo.clone());
            let path = object_path(ObjectType::ComposefsImage, &commit);
            let stored = fs::read(repo.composefs_image_path(&commit)).unwrap();
            let (len, bytes) = get(&view, &path).await;
            assert_eq!(len, Some(stored.len() as u64), "{mode:?}");
            assert_eq!(bytes, stored, "{mode:?}");
            assert_eq!(
                view.head(&path, &anyone()).await.unwrap(),
                ArchiveHead::Found {
                    len: Some(stored.len() as u64)
                }
            );
            let absent = object_path(ObjectType::ComposefsImage, &Checksum::from_bytes([7; 32]));
            assert_both(&view, &absent, false).await;
        }
    });
}
