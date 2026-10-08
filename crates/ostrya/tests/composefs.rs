#![forbid(unsafe_code)]

//! Composefs export tests.
//!
//! The `ostree` command exported the composefs fixture from the source tree
//! that the bare-user fixture commits. [`Repo::export_composefs`] over the
//! bare-user fixture commit must reproduce the golden image `tree.cfs` byte for
//! byte. The archive fixture holds the same commit, and its export must give
//! the same bytes.
//!
//! Each export must also give the fs-verity digest in the MANIFEST. The
//! fixture generator measured this digest with `composefs-info measure-file`
//! on the image of the `ostree` command. A second test writes the digest into
//! the metadata of a commit and reads it back.
//!
//! The tests check [`VerityPolicy::Disabled`] the same way against
//! `tree-noverity.cfs`. One more test shows that this policy reads no payload.
//! The test rewrites the bytes of a content object in place at the same
//! length. The `Disabled` image stays the same, and the `Computed` image
//! changes.
//!
//! Each golden check also exports through a file descriptor with
//! [`Repo::export_composefs_to`]. The file must hold the same bytes, and the
//! returned digest must equal the fs-verity digest of the file content. One
//! more test requires that [`Transaction::composefs_digest`] over the same tree
//! gives the recorded digest.
//!
//! Two tests build their own tree, which the running user owns. In the first
//! test, a `bare` and a `bare-user` repository hold the tree. The two
//! repositories export the same bytes and the same digest under each verity
//! policy.
//!
//! The `bare` export reads the owner, the mode, and the xattrs from the object
//! inode. The `bare-user` export reads them from `user.ostreemeta`. The mtime
//! is not an input to the image.
//!
//! In the second test, a `bare` repository seals its objects. The kernel
//! measures the image that the export writes with
//! [`ComposefsOptions::RECORDED`], and gets the digest that the commit records.
//!
//! The tests that compare against a golden image or against the recorded
//! digest skip if the composefs fixture is absent. The fixture generator
//! writes no composefs fixture if its `ostree` command has no composefs
//! support, or if `composefs-info` is not available.
//!
//! The tests that seal objects also skip if the file system has no fs-verity.
//! All other tests read no composefs fixture and always run.

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use ostrya::{
    Checksum, CommitOptions, ComposefsOptions, CreateOptions, DirMeta, Error, FileMeta,
    MutableTree, Repo, RepoMode, VerityPolicy,
};
use ostrya_composefs::FsVerityHasher;
use ostrya_core::{ObjectType, Xattrs, loose_path};
use ostrya_rt::block_on;

use common::{COMMIT, HELLO_TXT, TmpDir, fixture_repo, fixture_root};

/// The directory that holds the checked-in composefs golden fixtures.
fn composefs_dir() -> PathBuf {
    fixture_root().join("composefs")
}

/// Reads a `key=value` entry from the fixture MANIFEST.
fn manifest_value(key: &str) -> Option<String> {
    let text = std::fs::read_to_string(fixture_root().join("MANIFEST")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .map(|v| v.trim().to_owned())
}

/// Returns the composefs image digest under `key` in the MANIFEST.
///
/// The fixture generator measured the digest with
/// `composefs-info measure-file` on the image that the `ostree` command wrote.
/// If the fixture is absent, the value is `None`, and the test skips.
fn manifest_digest(key: &str) -> Option<String> {
    manifest_value(key).filter(|s| !s.is_empty())
}

/// Copies the `mode` fixture repository into `scratch` and returns its path.
/// `cp -a` preserves the `user.ostreemeta` xattrs that the objects carry.
fn scratch_fixture_repo(scratch: &TmpDir, mode: &str) -> PathBuf {
    let src = fixture_repo(mode);
    let dst = scratch.path().join("repo");
    let status = Command::new("cp")
        .arg("-a")
        .arg(&src)
        .arg(&dst)
        .status()
        .expect("run cp to copy the fixture repo");
    assert!(status.success(), "cp -a failed to copy the fixture repo");
    dst
}

/// The loose path of the content object `checksum` in the bare-user repository
/// at `repo_dir`. The object that the caller names is in the tree of `COMMIT`,
/// so the `Computed` image depends on its payload.
fn content_object(repo_dir: &Path, checksum: &str) -> PathBuf {
    repo_dir.join("objects").join(loose_path(
        &Checksum::from_hex(checksum).unwrap(),
        ObjectType::File,
        RepoMode::BareUser,
    ))
}

/// Flips one byte of the payload at `path` in place. The length of the object
/// and its `user.ostreemeta` attribute do not change.
fn rewrite_payload(path: &Path) {
    use std::io::Write;

    let mut bytes = std::fs::read(path).expect("read the object payload");
    assert!(!bytes.is_empty(), "the object has a payload to rewrite");
    bytes[0] ^= 0xff;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open the object for writing");
    file.write_all(&bytes).expect("rewrite the object payload");
    file.flush().expect("flush the rewritten object");
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Exports the fixture commit under `verity`. The image must equal
/// `<stem>.cfs` byte for byte, and its fs-verity digest must equal the MANIFEST
/// value at `digest_key`. The fd form must give the same bytes and the same
/// digest.
///
/// Both the `bare-user` and the `archive` fixture hold the same commit, so
/// each export must equal the golden image from `bare-user`. The `ostree`
/// command 2026.1 writes the same image from `archive` (observed).
///
/// Skips if the golden fixture is absent.
fn check_export(stem: &str, digest_key: &str, verity: VerityPolicy) {
    for mode in ["bare-user", "archive"] {
        check_export_from(mode, stem, digest_key, verity);
    }
}

/// [`check_export`] over the fixture repository of `mode`.
fn check_export_from(mode: &str, stem: &str, digest_key: &str, verity: VerityPolicy) {
    let (Some(digest), Ok(golden)) = (
        manifest_digest(digest_key),
        std::fs::read(composefs_dir().join(format!("{stem}.cfs"))),
    ) else {
        eprintln!("composefs fixture {stem} absent; skipping");
        return;
    };

    let scratch = TmpDir::new("composefs-export-to");
    let image_path = scratch.path().join(format!("{stem}.cfs"));
    let repo_dir = fixture_repo(mode);
    let stem = format!("{mode} {stem}");
    let stem = stem.as_str();
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let commit = Checksum::from_hex(COMMIT).unwrap();
        let image = repo
            .export_composefs(&commit, &ComposefsOptions { verity })
            .await
            .unwrap();

        assert_eq!(
            image.bytes.len(),
            golden.len(),
            "{stem}: image length {} != golden {}",
            image.bytes.len(),
            golden.len()
        );
        if let Some(pos) = image.bytes.iter().zip(&golden).position(|(a, b)| a != b) {
            panic!(
                "{stem}: image diverges from golden at byte {pos:#x}: got {:#04x}, want {:#04x}",
                image.bytes[pos], golden[pos]
            );
        }
        assert_eq!(
            to_hex(&image.fs_verity),
            digest,
            "{stem}: fs-verity digest mismatch"
        );

        let file = std::fs::File::create(&image_path).expect("create the image file");
        let streamed = repo
            .export_composefs_to(&commit, &ComposefsOptions { verity }, file.as_fd())
            .await
            .unwrap();
        drop(file);

        let written = std::fs::read(&image_path).expect("read the exported image back");
        assert_eq!(
            written, image.bytes,
            "{stem}: the fd form wrote different bytes than the buffer form"
        );
        assert_eq!(
            to_hex(&streamed),
            digest,
            "{stem}: the fd form returned a different digest"
        );
        assert_eq!(
            streamed,
            FsVerityHasher::hash(&written),
            "{stem}: the returned digest differs from the digest of the file"
        );
    });
}

#[test]
fn export_matches_golden_image_and_digest() {
    check_export("tree", "composefs_digest", VerityPolicy::Computed);
}

#[test]
fn noverity_export_matches_golden_image_and_digest() {
    check_export(
        "tree-noverity",
        "composefs_noverity_digest",
        VerityPolicy::Disabled,
    );
}

#[test]
fn stores_digest_in_commit_metadata() {
    let Some(digest) = manifest_digest("composefs_digest") else {
        eprintln!("composefs fixture absent; skipping");
        return;
    };

    // Copy the fixture repository, so that the transaction publishes into a
    // throwaway copy. The shared unpacked fixture stays unchanged.
    let scratch = TmpDir::new("composefs-meta");
    let dst = scratch_fixture_repo(&scratch, "bare-user");

    block_on(async {
        let repo = Repo::open(&dst).await.unwrap();
        let commit = Checksum::from_hex(COMMIT).unwrap();

        let txn = repo.transaction().await.unwrap();
        let new_commit = repo
            .commit_add_composefs_metadata(&txn, &commit)
            .await
            .unwrap();
        assert_ne!(
            new_commit, commit,
            "adding the digest metadata yields a distinct commit"
        );
        txn.commit().await.unwrap();

        let (obj, _) = repo.load_commit(&new_commit).await.unwrap();
        let value = obj
            .metadata
            .dict_get("ostree.composefs.digest.v0")
            .expect("ostree.composefs.digest.v0 present in the new commit");
        let (_, inner) = value.as_variant().expect("digest value is a variant");
        let bytes = inner.as_bytes().expect("digest is a byte array");
        assert_eq!(
            to_hex(bytes),
            digest,
            "stored digest equals the tool's recorded digest"
        );
    });
}

/// `Transaction::composefs_digest` gives the recorded digest of the fixture
/// tree. The transaction stages nothing, so each
/// object comes from the repository. The value equals the digest that the
/// buffered export returns.
#[test]
fn transaction_digest_matches_recorded_digest() {
    let Some(digest) = manifest_digest("composefs_digest") else {
        eprintln!("composefs fixture absent; skipping");
        return;
    };

    let repo_dir = fixture_repo("bare-user");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let (tree, commit) = repo.read_commit(COMMIT).await.unwrap();

        let txn = repo.transaction().await.unwrap();
        let staged = txn.composefs_digest(&tree).await.unwrap();
        txn.abort().await.unwrap();

        assert_eq!(
            to_hex(&staged),
            digest,
            "the staged-tree digest equals the tool's recorded digest"
        );

        let image = repo
            .export_composefs(
                &commit,
                &ComposefsOptions {
                    verity: VerityPolicy::Computed,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            staged, image.fs_verity,
            "the staged-tree digest equals the exported image's digest"
        );
    });
}

/// Seals each regular `.file` object under `repo_dir/objects` with the
/// parameters that the `ostree` command uses, and returns the number of sealed
/// objects. If the file system refuses the first seal, returns `None`, so that
/// the caller skips.
fn seal_file_objects(repo_dir: &Path) -> Option<usize> {
    let mut sealed = 0;
    for fanout in std::fs::read_dir(repo_dir.join("objects")).unwrap() {
        let fanout = fanout.unwrap().path();
        if !fanout.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&fanout).unwrap() {
            let path = entry.unwrap().path();
            let is_file_object = path.extension().is_some_and(|e| e == "file");
            if !is_file_object || !std::fs::symlink_metadata(&path).unwrap().is_file() {
                continue;
            }
            let ro = std::fs::File::open(&path).unwrap();
            match ostrya_sys::enable_verity(ro.as_fd()) {
                Ok(()) => sealed += 1,
                Err(e) if sealed == 0 => {
                    eprintln!("filesystem lacks fs-verity ({e})");
                    return None;
                }
                Err(e) => panic!("seal {}: {e}", path.display()),
            }
        }
    }
    Some(sealed)
}

/// In a bare-user repository with sealed objects,
/// `Transaction::composefs_digest` over the fixture tree gives the digest of
/// the unsealed fixture. It also gives the recorded digest.
///
/// In the sealed copy, the kernel supplies the digest of each backing object.
/// The unit test `every_sealed_fixture_object_yields_the_kernel_digest` in
/// `src/file.rs` shows that each sealed fixture object gives that digest.
///
/// Skips if the fixture is absent or if the file system has no fs-verity.
#[test]
fn sealed_repository_digest_matches_recorded_digest() {
    let Some(digest) = manifest_digest("composefs_digest") else {
        eprintln!("composefs fixture absent; skipping");
        return;
    };

    let scratch = TmpDir::new("composefs-sealed");
    let sealed_dir = scratch_fixture_repo(&scratch, "bare-user");
    let cfg = sealed_dir.join("config");
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str("[ex-integrity]\nfsverity=yes\n");
    std::fs::write(&cfg, text).unwrap();
    let Some(sealed) = seal_file_objects(&sealed_dir) else {
        eprintln!("skipping sealed-repository digest check");
        return;
    };
    assert!(sealed > 0, "the fixture holds content objects to seal");

    let digest_of = |repo_dir: PathBuf| async move {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let (tree, _) = repo.read_commit(COMMIT).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        let value = txn.composefs_digest(&tree).await.unwrap();
        txn.abort().await.unwrap();
        value
    };
    block_on(async {
        let from_sealed = digest_of(sealed_dir.clone()).await;
        let from_unsealed = digest_of(fixture_repo("bare-user")).await;
        assert_eq!(
            from_sealed, from_unsealed,
            "the sealed repository reaches the unsealed digest"
        );
        assert_eq!(
            to_hex(&from_sealed),
            digest,
            "the sealed repository reaches the tool's recorded digest"
        );
    });
}

/// Builds a source tree under `base/src` that the running user owns, with fixed
/// modes and `user.*` xattrs. The tree holds:
///
/// - a regular file of each mode class,
/// - a file that spans more than one fs-verity block,
/// - an empty file,
/// - a nested directory,
/// - a symlink.
///
/// Linux refuses a `user.*` xattr on a symlink, so the symlink carries none.
/// The function sets each xattr before the chmod, because a `user.*` xattr
/// needs write access to the inode.
fn build_owned_source(base: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let chmod = |p: &Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    };
    let setxattr = |p: &Path, name: &str, value: &[u8]| {
        rustix::fs::setxattr(p, name, value, rustix::fs::XattrFlags::empty()).unwrap();
    };
    let src = base.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello composefs\n").unwrap();
    std::fs::write(src.join("readonly.txt"), b"read only\n").unwrap();
    std::fs::write(src.join("run.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    let big: Vec<u8> = (0..9000).map(|i| i as u8).collect();
    std::fs::write(src.join("big.bin"), big).unwrap();
    std::fs::write(src.join("empty"), b"").unwrap();
    std::fs::write(src.join("sub/nested.txt"), b"nested\n").unwrap();
    std::os::unix::fs::symlink("hello.txt", src.join("link")).unwrap();

    setxattr(&src, "user.dir", b"root");
    setxattr(&src.join("hello.txt"), "user.demo", b"value");
    setxattr(&src.join("hello.txt"), "user.shared", b"s");
    setxattr(&src.join("readonly.txt"), "user.shared", b"s");
    setxattr(&src.join("sub"), "user.dir", b"sub");

    chmod(&src.join("hello.txt"), 0o644);
    chmod(&src.join("readonly.txt"), 0o444);
    chmod(&src.join("run.sh"), 0o755);
    chmod(&src.join("big.bin"), 0o644);
    chmod(&src.join("empty"), 0o644);
    chmod(&src.join("sub/nested.txt"), 0o600);
    chmod(&src.join("sub"), 0o750);
    chmod(&src, 0o755);
}

/// Creates a repository at `root` in `mode`. If `config` is not empty, appends
/// it to the config file of the repository. Then opens the repository again,
/// so that it parses the text.
async fn new_repo(root: &Path, mode: RepoMode, config: &str) -> Repo {
    let repo = Repo::create(root, CreateOptions::new(mode)).await.unwrap();
    if config.is_empty() {
        return repo;
    }
    drop(repo);
    let cfg = root.join("config");
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(config);
    std::fs::write(&cfg, text).unwrap();
    Repo::open(root).await.unwrap()
}

/// Walks `base/src` into `repo` with no modifier, so that the commit records
/// the owner, the mode, and the xattrs of each source inode. Commits the tree
/// at timestamp 0, and returns the commit checksum.
async fn commit_owned(repo: &Repo, base: &Path) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some("owned tree".to_owned()),
                timestamp: Some(0),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.commit().await.unwrap();
    commit
}

/// The names in `xattrs` as text, for a failure message.
fn xattr_names(xattrs: &Xattrs) -> Vec<String> {
    xattrs
        .iter()
        .map(|(name, _)| String::from_utf8_lossy(name).into_owned())
        .collect()
}

/// The xattr set the walk records for `pairs` of (name, value).
fn expected_xattrs(pairs: &[(&str, &[u8])]) -> Xattrs {
    Xattrs::new(
        pairs
            .iter()
            .map(|(name, value)| (format!("{name}\0").into_bytes(), value.to_vec())),
    )
    .unwrap()
}

/// A `bare` and a `bare-user` repository hold one tree that the running user
/// owns. Under each verity policy, the two repositories export the same image
/// and the same digest.
///
/// The `bare` export reads the owner, the mode, and the xattrs of a file from
/// the object inode. The `bare-user` export reads them from `user.ostreemeta`.
/// A content object stores no mtime. The export sets the mtime of each inode to
/// 0, so the mtime is not an input to the image.
///
/// If the host adds xattrs to a new file, the commit or the xattr check fails.
#[test]
fn bare_and_bare_user_export_the_same_image() {
    use std::os::unix::fs::MetadataExt;

    let scratch = TmpDir::new("composefs-bare-pair");
    let base = scratch.path().join("tree");
    build_owned_source(&base);

    block_on(async {
        let bare = new_repo(&scratch.path().join("bare"), RepoMode::Bare, "").await;
        let user = new_repo(&scratch.path().join("bare-user"), RepoMode::BareUser, "").await;
        let commit = commit_owned(&bare, &base).await;
        assert_eq!(
            commit_owned(&user, &base).await,
            commit,
            "both repositories record the same commit"
        );

        let (commit_obj, _) = bare.load_commit(&commit).await.unwrap();
        let root = bare.load_dirtree(&commit_obj.root_dirtree).await.unwrap();
        let (_, sub_tree, sub_meta) = root
            .dirs
            .iter()
            .find(|(n, _, _)| n == "sub")
            .expect("the tree holds sub");
        let sub = bare.load_dirtree(sub_tree).await.unwrap();
        let files = [
            (
                "hello.txt",
                0o100644,
                expected_xattrs(&[("user.demo", b"value"), ("user.shared", b"s")]),
            ),
            (
                "readonly.txt",
                0o100444,
                expected_xattrs(&[("user.shared", b"s")]),
            ),
            ("run.sh", 0o100755, expected_xattrs(&[])),
            ("big.bin", 0o100644, expected_xattrs(&[])),
            ("empty", 0o100644, expected_xattrs(&[])),
            ("sub/nested.txt", 0o100600, expected_xattrs(&[])),
        ];
        for (name, mode, xattrs) in &files {
            let (tree, leaf) = match name.strip_prefix("sub/") {
                Some(leaf) => (&sub, leaf),
                None => (&root, *name),
            };
            let checksum = tree
                .files
                .iter()
                .find(|(n, _)| n == leaf)
                .map(|(_, c)| *c)
                .unwrap_or_else(|| panic!("the tree holds {name}"));
            let source = std::fs::symlink_metadata(base.join("src").join(name)).unwrap();
            for (label, repo) in [("bare", &bare), ("bare-user", &user)] {
                let file = repo.load_file(&checksum).await.unwrap();
                assert_eq!(
                    (file.uid, file.gid),
                    (source.uid(), source.gid()),
                    "{label} {name}: the owner is the owner of the source file"
                );
                assert_eq!(file.mode, *mode, "{label} {name}: mode");
                assert_eq!(
                    file.xattrs,
                    *xattrs,
                    "{label} {name}: xattrs {:?}, want {:?}",
                    xattr_names(&file.xattrs),
                    xattr_names(xattrs)
                );
            }
        }
        let dirs = [
            (
                "root",
                &commit_obj.root_dirmeta,
                0o040755,
                b"root".as_slice(),
            ),
            ("sub", sub_meta, 0o040750, b"sub".as_slice()),
        ];
        for (label, checksum, mode, value) in dirs {
            let dirmeta = bare.load_dirmeta(checksum).await.unwrap();
            let want = expected_xattrs(&[("user.dir", value)]);
            assert_eq!(
                dirmeta.xattrs,
                want,
                "{label} dirmeta: xattrs {:?}, want {:?}",
                xattr_names(&dirmeta.xattrs),
                xattr_names(&want)
            );
            assert_eq!(dirmeta.mode, mode, "{label} dirmeta: mode");
        }

        let mut images = Vec::new();
        for verity in [VerityPolicy::Computed, VerityPolicy::Disabled] {
            let opts = ComposefsOptions { verity };
            let from_bare = bare.export_composefs(&commit, &opts).await.unwrap();
            let from_user = user.export_composefs(&commit, &opts).await.unwrap();
            assert_eq!(
                from_bare.bytes.len(),
                from_user.bytes.len(),
                "{verity:?}: bare image length {} != bare-user {}",
                from_bare.bytes.len(),
                from_user.bytes.len()
            );
            if let Some(pos) = from_bare
                .bytes
                .iter()
                .zip(&from_user.bytes)
                .position(|(a, b)| a != b)
            {
                panic!(
                    "{verity:?}: bare image diverges from bare-user at byte {pos:#x}: \
                     got {:#04x}, want {:#04x}",
                    from_bare.bytes[pos], from_user.bytes[pos]
                );
            }
            assert_eq!(
                from_bare.fs_verity, from_user.fs_verity,
                "{verity:?}: the two repositories give the same digest"
            );
            images.push(from_bare.bytes);
        }
        assert_ne!(
            images[0], images[1],
            "the Computed and Disabled images differ"
        );
    });
}

/// Enables fs-verity on `fd`, and tries again on `ETXTBSY`. The kernel refuses
/// to seal an inode that a writable descriptor still holds. A child that
/// another test forks holds a copy of each open descriptor until its `exec`, so
/// the refusal stops when that window closes. If the refusal lasts for all
/// attempts, the function returns it.
fn enable_verity_retrying(fd: std::os::fd::BorrowedFd<'_>) -> rustix::io::Result<()> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        match ostrya_sys::enable_verity(fd) {
            Err(rustix::io::Errno::TXTBSY) if attempts < 50 => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

/// A `bare` repository seals its objects and exports an image with
/// [`ComposefsOptions::RECORDED`]. The kernel measures this image and gets the
/// digest that the commit records. Skips if the file system has no fs-verity.
#[test]
fn a_sealed_bare_export_measures_the_recorded_digest() {
    let scratch = TmpDir::new("composefs-sealed-bare");
    let probe = scratch.path().join("probe");
    std::fs::write(&probe, b"probe\n").unwrap();
    let ro = std::fs::File::open(&probe).unwrap();
    match enable_verity_retrying(ro.as_fd()) {
        Ok(()) => {}
        Err(rustix::io::Errno::TXTBSY) => panic!("seal the probe: ETXTBSY after all attempts"),
        Err(e) => {
            eprintln!("skipping: filesystem lacks fs-verity ({e})");
            return;
        }
    }
    drop(ro);

    let base = scratch.path().join("tree");
    build_owned_source(&base);
    let repo_dir = scratch.path().join("repo");
    let image_path = scratch.path().join("root.cfs");

    block_on(async {
        let repo = new_repo(&repo_dir, RepoMode::Bare, "[ex-integrity]\nfsverity=yes\n").await;
        let commit = commit_owned(&repo, &base).await;

        let objects: Vec<PathBuf> = common::regular_objects(&repo_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "file"))
            .collect();
        assert_eq!(objects.len(), 6, "the tree holds six regular files");
        for path in &objects {
            let ro = std::fs::File::open(path).unwrap();
            if let Err(e) = ostrya_sys::measure_verity(ro.as_fd()) {
                panic!("{} is not sealed: {e}", path.display());
            }
        }

        let txn = repo.transaction().await.unwrap();
        let stored = repo
            .commit_add_composefs_metadata(&txn, &commit)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        let (obj, _) = repo.load_commit(&stored).await.unwrap();
        let value = obj
            .metadata
            .dict_get("ostree.composefs.digest.v0")
            .expect("the new commit carries the digest key");
        let (_, inner) = value.as_variant().expect("digest value is a variant");
        let recorded = inner.as_bytes().expect("digest is a byte array").to_vec();

        let file = std::fs::File::create(&image_path).expect("create the image file");
        let returned = repo
            .export_composefs_to(&stored, &ComposefsOptions::RECORDED, file.as_fd())
            .await
            .unwrap();
        drop(file);

        let ro = std::fs::File::open(&image_path).expect("open the image read-only");
        enable_verity_retrying(ro.as_fd()).expect("seal the image");
        let measured = ostrya_sys::measure_verity(ro.as_fd()).expect("measure the image");
        assert_eq!(
            to_hex(&measured),
            to_hex(&recorded),
            "the kernel measures the image to the recorded digest"
        );
        assert_eq!(
            to_hex(&returned),
            to_hex(&recorded),
            "the export returns the recorded digest"
        );
    });
}

/// The payload of a content object is an input to the `Computed` image and has
/// no effect on the `Disabled` image. The test rewrites the payload in place at
/// the same length. The metadata of each inode stays the same, so the object
/// loads under both policies. The payload is the only input that changes.
///
/// The bare-user fixture and the library are the only inputs, so this test
/// runs whatever composefs support the `ostree` command on the host has.
#[test]
fn disabled_policy_reads_no_payload() {
    let computed = ComposefsOptions {
        verity: VerityPolicy::Computed,
    };
    let disabled = ComposefsOptions {
        verity: VerityPolicy::Disabled,
    };

    let scratch = TmpDir::new("composefs-noverity-payload");
    let repo_dir = scratch_fixture_repo(&scratch, "bare-user");

    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let commit = Checksum::from_hex(COMMIT).unwrap();

        let before_computed = repo.export_composefs(&commit, &computed).await.unwrap();
        let before_disabled = repo.export_composefs(&commit, &disabled).await.unwrap();

        rewrite_payload(&content_object(&repo_dir, HELLO_TXT));

        let after_computed = repo.export_composefs(&commit, &computed).await.unwrap();
        let after_disabled = repo.export_composefs(&commit, &disabled).await.unwrap();

        assert_eq!(
            before_disabled.bytes, after_disabled.bytes,
            "a rewritten payload leaves the Disabled image unchanged"
        );
        assert_ne!(
            before_computed.bytes, after_computed.bytes,
            "a rewritten payload changes the Computed image"
        );
        assert_ne!(
            before_disabled.fs_verity, before_computed.fs_verity,
            "the two policies produce distinct images"
        );
    });
}

/// The inode of the helper tree that carries the attributes under test.
#[derive(Clone, Copy)]
enum Carrier {
    /// The root directory, through its dirmeta object.
    Root,
    /// A regular file in the root. The export adds `trusted.overlay.redirect`
    /// and `trusted.overlay.metacopy` to this inode, in addition to its own
    /// attributes. This case also checks that these two are outside the budget.
    File,
}

/// Exports the composefs image of a tree whose `carrier` inode holds `xattrs`.
/// The tree is in a new repository of its own in `mode`.
///
/// The function builds the dirmeta object directly, because the limit of the
/// host file system decides if a real directory can hold the attributes. If
/// the attributes on a file object reach that limit in a bare-user repository,
/// `mode` is `Archive`. An archive object carries its metadata in its own
/// header.
async fn export_xattrs(
    repo_dir: &Path,
    mode: RepoMode,
    carrier: Carrier,
    xattrs: Xattrs,
) -> Result<(), Error> {
    let repo = Repo::create(repo_dir, CreateOptions::new(mode))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let root_xattrs = match carrier {
        Carrier::Root => xattrs,
        Carrier::File => {
            let meta = FileMeta {
                uid: 0,
                gid: 0,
                mode: 0o100644,
                xattrs,
            };
            // A file with content is backed, so the export adds the redirect
            // and metacopy attributes to its inode.
            let file = txn
                .write_regfile_inline(None, &meta, b"backed\n")
                .await
                .unwrap();
            mtree.replace_file("f", file).unwrap();
            Xattrs::empty()
        }
    };
    let dirmeta_bytes = DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040755,
        xattrs: root_xattrs,
    }
    .serialize()
    .unwrap();
    let dirmeta = txn
        .write_metadata(ObjectType::DirMeta, None, &dirmeta_bytes)
        .await
        .unwrap();
    mtree.set_metadata_checksum(dirmeta);
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some("xattr budget".to_owned()),
                timestamp: Some(0),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    // The staged digest path reads the objects through the transaction. It must
    // reach the same outcome as the export over the published commit.
    let staged = txn.composefs_digest(&root).await.map(|_| ());
    txn.commit().await.unwrap();

    // `Image` does not implement `Debug`, so the code maps each value to `()`.
    let exported = repo
        .export_composefs(&commit, &ComposefsOptions::default())
        .await
        .map(|_| ());
    assert_eq!(
        staged.is_ok(),
        exported.is_ok(),
        "the staged digest path reached {staged:?} and the export {exported:?}"
    );
    exported
}

/// One xattr takes its name, its value, and 7 bytes from the budget of the
/// inode, which is 32755 bytes. At the budget, the export builds the image. One
/// byte past the budget, the export refuses and names the attribute.
#[test]
fn holds_an_inode_to_the_composefs_xattr_budget() {
    let scratch = TmpDir::new("composefs-xattr-budget");
    let name = b"user.long\0".to_vec();
    // 7 + 9 (the name without its NUL) + value == 32755 at the budget.
    let at_budget = 32755 - 7 - 9;
    block_on(async {
        export_xattrs(
            &scratch.path().join("at"),
            RepoMode::BareUser,
            Carrier::Root,
            Xattrs::new([(name.clone(), vec![b'x'; at_budget])]).unwrap(),
        )
        .await
        .expect("the export builds the image at the budget");

        let err = export_xattrs(
            &scratch.path().join("over"),
            RepoMode::BareUser,
            Carrier::Root,
            Xattrs::new([(name, vec![b'x'; at_budget + 1])]).unwrap(),
        )
        .await
        .expect_err("the export refuses one byte past the budget");
        let text = err.to_string();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the export refused with {err:?}"
        );
        assert!(
            text.contains("user.long") && text.contains("32756"),
            "the refusal names the attribute and the bytes it takes: {text}"
        );
    });
}

/// The budget applies to the whole inode, so two attributes that each fit
/// alone share one budget. The refusal names the attribute that takes the
/// inode past the budget.
#[test]
fn the_composefs_xattr_budget_covers_the_inode() {
    let scratch = TmpDir::new("composefs-xattr-budget-sum");
    // 2 * (7 + 6 + value) == 32756 one byte past the budget.
    let each = (32756 / 2) - 7 - 6;
    block_on(async {
        let err = export_xattrs(
            scratch.path(),
            RepoMode::BareUser,
            Carrier::Root,
            Xattrs::new([
                (b"user.a\0".to_vec(), vec![b'x'; each]),
                (b"user.b\0".to_vec(), vec![b'y'; each]),
            ])
            .unwrap(),
        )
        .await
        .expect_err("the export refuses the pair");
        let text = err.to_string();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the export refused with {err:?}"
        );
        assert!(
            text.contains("user.b") && text.contains("32756"),
            "the refusal names the second attribute: {text}"
        );
    });
}

/// A regular file has the same budget. The `trusted.overlay.redirect` and
/// `trusted.overlay.metacopy` attributes that the export adds to the inode are
/// outside the budget, so the walk accepts the file at the budget. The test
/// uses an archive repository, because the `user.ostreemeta` attribute of a
/// bare-user object cannot hold the attribute at this size.
#[test]
fn the_composefs_xattr_budget_covers_a_regular_file() {
    let scratch = TmpDir::new("composefs-xattr-budget-file");
    let name = b"user.long\0".to_vec();
    let at_budget = 32755 - 7 - 9;
    block_on(async {
        export_xattrs(
            &scratch.path().join("at"),
            RepoMode::Archive,
            Carrier::File,
            Xattrs::new([(name.clone(), vec![b'x'; at_budget])]).unwrap(),
        )
        .await
        .expect("the export builds the image at the budget");

        let err = export_xattrs(
            &scratch.path().join("over"),
            RepoMode::Archive,
            Carrier::File,
            Xattrs::new([(name, vec![b'x'; at_budget + 1])]).unwrap(),
        )
        .await
        .expect_err("the export refuses one byte past the budget");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the export refused with {err:?}"
        );
    });
}

/// Commits a tree that holds one symlink whose target is `len` bytes, in a
/// repository of its own under `dir`. Then walks the tree into the image.
async fn export_symlink(dir: &Path, len: usize) -> Result<(), Error> {
    let repo = Repo::create(dir, CreateOptions::new(RepoMode::BareUser))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let meta = FileMeta {
        uid: 0,
        gid: 0,
        mode: 0o120777,
        xattrs: Xattrs::empty(),
    };
    let link = txn
        .write_symlink(&"z".repeat(len), &meta, None)
        .await
        .unwrap();
    let mut mtree = MutableTree::new();
    mtree.replace_file("l", link).unwrap();
    let dirmeta_bytes = DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040755,
        xattrs: Xattrs::empty(),
    }
    .serialize()
    .unwrap();
    let dirmeta = txn
        .write_metadata(ObjectType::DirMeta, None, &dirmeta_bytes)
        .await
        .unwrap();
    mtree.set_metadata_checksum(dirmeta);
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some("symlink".to_owned()),
                timestamp: Some(0),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.commit().await.unwrap();
    // `Image` does not implement `Debug`, so the code maps the value to `()`.
    repo.export_composefs(&commit, &ComposefsOptions::default())
        .await
        .map(|_| ())
}

/// A symlink stores its target inline, next to a 32-byte compact inode header,
/// so a target with no attributes fits at 4063 bytes. At 4064 bytes, the
/// target does not fit. The `ostree` command 2026.1 writes the image at 4063
/// bytes and aborts at 4064 bytes (observed).
#[test]
fn holds_a_symlink_target_to_its_inode_block() {
    let scratch = TmpDir::new("composefs-symlink-block");
    block_on(async {
        export_symlink(&scratch.path().join("at"), 4063)
            .await
            .expect("the export builds the image at 4063 bytes");

        let err = export_symlink(&scratch.path().join("over"), 4064)
            .await
            .expect_err("the export refuses a target that fills the block");
        let text = err.to_string();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the export refused with {err:?}"
        );
        assert!(
            text.contains("4064"),
            "the refusal names the length: {text}"
        );
    });
}

/// Commits a tree that holds one regular file whose name is `len` bytes, in a
/// repository of its own under `dir`. Then walks the tree into the image.
async fn export_child_name(dir: &Path, len: usize) -> Result<(), Error> {
    let repo = Repo::create(dir, CreateOptions::new(RepoMode::BareUser))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let meta = FileMeta {
        uid: 0,
        gid: 0,
        mode: 0o100644,
        xattrs: Xattrs::empty(),
    };
    let file = txn
        .write_regfile_inline(None, &meta, b"named\n")
        .await
        .unwrap();
    let mut mtree = MutableTree::new();
    mtree.replace_file(&"n".repeat(len), file).unwrap();
    let dirmeta_bytes = DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040755,
        xattrs: Xattrs::empty(),
    }
    .serialize()
    .unwrap();
    let dirmeta = txn
        .write_metadata(ObjectType::DirMeta, None, &dirmeta_bytes)
        .await
        .unwrap();
    mtree.set_metadata_checksum(dirmeta);
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some("child name".to_owned()),
                timestamp: Some(0),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.commit().await.unwrap();
    // `Image` does not implement `Debug`, so the code maps the value to `()`.
    repo.export_composefs(&commit, &ComposefsOptions::default())
        .await
        .map(|_| ())
}

/// The image holds a child name of at most 255 bytes. The `ostree` command
/// 2026.1 refuses a 256-byte name with `File name too long` (observed).
#[test]
fn holds_a_child_name_to_255_bytes() {
    let scratch = TmpDir::new("composefs-child-name");
    block_on(async {
        export_child_name(&scratch.path().join("at"), 255)
            .await
            .expect("the export builds the image at 255 bytes");

        let err = export_child_name(&scratch.path().join("over"), 256)
            .await
            .expect_err("the export refuses a 256-byte name");
        let text = err.to_string();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the export refused with {err:?}"
        );
        assert!(
            text.contains("256 bytes"),
            "the refusal names the length: {text}"
        );
    });
}

/// An xattr name has a one-byte length field in the image, so a name of more
/// than 255 bytes does not fit at any budget. At 255 bytes, the walk
/// accepts the attribute. At 256 bytes, the walk refuses and names it.
#[test]
fn holds_an_xattr_name_to_the_erofs_length_field() {
    let scratch = TmpDir::new("composefs-xattr-name");
    let name_of = |len: usize| {
        let mut name = b"user.".to_vec();
        name.resize(len, b'n');
        name.push(0);
        name
    };
    block_on(async {
        export_xattrs(
            &scratch.path().join("at"),
            RepoMode::Archive,
            Carrier::File,
            Xattrs::new([(name_of(255), b"v".to_vec())]).unwrap(),
        )
        .await
        .expect("the export builds the image at 255 bytes of name");

        let err = export_xattrs(
            &scratch.path().join("over"),
            RepoMode::Archive,
            Carrier::File,
            Xattrs::new([(name_of(256), b"v".to_vec())]).unwrap(),
        )
        .await
        .expect_err("the export refuses a 256-byte name");
        let text = err.to_string();
        assert!(
            matches!(err, Error::Unsupported(_)),
            "the export refused with {err:?}"
        );
        assert!(
            text.contains("user.nn") && text.contains("256"),
            "the refusal names the attribute and its length: {text}"
        );
    });
}

/// `commit_add_composefs_metadata` runs in an `archive` repository and records
/// the digest that a `bare-user` repository records for the same tree.
#[test]
fn digest_metadata_runs_in_an_archive_repository() {
    let Some(digest) = manifest_digest("composefs_digest") else {
        eprintln!("composefs fixture absent; skipping");
        return;
    };

    // The transaction publishes, so the test copies the archive fixture first.
    let scratch = TmpDir::new("composefs-archive-meta");
    let dst = scratch_fixture_repo(&scratch, "archive");

    block_on(async {
        let repo = Repo::open(&dst).await.unwrap();
        assert_eq!(repo.mode(), RepoMode::Archive, "the fixture is archive");
        let commit = Checksum::from_hex(COMMIT).unwrap();

        let txn = repo.transaction().await.unwrap();
        let stored = repo
            .commit_add_composefs_metadata(&txn, &commit)
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let (obj, _) = repo.load_commit(&stored).await.unwrap();
        let value = obj
            .metadata
            .dict_get("ostree.composefs.digest.v0")
            .expect("the new commit carries the digest key");
        let (_, inner) = value.as_variant().expect("digest value is a variant");
        let bytes = inner.as_bytes().expect("digest is a byte array");
        assert_eq!(
            to_hex(bytes),
            digest,
            "the archive repository records the digest the tool recorded"
        );
    });
}
