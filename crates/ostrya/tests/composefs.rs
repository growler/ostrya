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
//!
//! The tests of the entry hook read no image structure. They search the image
//! for unique byte strings, and they compare the image of a hook on one tree
//! with the image of a second tree that stores the same metadata.

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use ostrya::{
    Checksum, CommitOptions, ComposefsEntryFn, ComposefsOptions, CreateOptions, DirMeta, EntryKind,
    Error, FileMeta, Metadata, MutableTree, Repo, RepoMode, VerityPolicy,
};
use ostrya_composefs::FsVerityHasher;
use ostrya_core::{ObjectType, Xattrs, loose_path};
use ostrya_rt::block_on;

use common::composefs::{
    build_owned_source, commit_owned, composefs_dir, manifest_digest, new_repo,
    scratch_fixture_repo,
};
use common::{COMMIT, HELLO_TXT, TmpDir, fixture_repo};

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
            .export_composefs(&commit, &ComposefsOptions { verity }, None)
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
            .export_composefs_to(&commit, &ComposefsOptions { verity }, None, file.as_fd())
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
                None,
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
            let from_bare = bare.export_composefs(&commit, &opts, None).await.unwrap();
            let from_user = user.export_composefs(&commit, &opts, None).await.unwrap();
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
            .export_composefs_to(&stored, &ComposefsOptions::RECORDED, None, file.as_fd())
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

        let before_computed = repo
            .export_composefs(&commit, &computed, None)
            .await
            .unwrap();
        let before_disabled = repo
            .export_composefs(&commit, &disabled, None)
            .await
            .unwrap();

        rewrite_payload(&content_object(&repo_dir, HELLO_TXT));

        let after_computed = repo
            .export_composefs(&commit, &computed, None)
            .await
            .unwrap();
        let after_disabled = repo
            .export_composefs(&commit, &disabled, None)
            .await
            .unwrap();

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
        .export_composefs(&commit, &ComposefsOptions::default(), None)
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
    repo.export_composefs(&commit, &ComposefsOptions::default(), None)
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
    repo.export_composefs(&commit, &ComposefsOptions::default(), None)
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

/// The export for a mount writes the bytes of the export, refuses an image
/// over its size limit with no write, and under `Computed` takes the digest
/// of each backing object from the kernel alone. An unsealed object fails
/// the export. The sealed part skips if the file system has no fs-verity.
#[test]
fn the_mount_export_writes_the_export_and_refuses_an_unsealed_object() {
    let scratch = TmpDir::new("composefs-mount-export");
    let repo_dir = scratch_fixture_repo(&scratch, "bare-user");
    let image_path = scratch.path().join("mount.cfs");

    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let commit = Checksum::from_hex(COMMIT).unwrap();
        let disabled = ComposefsOptions {
            verity: VerityPolicy::Disabled,
        };
        let want = repo
            .export_composefs(&commit, &disabled, None)
            .await
            .unwrap();

        let file = std::fs::File::create(&image_path).unwrap();
        let size = repo
            .export_composefs_for_mount(&commit, VerityPolicy::Disabled, file.as_fd(), u64::MAX)
            .await
            .unwrap();
        drop(file);
        assert_eq!(size, want.bytes.len() as u64);
        assert_eq!(std::fs::read(&image_path).unwrap(), want.bytes);

        let file = std::fs::File::create(&image_path).unwrap();
        let err = repo
            .export_composefs_for_mount(&commit, VerityPolicy::Disabled, file.as_fd(), size - 1)
            .await
            .unwrap_err();
        drop(file);
        assert!(
            matches!(&err, Error::Unsupported(text) if text.contains("more than the limit")),
            "{err}"
        );
        assert_eq!(std::fs::metadata(&image_path).unwrap().len(), 0);

        let file = std::fs::File::create(&image_path).unwrap();
        let err = repo
            .export_composefs_for_mount(&commit, VerityPolicy::Computed, file.as_fd(), u64::MAX)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Unsupported(text) if text.contains("no fs-verity seal")),
            "{err}"
        );
    });

    let Some(sealed) = seal_file_objects(&repo_dir) else {
        eprintln!("skipping the sealed part of the mount export check");
        return;
    };
    assert!(sealed > 0);
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let commit = Checksum::from_hex(COMMIT).unwrap();
        let want = repo
            .export_composefs(&commit, &ComposefsOptions::RECORDED, None)
            .await
            .unwrap();
        let file = std::fs::File::create(&image_path).unwrap();
        repo.export_composefs_for_mount(&commit, VerityPolicy::Computed, file.as_fd(), u64::MAX)
            .await
            .unwrap();
        drop(file);
        assert_eq!(std::fs::read(&image_path).unwrap(), want.bytes);
    });
}

/// The test label of the inode at `path`: a SELinux context that names the
/// path, with a NUL at its end. The NUL ends the label, so no label is a part
/// of another label.
fn label_of(path: &Path) -> Vec<u8> {
    let mut label = format!("system_u:object_r:hook_t:s0:{}", path.display()).into_bytes();
    label.push(0);
    label
}

/// Returns the number of times that `needle` occurs in `haystack`.
fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// Commits a flat tree in `repo` at timestamp 0 and returns the commit
/// checksum. The root dirmeta holds `root_xattrs`. Each entry of `files` is a
/// regular file with the mode 0644, the owner 0:0, its name, its content, and
/// its xattrs.
async fn commit_flat(
    repo: &Repo,
    root_xattrs: &Xattrs,
    files: &[(&str, &[u8], &Xattrs)],
) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    for (name, content, xattrs) in files {
        let meta = FileMeta {
            uid: 0,
            gid: 0,
            mode: 0o100644,
            xattrs: (*xattrs).clone(),
        };
        let file = txn
            .write_regfile_inline(None, &meta, content)
            .await
            .unwrap();
        mtree.replace_file(name, file).unwrap();
    }
    let dirmeta_bytes = DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040755,
        xattrs: root_xattrs.clone(),
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
                subject: Some("flat tree".to_owned()),
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

/// The hook sees each inode of the image one time, the five added top-level
/// directories included, with the kind of the inode. A label that the hook
/// sets on an inode goes into the image. The two export forms give the same
/// bytes with the hook, and the bytes differ from the image with no hook.
#[test]
fn the_entry_hook_sees_and_labels_each_inode() {
    let scratch = TmpDir::new("composefs-hook-label");
    let image_path = scratch.path().join("labeled.cfs");
    let repo_dir = fixture_repo("bare-user");
    let calls = Mutex::new(Vec::new());
    let hook: ComposefsEntryFn<'_> = &|path, kind, meta| {
        calls.lock().unwrap().push((path.to_path_buf(), kind));
        meta.xattrs
            .push((b"security.selinux".to_vec(), label_of(path)));
        Ok(())
    };
    let mut want: Vec<(PathBuf, EntryKind)> = [
        ("/", EntryKind::Directory),
        ("/boot", EntryKind::Directory),
        ("/etc", EntryKind::Directory),
        ("/sysroot", EntryKind::Directory),
        ("/usr", EntryKind::Directory),
        ("/var", EntryKind::Directory),
        ("/empty.txt", EntryKind::Regular),
        ("/hello.txt", EntryKind::Regular),
        ("/link", EntryKind::Symlink),
        ("/subdir", EntryKind::Directory),
        ("/subdir/nested.txt", EntryKind::Regular),
    ]
    .into_iter()
    .map(|(path, kind)| (PathBuf::from(path), kind))
    .collect();
    want.sort_by(|a, b| a.0.cmp(&b.0));

    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let commit = Checksum::from_hex(COMMIT).unwrap();
        let opts = ComposefsOptions::RECORDED;

        let image = repo
            .export_composefs(&commit, &opts, Some(hook))
            .await
            .unwrap();
        let mut seen = std::mem::take(&mut *calls.lock().unwrap());
        seen.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(seen, want, "the hook sees each inode one time");
        for (path, _) in &want {
            assert!(
                occurrences(&image.bytes, &label_of(path)) > 0,
                "the image holds the label of {}",
                path.display()
            );
        }

        let file = std::fs::File::create(&image_path).unwrap();
        let digest = repo
            .export_composefs_to(&commit, &opts, Some(hook), file.as_fd())
            .await
            .unwrap();
        drop(file);
        assert_eq!(std::fs::read(&image_path).unwrap(), image.bytes);
        assert_eq!(digest, image.fs_verity);
        assert_eq!(calls.lock().unwrap().len(), want.len());

        let plain = repo.export_composefs(&commit, &opts, None).await.unwrap();
        assert_ne!(plain.bytes, image.bytes);
    });
}

/// A label that the hook sets on the root gives the image of a tree whose
/// root dirmeta stores the same label. The whiteout stubs copy the label of
/// the root, so the two images are the same only if the stubs copy the label
/// that the hook set.
#[test]
fn the_whiteout_stubs_hold_the_root_label_of_the_hook() {
    let scratch = TmpDir::new("composefs-hook-whiteout");
    let label = label_of(Path::new("/"));
    let opts = ComposefsOptions::RECORDED;
    let hook: ComposefsEntryFn<'_> = &|path, _, meta| {
        if path == Path::new("/") {
            meta.xattrs
                .push((b"security.selinux".to_vec(), label.clone()));
        }
        Ok(())
    };
    block_on(async {
        let repo = new_repo(scratch.path(), RepoMode::Archive, "").await;
        let empty = Xattrs::empty();
        let mut stored_name = b"security.selinux".to_vec();
        stored_name.push(0);
        let stored = Xattrs::new([(stored_name, label.clone())]).unwrap();
        let x = commit_flat(&repo, &empty, &[("f", b"", &empty)]).await;
        let y = commit_flat(&repo, &stored, &[("f", b"", &empty)]).await;

        let hooked = repo.export_composefs(&x, &opts, Some(hook)).await.unwrap();
        let stored = repo.export_composefs(&y, &opts, None).await.unwrap();
        let plain = repo.export_composefs(&x, &opts, None).await.unwrap();
        assert_eq!(hooked.bytes, stored.bytes);
        assert_eq!(hooked.fs_verity, stored.fs_verity);
        assert_ne!(hooked.bytes, plain.bytes);
    });
}

/// A file capability is the xattr `security.capability` with a binary value.
/// The image holds the value that the hook sets byte for byte. On an empty
/// file, the hook gives the image of a tree that stores the same value.
#[test]
fn the_entry_hook_sets_a_binary_capability() {
    const CAP: [u8; 20] = [
        0x01, 0x00, 0x00, 0x02, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let opts = ComposefsOptions::RECORDED;
    let on = |target: &'static str| {
        move |path: &Path, _: EntryKind, meta: &mut Metadata| {
            if path == Path::new(target) {
                meta.xattrs
                    .push((b"security.capability".to_vec(), CAP.to_vec()));
            }
            Ok(())
        }
    };
    let on_hello = on("/hello.txt");
    let on_f = on("/f");

    let scratch = TmpDir::new("composefs-hook-capability");
    let repo_dir = fixture_repo("bare-user");
    block_on(async {
        let repo = Repo::open(&repo_dir).await.unwrap();
        let commit = Checksum::from_hex(COMMIT).unwrap();
        let image = repo
            .export_composefs(&commit, &opts, Some(&on_hello))
            .await
            .unwrap();
        let plain = repo.export_composefs(&commit, &opts, None).await.unwrap();
        assert_eq!(occurrences(&image.bytes, &CAP), 1);
        assert_eq!(occurrences(&plain.bytes, &CAP), 0);

        let repo = new_repo(&scratch.path().join("repo"), RepoMode::Archive, "").await;
        let empty = Xattrs::empty();
        let stored = Xattrs::new([(b"security.capability\0".to_vec(), CAP.to_vec())]).unwrap();
        let x = commit_flat(&repo, &empty, &[("f", b"", &empty)]).await;
        let y = commit_flat(&repo, &empty, &[("f", b"", &stored)]).await;
        let hooked = repo.export_composefs(&x, &opts, Some(&on_f)).await.unwrap();
        let stored = repo.export_composefs(&y, &opts, None).await.unwrap();
        assert_eq!(hooked.bytes, stored.bytes);
    });
}

/// Exports the fixture commit with a hook that pushes `xattrs` onto the inode
/// at `target`, and returns the error of the export.
async fn refusal_of(target: &str, xattrs: Vec<(Vec<u8>, Vec<u8>)>) -> Error {
    let repo = Repo::open(&fixture_repo("bare-user")).await.unwrap();
    let commit = Checksum::from_hex(COMMIT).unwrap();
    let hook: ComposefsEntryFn<'_> = &|path, _, meta| {
        if path == Path::new(target) {
            meta.xattrs.extend(xattrs.iter().cloned());
        }
        Ok(())
    };
    // `Image` does not implement `Debug`, so the code maps the value to `()`.
    repo.export_composefs(&commit, &ComposefsOptions::RECORDED, Some(hook))
        .await
        .map(|_| ())
        .expect_err("the export refuses the xattrs of the hook")
}

/// The check after the hook holds each inode to the xattr budget and each
/// name to 255 bytes, the added top-level directories included. It refuses
/// an empty name, a name with a NUL byte, and a name that occurs two times.
/// Each refusal is `Unsupported`, and the writer does not panic.
#[test]
fn the_check_after_the_hook_refuses_xattrs_the_image_cannot_hold() {
    let long_name = |len: usize| {
        let mut name = b"user.".to_vec();
        name.resize(len, b'n');
        name
    };
    block_on(async {
        for target in ["/", "/etc"] {
            let err = refusal_of(target, vec![(b"user.big".to_vec(), vec![b'x'; 70_000])]).await;
            assert!(
                matches!(&err, Error::Unsupported(text)
                    if text.contains("user.big") && text.contains("70015") && text.contains("32755")),
                "{target}: {err:?}"
            );
        }
        for (target, len) in [("/hello.txt", 305), ("/link", 256)] {
            let err = refusal_of(target, vec![(long_name(len), b"v".to_vec())]).await;
            assert!(
                matches!(&err, Error::Unsupported(text)
                    if text.contains(&format!("{len} bytes long")) && text.contains("255")),
                "{target}: {err:?}"
            );
        }
        let cases = [
            (
                vec![
                    (b"user.dup".to_vec(), b"a".to_vec()),
                    (b"user.dup".to_vec(), b"b".to_vec()),
                ],
                "two times",
            ),
            (vec![(Vec::new(), b"v".to_vec())], "empty"),
            (vec![(b"user.a\0b".to_vec(), b"v".to_vec())], "NUL"),
        ];
        for (xattrs, fragment) in cases {
            let err = refusal_of("/subdir/nested.txt", xattrs).await;
            assert!(
                matches!(&err, Error::Unsupported(text) if text.contains(fragment)),
                "{fragment}: {err:?}"
            );
        }
    });
}

/// Xattrs of 5000 bytes on a symlink fit the budget of the inode and fill
/// the inode block, so the block holds no byte of target. The export refuses
/// the symlink with `Unsupported`, and the writer does not panic.
#[test]
fn a_symlink_whose_xattrs_fill_its_block_is_refused() {
    block_on(async {
        let err = refusal_of("/link", vec![(b"user.big".to_vec(), vec![b'x'; 5000])]).await;
        assert!(
            matches!(&err, Error::Unsupported(text) if text.contains("holds 0 bytes of target")),
            "{err:?}"
        );
    });
}

/// An error of the hook stops the export, and the export returns that error
/// unchanged. The file form writes no byte, and the export calls the hook no
/// more after the error.
#[test]
fn an_error_of_the_hook_stops_the_export() {
    let scratch = TmpDir::new("composefs-hook-error");
    let image_path = scratch.path().join("refused.cfs");
    let opts = ComposefsOptions::RECORDED;
    let on_link: ComposefsEntryFn<'_> = &|path, _, _| {
        if path == Path::new("/link") {
            return Err(Error::InvalidInput("the hook refuses /link".to_owned()));
        }
        Ok(())
    };
    let calls = AtomicUsize::new(0);
    let always: ComposefsEntryFn<'_> = &|_, _, _| {
        calls.fetch_add(1, Ordering::Relaxed);
        Err(Error::InvalidInput(
            "the hook refuses each inode".to_owned(),
        ))
    };
    let is_link_refusal =
        |err: &Error| matches!(err, Error::InvalidInput(text) if text == "the hook refuses /link");
    block_on(async {
        let repo = Repo::open(&fixture_repo("bare-user")).await.unwrap();
        let commit = Checksum::from_hex(COMMIT).unwrap();

        let err = repo
            .export_composefs(&commit, &opts, Some(on_link))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(is_link_refusal(&err), "{err:?}");

        let file = std::fs::File::create(&image_path).unwrap();
        let err = repo
            .export_composefs_to(&commit, &opts, Some(on_link), file.as_fd())
            .await
            .unwrap_err();
        drop(file);
        assert!(is_link_refusal(&err), "{err:?}");
        assert_eq!(std::fs::metadata(&image_path).unwrap().len(), 0);

        let err = repo
            .export_composefs(&commit, &opts, Some(always))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    });
}

/// Two paths that name one file object give two inodes, and the hook sees
/// each one with its own metadata. Each label occurs one time in the image.
#[test]
fn the_hook_labels_each_path_to_one_object_on_its_own() {
    let scratch = TmpDir::new("composefs-hook-shared-object");
    let hook: ComposefsEntryFn<'_> = &|path, _, meta| {
        meta.xattrs
            .push((b"security.selinux".to_vec(), label_of(path)));
        Ok(())
    };
    block_on(async {
        let repo = new_repo(scratch.path(), RepoMode::Archive, "").await;
        let empty = Xattrs::empty();
        let content: &[u8] = b"shared bytes\n";
        let commit = commit_flat(
            &repo,
            &empty,
            &[("a", content, &empty), ("b", content, &empty)],
        )
        .await;
        let image = repo
            .export_composefs(&commit, &ComposefsOptions::RECORDED, Some(hook))
            .await
            .unwrap();
        for path in ["/a", "/b"] {
            assert_eq!(
                occurrences(&image.bytes, &label_of(Path::new(path))),
                1,
                "the label of {path} occurs one time"
            );
        }
    });
}
