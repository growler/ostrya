#![forbid(unsafe_code)]

//! Tests of the composefs image object, `objects/<xx>/<commit>.cfs`.
//!
//! The tests check these facts:
//!
//! - The fs-verity digest of a stored image is the value of
//!   `ostree.composefs.digest.v0` in its commit, and the image bytes are the
//!   bytes of an export with [`ComposefsOptions::RECORDED`]. With the golden
//!   fixture, the image of the fixture commit is the golden image `tree.cfs`.
//! - A write refuses a commit without the key, a malformed key, and an image
//!   of another tree, and stores nothing.
//! - A changed image fails the check and fsck, and a second write replaces
//!   it. An image that does not read fails in the same way, and a write
//!   replaces it too. fsck with `delete` removes both, and keeps the image of
//!   a commit that does not load.
//! - Prune removes the image with its commit, and removes an image whose
//!   commit is absent. The image changes no prune statistic.
//! - The image bytes are the same in `bare`, `bare-user`, and `archive`.
//!
//! The test of the golden image skips if the composefs fixture is absent. The
//! tests that seal the image skip if the file system has no fs-verity. The
//! tests that make a file unreadable with the mode 000 skip as root.

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use ostrya::{
    Checksum, CommitOptions, ComposefsImageAdd, ComposefsImageState, ComposefsOptions, Error,
    FsckImageErrorKind, FsckOptions, MutableTree, PruneOptions, PruneStats, Repo, RepoMode, Value,
};
use ostrya_composefs::FsVerityHasher;
use ostrya_core::{ObjectName, ObjectType, loose_path};
use ostrya_rt::block_on;

use common::composefs::{
    DIGEST_KEY, build_owned_source, commit_owned, commit_tree, composefs_dir, dict,
    manifest_digest, new_repo, scratch_fixture_repo, verity_supported,
};
use common::{COMMIT, TmpDir, file_inventory, is_sealed};

/// Returns the digest that `commit` records under the image key.
async fn recorded(repo: &Repo, commit: &Checksum) -> [u8; 32] {
    let (obj, _) = repo.load_commit(commit).await.unwrap();
    let value = obj
        .metadata
        .dict_get(DIGEST_KEY)
        .expect("the commit has the key");
    let (_, bytes) = value.as_variant().expect("the key holds a variant");
    bytes.as_bytes().unwrap().try_into().unwrap()
}

/// Returns the fs-verity digest of the file at `path`, read in chunks.
fn file_digest(path: &Path) -> [u8; 32] {
    use std::io::Read;

    let mut file = std::fs::File::open(path).unwrap();
    let mut hasher = FsVerityHasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    hasher.finalize()
}

/// Returns the lowercase hex form of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Flips one byte in the middle of the file at `path`. The size of the file
/// does not change.
fn flip_middle_byte(path: &Path) {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let middle = file.metadata().unwrap().len() / 2;
    let mut byte = [0u8; 1];
    file.seek(SeekFrom::Start(middle)).unwrap();
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xff;
    file.seek(SeekFrom::Start(middle)).unwrap();
    file.write_all(&byte).unwrap();
}

/// The image of a commit has the digest that the commit records, and the bytes
/// of the export with [`ComposefsOptions::RECORDED`]. The listing names it,
/// and its mode is 0644. The image changes neither the commit checksum nor
/// the statistics of the transaction.
#[test]
fn a_stored_image_has_the_digest_the_commit_records() {
    let scratch = TmpDir::new("cfs-digest");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    block_on(async {
        let repo = new_repo(&scratch.path().join("image"), RepoMode::BareUser, "").await;
        let twin = new_repo(&scratch.path().join("plain"), RepoMode::BareUser, "").await;
        let (commit, stats) = commit_tree(&repo, &base, 1, true, None).await;
        let (twin_commit, twin_stats) = commit_tree(&twin, &base, 1, false, None).await;
        assert_eq!(commit, twin_commit, "the image does not change the commit");
        assert_eq!(stats, twin_stats, "no statistic counts the image");

        let key = recorded(&repo, &commit).await;
        let path = repo.composefs_image_path(&commit);
        assert_eq!(
            path,
            scratch.path().join("image/objects").join(loose_path(
                &commit,
                ObjectType::ComposefsImage,
                RepoMode::BareUser
            ))
        );
        assert_eq!(file_digest(&path), key, "the image digest is the key");
        let export = repo
            .export_composefs(&commit, &ComposefsOptions::RECORDED)
            .await
            .unwrap();
        assert_eq!(export.fs_verity, key);
        assert_eq!(std::fs::read(&path).unwrap(), export.bytes);

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o644, "mode {mode:o}");

        let listed = repo.list_objects().await.unwrap();
        assert!(listed.contains(&ObjectName::new(commit, ObjectType::ComposefsImage)));
        assert_eq!(
            repo.check_composefs_image(&commit).await.unwrap(),
            ComposefsImageState::Valid
        );

        // A second write changes nothing, in a new transaction and in the
        // transaction that staged the image.
        assert_eq!(
            repo.add_composefs_image(&commit).await.unwrap(),
            ComposefsImageAdd::AlreadyValid
        );
        assert_eq!(
            twin.add_composefs_image(&commit).await.unwrap(),
            ComposefsImageAdd::Added
        );
        assert_eq!(
            std::fs::read(twin.composefs_image_path(&commit)).unwrap(),
            export.bytes
        );
        std::fs::remove_file(twin.composefs_image_path(&commit)).unwrap();
        let txn = twin.transaction().await.unwrap();
        assert_eq!(
            txn.write_composefs_image(&commit).await.unwrap(),
            ComposefsImageAdd::Added
        );
        assert_eq!(
            txn.write_composefs_image(&commit).await.unwrap(),
            ComposefsImageAdd::AlreadyValid
        );
        txn.commit().await.unwrap();
        assert_eq!(
            twin.check_composefs_image(&commit).await.unwrap(),
            ComposefsImageState::Valid
        );
    });
}

/// The image of the fixture commit is the golden image that the `ostree`
/// command exported, and its digest is the digest of the MANIFEST. Skips if
/// the composefs fixture is absent.
#[test]
fn the_image_of_the_fixture_commit_is_the_golden_image() {
    let Some(digest) = manifest_digest("composefs_digest") else {
        eprintln!("composefs fixture absent; skipping");
        return;
    };
    let golden = std::fs::read(composefs_dir().join("tree.cfs")).unwrap();
    let scratch = TmpDir::new("cfs-golden");
    let dst = scratch_fixture_repo(&scratch, "bare-user");
    block_on(async {
        let repo = Repo::open(&dst).await.unwrap();
        let fixture = Checksum::from_hex(COMMIT).unwrap();
        let txn = repo.transaction().await.unwrap();
        let commit = repo
            .commit_add_composefs_metadata(&txn, &fixture)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        assert!(
            !repo
                .has_object(ObjectType::ComposefsImage, &commit)
                .await
                .unwrap(),
            "the metadata alone stores no image"
        );

        assert_eq!(
            repo.add_composefs_image(&commit).await.unwrap(),
            ComposefsImageAdd::Added
        );
        let path = repo.composefs_image_path(&commit);
        assert_eq!(to_hex(&file_digest(&path)), digest);
        assert_eq!(to_hex(&recorded(&repo, &commit).await), digest);
        assert!(
            std::fs::read(&path).unwrap() == golden,
            "not the golden image"
        );
    });
}

/// Each write refuses a commit without the key, a malformed key, and an
/// image of another tree, and the object store does not change.
#[test]
fn a_write_needs_the_key_of_the_commit() {
    let scratch = TmpDir::new("cfs-key");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    let root = scratch.path().join("repo");
    block_on(async {
        let repo = new_repo(&root, RepoMode::BareUser, "").await;
        let plain = commit_owned(&repo, &base).await;
        let (keyed, _) = commit_tree(&repo, &base, 7, false, None).await;
        let before = file_inventory(&root, "objects");

        let err = repo.add_composefs_image(&plain).await.unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err}");

        // A malformed key: a string in place of the bytes.
        let (tree, _) = repo.read_commit(&plain.to_hex()).await.unwrap();
        let txn = repo.transaction().await.unwrap();
        let bad = txn
            .write_commit(
                CommitOptions {
                    timestamp: Some(9),
                    metadata: Some(dict(DIGEST_KEY, "s", Value::Str("digest".into()))),
                    ..CommitOptions::default()
                },
                &tree,
            )
            .await
            .unwrap();
        let err = txn.write_composefs_image(&bad).await.unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
        txn.abort().await.unwrap();

        // An image of another tree, attached to a commit with the key.
        std::fs::write(base.join("src/extra.txt"), b"another tree\n").unwrap();
        let txn = repo.transaction().await.unwrap();
        let mut mtree = MutableTree::new();
        let dfd = std::fs::File::open(&base).unwrap();
        txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
            .await
            .unwrap();
        let other = txn.write_mtree(&mut mtree).await.unwrap();
        let image = txn.build_composefs_image(&other).await.unwrap();
        let actual = *image.digest();
        let err = txn.attach_composefs_image(&keyed, image).await.unwrap_err();
        match err {
            Error::ComposefsDigestMismatch {
                commit,
                expected,
                actual: got,
            } => {
                assert_eq!(commit, keyed);
                assert_eq!(expected, recorded(&repo, &keyed).await);
                assert_eq!(got, actual);
            }
            other => panic!("{other}"),
        }
        let image = txn.build_composefs_image(&other).await.unwrap();
        let err = txn.attach_composefs_image(&plain, image).await.unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err}");
        txn.abort().await.unwrap();

        assert_eq!(file_inventory(&root, "objects"), before);
        let staging = std::fs::read_dir(root.join("tmp"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("staging-"))
            .count();
        assert_eq!(staging, 0, "no staging directory stays");
    });
}

/// A changed image fails the check and fsck, and marks no commit partial. A
/// write replaces it, and fsck with `delete` removes it.
#[test]
fn a_changed_image_fails_the_check_and_a_write_replaces_it() {
    let scratch = TmpDir::new("cfs-corrupt");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    block_on(async {
        let repo = new_repo(
            &scratch.path().join("repo"),
            RepoMode::BareUser,
            "[ex-integrity]\nfsverity=no\n",
        )
        .await;
        let (commit, _) = commit_tree(&repo, &base, 1, true, Some("main")).await;
        let key = recorded(&repo, &commit).await;
        let path = repo.composefs_image_path(&commit);
        let size = std::fs::metadata(&path).unwrap().len();

        flip_middle_byte(&path);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size);
        let actual = file_digest(&path);
        assert_ne!(actual, key);
        assert_eq!(
            repo.check_composefs_image(&commit).await.unwrap(),
            ComposefsImageState::Mismatch {
                expected: key,
                actual
            }
        );

        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert!(!report.is_ok());
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(report.marked_partial.is_empty());
        assert_eq!(report.images_checked, 1);
        assert_eq!(report.image_errors.len(), 1);
        assert_eq!(report.image_errors[0].commit, commit);
        assert!(matches!(
            report.image_errors[0].kind,
            FsckImageErrorKind::Mismatch { expected, actual: got } if expected == key && got == actual
        ));
        assert!(path.exists(), "fsck without delete keeps the image");

        assert_eq!(
            repo.add_composefs_image(&commit).await.unwrap(),
            ComposefsImageAdd::Replaced
        );
        assert_eq!(
            repo.check_composefs_image(&commit).await.unwrap(),
            ComposefsImageState::Valid
        );
        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert!(report.is_ok(), "{report:?}");
        assert_eq!(report.images_checked, 1);

        flip_middle_byte(&path);
        let opts = FsckOptions {
            delete: true,
            ..FsckOptions::default()
        };
        let report = repo.fsck(&opts).await.unwrap();
        assert_eq!(report.image_errors.len(), 1);
        assert_eq!(
            report.deleted,
            vec![ObjectName::new(commit, ObjectType::ComposefsImage)]
        );
        assert!(report.marked_partial.is_empty());
        assert!(!path.exists());
        assert_eq!(
            repo.check_composefs_image(&commit).await.unwrap(),
            ComposefsImageState::Absent
        );
        assert_eq!(
            repo.add_composefs_image(&commit).await.unwrap(),
            ComposefsImageAdd::Added
        );
    });
}

/// Sets the permission bits of the file at `path` to `mode`.
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// An image that does not read fails the check and fsck. A write replaces it,
/// and fsck with `delete` removes it. The mode 000 makes a read fail as an I/O
/// error does.
#[test]
fn an_image_that_does_not_read_is_replaced_and_fsck_delete_removes_it() {
    if rustix::process::geteuid().is_root() {
        eprintln!("skipping: root reads a file with the mode 000");
        return;
    }
    let scratch = TmpDir::new("cfs-unreadable");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    block_on(async {
        let repo = new_repo(
            &scratch.path().join("repo"),
            RepoMode::BareUser,
            "[ex-integrity]\nfsverity=no\n",
        )
        .await;
        let (commit, _) = commit_tree(&repo, &base, 1, true, Some("main")).await;
        let path = repo.composefs_image_path(&commit);

        chmod(&path, 0o000);
        assert!(matches!(
            repo.check_composefs_image(&commit).await,
            Err(Error::Io(_))
        ));
        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert!(!report.is_ok());
        assert_eq!(report.images_checked, 1);
        assert_eq!(report.image_errors.len(), 1);
        assert!(
            matches!(
                report.image_errors[0].kind,
                FsckImageErrorKind::ImageUnreadable(_)
            ),
            "{report:?}"
        );
        assert!(path.exists(), "fsck without delete keeps the image");

        assert_eq!(
            repo.add_composefs_image(&commit).await.unwrap(),
            ComposefsImageAdd::Replaced
        );
        assert_eq!(
            repo.check_composefs_image(&commit).await.unwrap(),
            ComposefsImageState::Valid
        );
        assert!(repo.fsck(&FsckOptions::default()).await.unwrap().is_ok());

        chmod(&path, 0o000);
        let opts = FsckOptions {
            delete: true,
            ..FsckOptions::default()
        };
        let report = repo.fsck(&opts).await.unwrap();
        assert_eq!(report.image_errors.len(), 1);
        assert_eq!(
            report.deleted,
            vec![ObjectName::new(commit, ObjectType::ComposefsImage)]
        );
        assert!(!path.exists());
    });
}

/// fsck reports an image whose commit does not load, and `delete` keeps the
/// image. The mode 000 of the commit object makes its read fail. The commit
/// is partial, so the object walk does not read it, and `delete` does not
/// unlink it.
#[test]
fn fsck_delete_keeps_the_image_of_a_commit_that_does_not_load() {
    if rustix::process::geteuid().is_root() {
        eprintln!("skipping: root reads a file with the mode 000");
        return;
    }
    let scratch = TmpDir::new("cfs-commit-unreadable");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    block_on(async {
        let repo = new_repo(
            &scratch.path().join("repo"),
            RepoMode::BareUser,
            "[ex-integrity]\nfsverity=no\n",
        )
        .await;
        let (commit, _) = commit_tree(&repo, &base, 1, true, None).await;
        common::mark_partial(&repo, &commit);
        let commit_path = repo.path().join("objects").join(loose_path(
            &commit,
            ObjectType::Commit,
            RepoMode::BareUser,
        ));
        chmod(&commit_path, 0o000);

        let opts = FsckOptions {
            delete: true,
            ..FsckOptions::default()
        };
        let report = repo.fsck(&opts).await.unwrap();
        chmod(&commit_path, 0o644);
        assert!(!report.is_ok());
        assert_eq!(report.commits_partial, 1);
        let image = report
            .image_errors
            .iter()
            .find(|e| e.commit == commit)
            .unwrap_or_else(|| panic!("{report:?}"));
        assert!(
            matches!(image.kind, FsckImageErrorKind::CommitUnreadable(_)),
            "{report:?}"
        );
        assert!(
            !report
                .deleted
                .contains(&ObjectName::new(commit, ObjectType::ComposefsImage))
        );
        assert!(repo.composefs_image_path(&commit).exists());
    });
}

/// fsck reports an image whose commit is absent and passes, and checks the
/// image of a partial commit.
#[test]
fn fsck_reports_an_orphan_image_and_checks_a_partial_commit() {
    let scratch = TmpDir::new("cfs-fsck");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    block_on(async {
        let repo = new_repo(&scratch.path().join("repo"), RepoMode::BareUser, "").await;
        let (orphan, _) = commit_tree(&repo, &base, 1, true, None).await;
        let (partial, _) = commit_tree(&repo, &base, 2, true, None).await;
        let commit_path = |c: &Checksum| {
            repo.path()
                .join("objects")
                .join(loose_path(c, ObjectType::Commit, RepoMode::BareUser))
        };
        std::fs::remove_file(commit_path(&orphan)).unwrap();

        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert!(report.is_ok(), "{report:?}");
        assert_eq!(report.orphan_images, vec![orphan]);
        assert_eq!(report.images_checked, 1);

        common::mark_partial(&repo, &partial);
        flip_middle_byte(&repo.composefs_image_path(&partial));
        let report = repo.fsck(&FsckOptions::default()).await.unwrap();
        assert_eq!(report.commits_partial, 1);
        assert_eq!(report.image_errors.len(), 1);
        assert_eq!(report.image_errors[0].commit, partial);
    });
}

/// Two repositories that hold the same commits, one with images and one
/// without.
struct Twins {
    _scratch: TmpDir,
    with: Repo,
    without: Repo,
    /// The commit that the ref `main` names.
    kept: Checksum,
    /// A commit of another tree that no ref names.
    loose: Checksum,
}

/// Builds [`Twins`] under a new scratch directory named after `tag`.
async fn twins(tag: &str) -> Twins {
    let scratch = TmpDir::new(tag);
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    let with = new_repo(&scratch.path().join("with"), RepoMode::BareUser, "").await;
    let without = new_repo(&scratch.path().join("without"), RepoMode::BareUser, "").await;
    let (kept, _) = commit_tree(&with, &base, 1, true, Some("main")).await;
    assert_eq!(
        commit_tree(&without, &base, 1, false, Some("main")).await.0,
        kept
    );
    std::fs::write(base.join("src/extra.txt"), b"a file of the loose tree\n").unwrap();
    let (loose, _) = commit_tree(&with, &base, 2, true, None).await;
    assert_eq!(commit_tree(&without, &base, 2, false, None).await.0, loose);
    Twins {
        _scratch: scratch,
        with,
        without,
        kept,
        loose,
    }
}

impl Twins {
    /// Runs one prune on each repository, and requires the same statistics.
    async fn prune(&self, opts: &PruneOptions) -> PruneStats {
        let stats = self.with.prune(opts).await.unwrap();
        let plain = self.without.prune(opts).await.unwrap();
        assert_eq!(stats, plain, "the images change no statistic");
        stats
    }

    /// Returns `true` if the repository with images holds the image of
    /// `commit`.
    fn has_image(&self, commit: &Checksum) -> bool {
        self.with.composefs_image_path(commit).exists()
    }

    /// Returns the commit object path of `commit` in each repository.
    fn commit_paths(&self, commit: &Checksum) -> [PathBuf; 2] {
        [&self.with, &self.without].map(|repo| {
            repo.path().join("objects").join(loose_path(
                commit,
                ObjectType::Commit,
                RepoMode::BareUser,
            ))
        })
    }
}

/// Prune removes the image with its commit, and keeps the image of a kept
/// commit. Each run gives the statistics of the same run without images.
#[test]
fn prune_removes_the_image_with_its_commit() {
    block_on(async {
        // A walk from the refs alone.
        let t = twins("cfs-prune-refs").await;
        let stats = t
            .prune(&PruneOptions {
                refs_only: true,
                ..PruneOptions::default()
            })
            .await;
        assert!(stats.pruned_objects > 0);
        assert!(t.has_image(&t.kept));
        assert!(!t.has_image(&t.loose));

        // The deletion of one named commit.
        let t = twins("cfs-prune-delete").await;
        t.prune(&PruneOptions {
            delete_commit: Some(t.loose),
            ..PruneOptions::default()
        })
        .await;
        assert!(t.has_image(&t.kept));
        assert!(!t.has_image(&t.loose));

        // Commit objects alone.
        let t = twins("cfs-prune-commit-only").await;
        let stats = t
            .prune(&PruneOptions {
                refs_only: true,
                commit_only: true,
                ..PruneOptions::default()
            })
            .await;
        assert_eq!(stats.pruned_objects, 1);
        assert!(t.has_image(&t.kept));
        assert!(!t.has_image(&t.loose));

        // An image whose commit was removed out of band.
        let t = twins("cfs-prune-orphan").await;
        for path in t.commit_paths(&t.loose) {
            std::fs::remove_file(path).unwrap();
        }
        let dry = t
            .prune(&PruneOptions {
                no_prune: true,
                ..PruneOptions::default()
            })
            .await;
        assert!(t.has_image(&t.loose), "a dry run removes nothing");
        assert_eq!(t.prune(&PruneOptions::default()).await, dry);
        assert!(t.has_image(&t.kept));
        assert!(!t.has_image(&t.loose));
    });
}

/// The same tree gives the same image bytes in `bare`, `bare-user`, and
/// `archive`, and these are the bytes of the export.
#[test]
fn the_image_bytes_are_the_same_in_every_mode() {
    let scratch = TmpDir::new("cfs-modes");
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    block_on(async {
        let mut images = Vec::new();
        for (name, mode) in [
            ("bare", RepoMode::Bare),
            ("bare-user", RepoMode::BareUser),
            ("archive", RepoMode::Archive),
        ] {
            let repo = new_repo(&scratch.path().join(name), mode, "").await;
            let (commit, _) = commit_tree(&repo, &base, 1, true, None).await;
            let bytes = std::fs::read(repo.composefs_image_path(&commit)).unwrap();
            let export = repo
                .export_composefs(&commit, &ComposefsOptions::RECORDED)
                .await
                .unwrap();
            assert!(bytes == export.bytes, "{name}: the image is the export");
            images.push((name, bytes));
        }
        for (name, bytes) in &images[1..] {
            assert!(*bytes == images[0].1, "{name} differs from bare");
        }
    });
}

/// With `[ex-integrity] fsverity=yes`, the stored image is sealed, and the
/// kernel measures the digest that the commit records. Skips if the file
/// system has no fs-verity.
#[test]
fn a_sealing_repository_seals_the_image() {
    let scratch = TmpDir::new("cfs-sealed");
    if !verity_supported(scratch.path()) {
        eprintln!("skipping: the file system has no fs-verity");
        return;
    }
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    block_on(async {
        let repo = new_repo(
            &scratch.path().join("repo"),
            RepoMode::BareUser,
            "[ex-integrity]\nfsverity=yes\n",
        )
        .await;
        let (commit, _) = commit_tree(&repo, &base, 1, true, None).await;
        let path = repo.composefs_image_path(&commit);
        assert!(is_sealed(&path));
        let ro = std::fs::File::open(&path).unwrap();
        assert_eq!(
            ostrya_sys::measure_verity(ro.as_fd()).unwrap(),
            recorded(&repo, &commit).await
        );
        assert_eq!(
            repo.check_composefs_image(&commit).await.unwrap(),
            ComposefsImageState::Valid
        );
    });
}

/// With `[ex-integrity] fsverity=yes` on a file system without fs-verity,
/// the write fails and stores nothing. The test runs on tmpfs at `/dev/shm`.
#[test]
fn a_required_seal_that_fails_stores_no_image() {
    let shm = Path::new("/dev/shm");
    if !shm.is_dir() {
        eprintln!("skipping: /dev/shm is absent");
        return;
    }
    let dir = shm.join(format!("ostrya-cfs-seal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    if verity_supported(&dir) {
        eprintln!("skipping: /dev/shm has fs-verity");
        return;
    }
    let base = dir.join("tree");
    build_owned_source(&base);
    let root = dir.join("repo");
    block_on(async {
        let repo = new_repo(&root, RepoMode::BareUser, "").await;
        let (commit, _) = commit_tree(&repo, &base, 1, false, None).await;
        drop(repo);
        let config = root.join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("[ex-integrity]\nfsverity=yes\n");
        std::fs::write(&config, text).unwrap();
        let repo = Repo::open(&root).await.unwrap();
        let before = file_inventory(&root, "objects");

        let err = repo.add_composefs_image(&commit).await.unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        assert_eq!(file_inventory(&root, "objects"), before);
        assert!(!repo.composefs_image_path(&commit).exists());
    });
}
