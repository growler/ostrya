#![forbid(unsafe_code)]

//! Tests of the refusals of the direct mounter that come before the first
//! privileged system call, so they run as any user:
//!
//! - an `archive` repository;
//! - a commit without the composefs key, a commit with no stored image, and
//!   a stored image with one byte changed;
//! - an image of the caller that is empty or whose size is not a multiple of
//!   4096 bytes;
//! - an unmount of a directory that is not an overlay mount.
//!
//! Each refusal leaves the target empty.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use ostrya::{ObjectType, RepoMode};
use ostrya_mount::{Access, Direct, Error, MountOptions};
use ostrya_rt::block_on;

use common::{Key, TmpDir, build_source, commit_tree, new_repo};

/// Compile-time checks that the public types are `Send + Sync`, and that the
/// futures of the mount calls are `Send`.
#[allow(dead_code)]
fn public_types_are_send_and_sync() {
    fn send_sync<T: Send + Sync>() {}
    fn send<T: Send>(_: &T) {}
    send_sync::<Direct>();
    send_sync::<MountOptions>();
    send_sync::<Access>();
    send_sync::<Error>();

    let fut = async {
        let repo = ostrya::Repo::open(Path::new("/")).await.unwrap();
        let commit: ostrya::Checksum = "0".repeat(64).parse().unwrap();
        let opts = MountOptions::default();
        let direct = Direct::new();
        let target = Path::new("/");
        let _ = direct.mount_stored(&repo, &commit, target, &opts).await;
        let _ = direct.mount_built(&repo, &commit, target, &opts).await;
        let file = std::fs::File::open("/").unwrap();
        let _ = direct.mount_image(file.as_fd(), &repo, target, &opts).await;
        let _ = direct.unmount(target).await;
    };
    send(&fut);
}

/// Asserts that `dir` is empty.
fn assert_empty(dir: &Path) {
    assert_eq!(
        std::fs::read_dir(dir).unwrap().count(),
        0,
        "{}",
        dir.display()
    );
}

#[test]
fn an_archive_repository_is_refused() {
    let scratch = TmpDir::new("archive");
    let base = scratch.path().join("tree");
    build_source(&base);
    let target = scratch.path().join("mnt");
    std::fs::create_dir(&target).unwrap();
    block_on(async {
        let repo = new_repo(&scratch.path().join("repo"), RepoMode::Archive, "").await;
        let commit = commit_tree(&repo, &base, 1, Key::Image).await;
        let opts = MountOptions::default();
        let direct = Direct::new();
        let err = direct
            .mount_stored(&repo, &commit, &target, &opts)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedMode(RepoMode::Archive)),
            "{err}"
        );
        let err = direct
            .mount_built(&repo, &commit, &target, &opts)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedMode(RepoMode::Archive)),
            "{err}"
        );
    });
    assert_empty(&target);
}

#[test]
fn a_stored_mount_needs_a_valid_image() {
    let scratch = TmpDir::new("stored");
    let base = scratch.path().join("tree");
    build_source(&base);
    let target = scratch.path().join("mnt");
    std::fs::create_dir(&target).unwrap();
    block_on(async {
        let repo = new_repo(&scratch.path().join("repo"), RepoMode::BareUser, "").await;
        let plain = commit_tree(&repo, &base, 1, Key::None).await;
        let keyed = commit_tree(&repo, &base, 2, Key::Only).await;
        let stored = commit_tree(&repo, &base, 3, Key::Image).await;
        let mut opts = MountOptions::default();
        opts.access = Access::ReadWrite;
        let direct = Direct::new();

        let err = direct
            .mount_stored(&repo, &plain, &target, &opts)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Repo(ostrya::Error::InvalidInput(_))),
            "{err}"
        );

        let err = direct
            .mount_stored(&repo, &keyed, &target, &opts)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Repo(ostrya::Error::ObjectNotFound {
                    ty: ObjectType::ComposefsImage,
                    ..
                })
            ),
            "{err}"
        );

        let path = repo.composefs_image_path(&stored);
        let mut bytes = std::fs::read(&path).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        let err = direct
            .mount_stored(&repo, &stored, &target, &opts)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Repo(ostrya::Error::ComposefsDigestMismatch { .. })
            ),
            "{err}"
        );
    });
    assert_empty(&target);
}

#[test]
fn an_image_of_the_caller_needs_whole_blocks() {
    let scratch = TmpDir::new("image");
    let target = scratch.path().join("mnt");
    std::fs::create_dir(&target).unwrap();
    block_on(async {
        let repo = new_repo(&scratch.path().join("repo"), RepoMode::BareUser, "").await;
        let direct = Direct::new();
        let opts = MountOptions::default();
        for size in [0usize, 4097] {
            let path = scratch.path().join(format!("image-{size}"));
            std::fs::write(&path, vec![0u8; size]).unwrap();
            let file = std::fs::File::open(&path).unwrap();
            let err = direct
                .mount_image(file.as_fd(), &repo, &target, &opts)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::InvalidImage(_)), "{size}: {err}");
        }
    });
    assert_empty(&target);
}

#[test]
fn an_unmount_needs_an_overlay_mount() {
    let scratch = TmpDir::new("unmount");
    let target = scratch.path().join("mnt");
    std::fs::create_dir(&target).unwrap();
    block_on(async {
        let err = Direct::new().unmount(&target).await.unwrap_err();
        assert!(
            matches!(err, Error::NotOverlayMount(ref p) if *p == target),
            "{err}"
        );
    });
}
