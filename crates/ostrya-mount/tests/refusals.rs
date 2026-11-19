#![forbid(unsafe_code)]

//! Tests of the refusals of the direct mounter that come before the first
//! privileged system call, so they run as any user:
//!
//! - an image of the caller that is empty or whose size is not a multiple of
//!   4096 bytes;
//! - an unmount of a directory that is not an overlay mount.
//!
//! Each refusal leaves the target empty.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use ostrya_mount::{Access, Direct, Error, Helper, HelperCode, MountFlags, MountOptions, Verity};

use common::TmpDir;

/// Compile-time checks that the public types are `Send + Sync`, and that the
/// futures of the mount calls of the client are `Send`.
#[allow(dead_code)]
fn public_types_are_send_and_sync() {
    fn send_sync<T: Send + Sync>() {}
    fn send<T: Send>(_: &T) {}
    send_sync::<Direct>();
    send_sync::<Helper>();
    send_sync::<MountOptions>();
    send_sync::<MountFlags>();
    send_sync::<Access>();
    send_sync::<Verity>();
    send_sync::<Error>();
    send_sync::<HelperCode>();

    let fut = async {
        let repo = ostrya::Repo::open(Path::new("/")).await.unwrap();
        let commit: ostrya::Checksum = "0".repeat(64).parse().unwrap();
        let opts = MountOptions::default();
        let target = Path::new("/");
        let helper = Helper::new().unwrap();
        let _ = helper.mount_stored(&repo, &commit, target, &opts).await;
        let _ = helper.mount_built(&repo, &commit, target, &opts).await;
        let _ = helper.unmount(target).await;
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
fn an_image_of_the_caller_needs_whole_blocks() {
    let scratch = TmpDir::new("image");
    let target = scratch.path().join("mnt");
    std::fs::create_dir(&target).unwrap();
    let objects = scratch.path().join("objects");
    std::fs::create_dir(&objects).unwrap();
    let objects = std::fs::File::open(&objects).unwrap();
    let direct = Direct::new();
    let opts = MountOptions::default();
    for size in [0usize, 4097] {
        let path = scratch.path().join(format!("image-{size}"));
        std::fs::write(&path, vec![0u8; size]).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let err = direct
            .mount_image(file.as_fd(), objects.as_fd(), Verity::Off, &target, &opts)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidImage(_)), "{size}: {err}");
    }
    assert_empty(&target);
}

#[test]
fn an_unmount_needs_an_overlay_mount() {
    let scratch = TmpDir::new("unmount");
    let target = scratch.path().join("mnt");
    std::fs::create_dir(&target).unwrap();
    let err = Direct::new().unmount(&target).unwrap_err();
    assert!(
        matches!(err, Error::NotOverlayMount(ref p) if *p == target),
        "{err}"
    );
}
