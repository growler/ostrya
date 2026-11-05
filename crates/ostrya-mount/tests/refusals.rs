#![forbid(unsafe_code)]

//! Tests of the refusals of the direct mounter that come before the first
//! privileged system call, so they run as any user:
//!
//! - an `archive` repository;
//! - a commit without the composefs key, a commit with no stored image, and
//!   a stored image with one byte changed;
//! - a symlink at each component of the path of a stored image;
//! - in the strict open mode, a symlink at the fan-out directory of the
//!   commit for a stored mount, and of the commit, a dirtree, a dirmeta, and a
//!   file for a built mount;
//! - an image of the caller that is empty or whose size is not a multiple of
//!   4096 bytes;
//! - a built mount with `[ex-integrity] fsverity=yes` and an object with no
//!   fs-verity seal;
//! - an unmount of a directory that is not an overlay mount.
//!
//! Each refusal leaves the target empty.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use ostrya::RepoMode;
use ostrya_mount::{Access, Direct, Error, Helper, HelperCode, MountOptions, Mounter};
use ostrya_rt::block_on;

use common::{Key, TmpDir, build_source, commit_tree, new_repo};

/// Compile-time checks that the public types are `Send + Sync`, and that the
/// futures of the mount calls of each front end are `Send`.
#[allow(dead_code)]
fn public_types_are_send_and_sync() {
    fn send_sync<T: Send + Sync>() {}
    fn send<T: Send>(_: &T) {}
    send_sync::<Direct>();
    send_sync::<Helper>();
    send_sync::<Mounter>();
    send_sync::<MountOptions>();
    send_sync::<Access>();
    send_sync::<Error>();
    send_sync::<HelperCode>();

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
        let helper = Helper::new().unwrap();
        let _ = helper.mount_stored(&repo, &commit, target, &opts).await;
        let _ = helper.mount_built(&repo, &commit, target, &opts).await;
        let _ = helper.unmount(target).await;
        let mounter = Mounter::from_env().unwrap();
        let _ = mounter.mount_stored(&repo, &commit, target, &opts).await;
        let _ = mounter.mount_built(&repo, &commit, target, &opts).await;
        let _ = mounter.unmount(target).await;
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
                Error::Repo(ostrya::Error::ComposefsImageNotFound { commit }) if commit == keyed
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

/// Returns `true` if `err` is a repository error with the error number
/// `ELOOP`.
fn is_eloop(err: &Error) -> bool {
    matches!(
        err,
        Error::Repo(ostrya::Error::Io(e)) if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
    )
}

/// Replaces the directory `path` with a symlink to `moved`, runs `f`, and
/// puts the directory back.
async fn with_symlink<F: std::future::Future<Output = ()>>(path: &Path, moved: &Path, f: F) {
    std::fs::rename(path, moved).unwrap();
    std::os::unix::fs::symlink(moved, path).unwrap();
    f.await;
    std::fs::remove_file(path).unwrap();
    std::fs::rename(moved, path).unwrap();
}

/// A symlink at `extensions/`, `ostrya/`, `composefs/`, or `<xx>/` of the
/// path of a stored image stops a stored mount with `ELOOP`.
#[test]
fn a_symlink_in_the_image_path_stops_a_stored_mount() {
    let scratch = TmpDir::new("image-symlink");
    let base = scratch.path().join("tree");
    build_source(&base);
    let target = scratch.path().join("mnt");
    std::fs::create_dir(&target).unwrap();
    block_on(async {
        let root = scratch.path().join("repo");
        let repo = new_repo(&root, RepoMode::BareUser, "").await;
        let commit = commit_tree(&repo, &base, 1, Key::Image).await;
        let hex = commit.to_hex();
        let moved = scratch.path().join("moved");
        for part in [
            "extensions".to_owned(),
            "extensions/ostrya".to_owned(),
            "extensions/ostrya/composefs".to_owned(),
            format!("extensions/ostrya/composefs/{}", &hex[..2]),
        ] {
            with_symlink(&root.join(&part), &moved, async {
                let err = Direct::new()
                    .mount_stored(&repo, &commit, &target, &MountOptions::default())
                    .await
                    .unwrap_err();
                assert!(is_eloop(&err), "{part}: {err}");
            })
            .await;
        }
    });
    assert_empty(&target);
}

/// With a handle of the strict open mode, a symlink at the fan-out directory
/// of the commit stops a stored mount, and a symlink at the fan-out
/// directory of the commit, of the root dirtree, of the root dirmeta, or of a
/// file stops a built mount, each with `ELOOP`.
#[test]
fn a_symlinked_fanout_stops_a_mount_of_a_strict_handle() {
    let scratch = TmpDir::new("fanout-symlink");
    let base = scratch.path().join("tree");
    build_source(&base);
    let target = scratch.path().join("mnt");
    std::fs::create_dir(&target).unwrap();
    block_on(async {
        let root = scratch.path().join("repo");
        let commit = {
            let repo = new_repo(&root, RepoMode::BareUser, "").await;
            commit_tree(&repo, &base, 1, Key::Image).await
        };
        let parent = std::fs::File::open(scratch.path()).unwrap();
        let repo = ostrya::Repo::open_at_strict(parent.as_fd(), Path::new("repo"))
            .await
            .unwrap();
        let (commit_obj, _) = repo.load_commit(&commit).await.unwrap();
        let file = common::object_with_content(
            &root,
            b"hello composefs
",
        );
        let objects = root.join("objects");
        let fanout = |hex: String| objects.join(&hex[..2]);
        let moved = scratch.path().join("moved");
        let opts = MountOptions::default();

        with_symlink(&fanout(commit.to_hex()), &moved, async {
            let err = Direct::new()
                .mount_stored(&repo, &commit, &target, &opts)
                .await
                .unwrap_err();
            assert!(is_eloop(&err), "stored commit: {err}");
        })
        .await;
        for (what, dir) in [
            ("commit", fanout(commit.to_hex())),
            ("dirtree", fanout(commit_obj.root_dirtree.to_hex())),
            ("dirmeta", fanout(commit_obj.root_dirmeta.to_hex())),
            ("file", file.parent().unwrap().to_owned()),
        ] {
            with_symlink(&dir, &moved, async {
                let err = Direct::new()
                    .mount_built(&repo, &commit, &target, &opts)
                    .await
                    .unwrap_err();
                assert!(is_eloop(&err), "built {what}: {err}");
            })
            .await;
        }
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

/// With `[ex-integrity] fsverity=yes`, a built mount takes the digest of each
/// backing object from the kernel. An object with no seal fails the build
/// before any mount step.
#[test]
fn a_built_mount_with_verity_needs_sealed_objects() {
    let scratch = TmpDir::new("unsealed");
    let base = scratch.path().join("tree");
    build_source(&base);
    let target = scratch.path().join("mnt");
    std::fs::create_dir(&target).unwrap();
    block_on(async {
        let root = scratch.path().join("repo");
        let repo = new_repo(&root, RepoMode::BareUser, "[ex-integrity]\nfsverity=no\n").await;
        let commit = commit_tree(&repo, &base, 1, Key::None).await;
        let cfg = root.join("config");
        let text = std::fs::read_to_string(&cfg)
            .unwrap()
            .replace("fsverity=no", "fsverity=yes");
        std::fs::write(&cfg, text).unwrap();
        let repo = ostrya::Repo::open(&root).await.unwrap();
        let err = Direct::new()
            .mount_built(&repo, &commit, &target, &MountOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Repo(ostrya::Error::Unsupported(text)) if text.contains("no fs-verity seal")),
            "{err}"
        );
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
