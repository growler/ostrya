#![forbid(unsafe_code)]

//! Tests of the mounts of the direct mounter. They need `CAP_SYS_ADMIN` in
//! the initial user namespace, so they skip for another user. If
//! `OSTRYA_REQUIRE_MOUNT` is set, a missing privilege or a file system
//! without fs-verity fails them.
//!
//! The tests check these facts:
//!
//! - With `verity=off`, a stored image with fs-verity digests mounts on
//!   objects without a seal, in `bare-user` and in `bare`, and the mounted
//!   tree is the committed tree.
//! - With `verity=require`, a stored image mounts on sealed objects. A
//!   changed object fails to open, with a seal and without one. With
//!   `verity=off`, the same object reads its new bytes.
//! - A built image and the stored image give the same tree, with
//!   `verity=off` and with `verity=require`.
//! - The unmount detaches the loop device, for a stored and a built image.
//! - A read-write mount writes each change to `<target>/overlay`, and the
//!   repository does not change.
//! - An unmount of a mount in use fails with `EBUSY`.
//! - The image of the caller mounts as the stored image does.

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use ostrya::{Checksum, Repo, RepoMode};
use ostrya_mount::{Access, Direct, Error, MountOptions};
use ostrya_rt::block_on;
use rustix::io::Errno;

use common::{
    Entry, INJECTED_DIRS, Key, MountGuard, TmpDir, build_source, commit_tree, loop_device_of,
    new_repo, object_with_content, require_mount, require_verity, wait_detached, walk,
};

/// The content of the file that the verity tests change.
const HELLO: &[u8] = b"hello composefs\n";

/// Read-only mount options.
fn read_only() -> MountOptions {
    MountOptions::default()
}

/// Read-write mount options.
fn read_write() -> MountOptions {
    let mut opts = MountOptions::default();
    opts.access = Access::ReadWrite;
    opts
}

/// Creates the empty directory `name` under `scratch` and returns it with a
/// guard that detaches each mount at it.
fn mount_point(scratch: &TmpDir, name: &str) -> (PathBuf, MountGuard) {
    let path = scratch.path().join(name);
    std::fs::create_dir(&path).unwrap();
    (path.clone(), MountGuard(path))
}

/// Walks the mounted tree at `target`. The image adds the top-level
/// directories in [`INJECTED_DIRS`], and the walk leaves them out.
fn walk_mount(target: &Path) -> Vec<Entry> {
    for dir in INJECTED_DIRS {
        assert!(target.join(dir).is_dir(), "{dir} is in the image");
    }
    walk(target, &INJECTED_DIRS)
}

/// Mounts the stored image of `commit` read-only at `target`, walks the
/// tree, and unmounts it.
async fn stored_tree(repo: &Repo, commit: &Checksum, target: &Path) -> Vec<Entry> {
    let direct = Direct::new();
    let root = direct
        .mount_stored(repo, commit, target, &read_only())
        .await
        .unwrap();
    drop(root);
    let tree = walk_mount(target);
    direct.unmount(target).await.unwrap();
    tree
}

/// Mounts the built image of `commit` read-only at `target`, walks the tree,
/// and unmounts it.
async fn built_tree(repo: &Repo, commit: &Checksum, target: &Path) -> Vec<Entry> {
    let direct = Direct::new();
    let root = direct
        .mount_built(repo, commit, target, &read_only())
        .await
        .unwrap();
    drop(root);
    let tree = walk_mount(target);
    direct.unmount(target).await.unwrap();
    tree
}

#[test]
fn verity_off_mounts_a_computed_image_on_unsealed_objects() {
    if !require_mount() {
        return;
    }
    for mode in [RepoMode::BareUser, RepoMode::Bare] {
        let scratch = TmpDir::new("verity-off");
        let base = scratch.path().join("tree");
        build_source(&base);
        let (target, _guard) = mount_point(&scratch, "mnt");
        block_on(async {
            let repo = new_repo(
                &scratch.path().join("repo"),
                mode,
                "[ex-integrity]\nfsverity=no\n",
            )
            .await;
            let commit = commit_tree(&repo, &base, 10, Key::Image).await;
            let image = repo.composefs_image_path(&commit);
            assert_eq!(std::fs::metadata(&image).unwrap().len() % 4096, 0);
            let tree = stored_tree(&repo, &commit, &target).await;
            assert_eq!(tree, walk(&base.join("src"), &[]), "{mode:?}");
        });
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    }
}

#[test]
fn verity_require_mounts_sealed_objects_and_fails_on_a_changed_object() {
    if !require_mount() {
        return;
    }
    let scratch = TmpDir::new("verity-require");
    if !require_verity(scratch.path()) {
        return;
    }
    let base = scratch.path().join("tree");
    build_source(&base);
    let (target, _guard) = mount_point(&scratch, "mnt");
    let root = scratch.path().join("repo");
    block_on(async {
        let repo = new_repo(&root, RepoMode::BareUser, "[ex-integrity]\nfsverity=yes\n").await;
        let commit = commit_tree(&repo, &base, 20, Key::Image).await;
        let direct = Direct::new();
        let source = walk(&base.join("src"), &[]);

        assert_eq!(stored_tree(&repo, &commit, &target).await, source);

        // An unsealed object with other bytes of the same size.
        let object = object_with_content(&root, HELLO);
        let changed = b"HELLO composefs\n";
        std::fs::remove_file(&object).unwrap();
        std::fs::write(&object, changed).unwrap();
        drop(
            direct
                .mount_stored(&repo, &commit, &target, &read_only())
                .await
                .unwrap(),
        );
        let err = std::fs::read(target.join("hello.txt")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(Errno::IO.raw_os_error()), "{err}");
        assert_eq!(
            std::fs::read(target.join("sub/nested.txt")).unwrap(),
            b"nested\n"
        );
        direct.unmount(&target).await.unwrap();

        // The same bytes with a seal: the digest is not the digest in the
        // image.
        let ro = std::fs::File::open(&object).unwrap();
        ostrya_sys::enable_verity(ro.as_fd()).unwrap();
        drop(ro);
        drop(
            direct
                .mount_stored(&repo, &commit, &target, &read_only())
                .await
                .unwrap(),
        );
        let err = std::fs::read(target.join("hello.txt")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(Errno::IO.raw_os_error()), "{err}");
        direct.unmount(&target).await.unwrap();

        // With `verity=off`, the overlay reads the changed object.
        drop(repo);
        let config = root.join("config");
        let text = std::fs::read_to_string(&config)
            .unwrap()
            .replace("fsverity=yes", "fsverity=no");
        std::fs::write(&config, text).unwrap();
        let repo = Repo::open(&root).await.unwrap();
        drop(
            direct
                .mount_stored(&repo, &commit, &target, &read_only())
                .await
                .unwrap(),
        );
        assert_eq!(std::fs::read(target.join("hello.txt")).unwrap(), changed);
        direct.unmount(&target).await.unwrap();
    });
}

#[test]
fn mount_built_and_mount_stored_give_the_same_tree() {
    if !require_mount() {
        return;
    }
    for (fsverity, timestamp) in [("no", 30), ("yes", 31)] {
        let scratch = TmpDir::new("built");
        if fsverity == "yes" && !require_verity(scratch.path()) {
            return;
        }
        let base = scratch.path().join("tree");
        build_source(&base);
        let (stored_at, _stored_guard) = mount_point(&scratch, "stored");
        let (built_at, _built_guard) = mount_point(&scratch, "built");
        block_on(async {
            let repo = new_repo(
                &scratch.path().join("repo"),
                RepoMode::BareUser,
                &format!("[ex-integrity]\nfsverity={fsverity}\n"),
            )
            .await;
            let commit = commit_tree(&repo, &base, timestamp, Key::Image).await;
            let stored = stored_tree(&repo, &commit, &stored_at).await;
            let built = built_tree(&repo, &commit, &built_at).await;
            assert_eq!(built, stored, "fsverity={fsverity}");
            assert_eq!(stored, walk(&base.join("src"), &[]));
        });
    }
}

#[test]
fn a_built_mount_needs_no_key() {
    if !require_mount() {
        return;
    }
    let scratch = TmpDir::new("built-no-key");
    let base = scratch.path().join("tree");
    build_source(&base);
    let (target, _guard) = mount_point(&scratch, "mnt");
    block_on(async {
        let repo = new_repo(&scratch.path().join("repo"), RepoMode::BareUser, "").await;
        let commit = commit_tree(&repo, &base, 35, Key::None).await;
        assert_eq!(
            built_tree(&repo, &commit, &target).await,
            walk(&base.join("src"), &[])
        );
    });
}

#[test]
fn unmount_frees_the_loop_device() {
    if !require_mount() {
        return;
    }
    let scratch = TmpDir::new("unmount");
    let base = scratch.path().join("tree");
    build_source(&base);
    let (target, _guard) = mount_point(&scratch, "mnt");
    block_on(async {
        let repo = new_repo(&scratch.path().join("repo"), RepoMode::BareUser, "").await;
        let commit = commit_tree(&repo, &base, 40, Key::Image).await;
        let direct = Direct::new();

        drop(
            direct
                .mount_stored(&repo, &commit, &target, &read_only())
                .await
                .unwrap(),
        );
        let image = repo.composefs_image_path(&commit);
        let image = std::fs::canonicalize(image).unwrap();
        let image = image.to_str().unwrap();
        let number = loop_device_of(image, false).expect("a loop device");
        direct.unmount(&target).await.unwrap();
        wait_detached(number, image, false);

        drop(
            direct
                .mount_built(&repo, &commit, &target, &read_only())
                .await
                .unwrap(),
        );
        let memfd = format!("/memfd:ostrya-cfs-{commit}");
        let number = loop_device_of(&memfd, true).expect("a loop device");
        direct.unmount(&target).await.unwrap();
        wait_detached(number, &memfd, true);
    });
}

#[test]
fn a_read_write_mount_writes_to_the_upper_directory() {
    if !require_mount() {
        return;
    }
    let scratch = TmpDir::new("read-write");
    let base = scratch.path().join("tree");
    build_source(&base);
    let (target, _guard) = mount_point(&scratch, "mnt");
    let root = scratch.path().join("repo");
    block_on(async {
        let repo = new_repo(&root, RepoMode::BareUser, "").await;
        let commit = commit_tree(&repo, &base, 50, Key::Image).await;
        let objects = walk(&root.join("objects"), &[]);
        let direct = Direct::new();

        drop(
            direct
                .mount_stored(&repo, &commit, &target, &read_write())
                .await
                .unwrap(),
        );
        assert!(
            !target.join("overlay").exists(),
            "the mount hides the upper dir"
        );
        std::fs::write(target.join("new.txt"), b"new\n").unwrap();
        std::fs::remove_file(target.join("readonly.txt")).unwrap();
        std::fs::write(target.join("hello.txt"), b"changed\n").unwrap();
        direct.unmount(&target).await.unwrap();

        let upper = target.join("overlay");
        assert_eq!(std::fs::read(upper.join("new.txt")).unwrap(), b"new\n");
        assert_eq!(
            std::fs::read(upper.join("hello.txt")).unwrap(),
            b"changed\n"
        );
        let whiteout = std::fs::symlink_metadata(upper.join("readonly.txt")).unwrap();
        {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            assert!(whiteout.file_type().is_char_device(), "a whiteout");
            assert_eq!(whiteout.rdev(), 0);
        }
        assert!(target.join("work").is_dir());
        assert_eq!(
            walk(&root.join("objects"), &[]),
            objects,
            "the repository is the same"
        );
    });
}

#[test]
fn an_unmount_of_a_mount_in_use_fails() {
    if !require_mount() {
        return;
    }
    let scratch = TmpDir::new("busy");
    let base = scratch.path().join("tree");
    build_source(&base);
    let (target, _guard) = mount_point(&scratch, "mnt");
    block_on(async {
        let repo = new_repo(&scratch.path().join("repo"), RepoMode::BareUser, "").await;
        let commit = commit_tree(&repo, &base, 60, Key::Image).await;
        let direct = Direct::new();
        let root = direct
            .mount_stored(&repo, &commit, &target, &read_only())
            .await
            .unwrap();
        let err = direct.unmount(&target).await.unwrap_err();
        assert!(
            matches!(
                err,
                Error::Sys {
                    errno: Errno::BUSY,
                    ..
                }
            ),
            "{err}"
        );
        drop(root);
        direct.unmount(&target).await.unwrap();
    });
}

#[test]
fn an_image_of_the_caller_mounts() {
    if !require_mount() {
        return;
    }
    let scratch = TmpDir::new("caller-image");
    let base = scratch.path().join("tree");
    build_source(&base);
    let (target, _guard) = mount_point(&scratch, "mnt");
    block_on(async {
        let repo = new_repo(&scratch.path().join("repo"), RepoMode::BareUser, "").await;
        let commit = commit_tree(&repo, &base, 70, Key::None).await;
        let path = scratch.path().join("image.cfs");
        let file = std::fs::File::create(&path).unwrap();
        repo.export_composefs_to(&commit, &ostrya::ComposefsOptions::default(), file.as_fd())
            .await
            .unwrap();
        drop(file);
        let file = std::fs::File::open(&path).unwrap();
        let direct = Direct::new();
        drop(
            direct
                .mount_image(file.as_fd(), &repo, &target, &read_only())
                .await
                .unwrap(),
        );
        drop(file);
        let tree = walk_mount(&target);
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let line = mountinfo
            .lines()
            .find(|l| l.contains(target.to_str().unwrap()))
            .expect("the mount is listed");
        assert!(line.contains(" overlay composefs "), "{line}");
        direct.unmount(&target).await.unwrap();
        assert_eq!(tree, walk(&base.join("src"), &[]));
    });
}
