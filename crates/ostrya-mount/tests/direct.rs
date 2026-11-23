#![forbid(unsafe_code)]

//! Tests of the mounts of the direct mounter. They need `CAP_SYS_ADMIN` in
//! the initial user namespace, so they skip for another user. If
//! `OSTRYA_REQUIRE_MOUNT` is set, a missing privilege or a file system
//! without fs-verity fails them.
//!
//! Each test opens or builds the image with `ostrya` and gives its
//! descriptor, the `objects` directory of the repository, and the `verity`
//! value of the repository config to the mounter. The tests check these
//! facts:
//!
//! - With `verity=off`, the image of an image commit, with fs-verity
//!   digests, mounts on objects without a seal, in `bare-user` and in
//!   `bare`, and the mounted tree is the committed tree.
//! - With `verity=require`, the image of an image commit mounts on sealed
//!   objects. A changed object fails to open, with a seal and without one.
//!   With `verity=off`, the same object reads its new bytes.
//! - An image that the test builds in a memory file and the image of the
//!   image commit give the same tree, with `verity=off` and with
//!   `verity=require`. With `verity=require`, the build compares the digest
//!   of the image with the key of the commit.
//! - The unmount detaches the loop device, for the image file of an image
//!   commit and for a memory file.
//! - A read-write mount writes each change to `<target>/overlay`, and the
//!   repository does not change.
//! - An unmount of a mount in use fails with `EBUSY`.
//! - An image file of the caller mounts with the source label `composefs`.
//! - The attribute flags of the options show on the mount, read-only and
//!   read-write, and a mount with no flag shows none of them.
//! - The image of an image commit that a hook labels mounts through the
//!   lookup, and the mount shows the xattr that the hook adds to a file.

mod common;

use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use ostrya::{
    COMPOSEFS_DIGEST_KEY, COMPOSEFS_RELATION, Checksum, CommitOptions, ComposefsEntryFn,
    ComposefsImage, MutableTree, Repo, RepoMode, Type, Value,
};
use ostrya_mount::{Access, Direct, Error, MountOptions};
use ostrya_rt::block_on;
use rustix::io::Errno;

use common::{
    Entry, INJECTED_DIRS, Key, MountGuard, TmpDir, build_source, built_image, commit_tree,
    loop_device_of, memfd_name, new_repo, object_with_content, require_mount, require_verity,
    stored_image, verity_of, wait_detached, walk,
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

/// Mounts the image of the image commit that `commit` names at `target`,
/// with the `objects` directory and the `verity` value of `repo`. Returns
/// the root of the mount and the opened image.
async fn mount_stored(
    repo: &Repo,
    commit: &Checksum,
    target: &Path,
    opts: &MountOptions,
) -> Result<(OwnedFd, ComposefsImage), Error> {
    let image = stored_image(repo, commit).await;
    let (verity, _) = verity_of(repo);
    Direct::new()
        .mount_image(image.file.as_fd(), repo.objects_dir(), verity, target, opts)
        .map(|root| (root, image))
}

/// Builds the image of `commit` in a memory file and mounts it at `target`,
/// with the `objects` directory and the `verity` value of `repo`.
async fn mount_built(
    repo: &Repo,
    commit: &Checksum,
    target: &Path,
    opts: &MountOptions,
) -> Result<OwnedFd, Error> {
    let image = built_image(repo, commit).await;
    let (verity, _) = verity_of(repo);
    Direct::new().mount_image(image.as_fd(), repo.objects_dir(), verity, target, opts)
}

/// Mounts the image of the image commit that `commit` names read-only at
/// `target`, walks the tree, and unmounts it. Returns the tree and the
/// opened image.
async fn stored_tree(
    repo: &Repo,
    commit: &Checksum,
    target: &Path,
) -> (Vec<Entry>, ComposefsImage) {
    let direct = Direct::new();
    let (root, image) = mount_stored(repo, commit, target, &read_only())
        .await
        .unwrap();
    drop(root);
    let tree = walk_mount(target);
    direct.unmount(target).unwrap();
    (tree, image)
}

/// Mounts the built image of `commit` read-only at `target`, walks the tree,
/// and unmounts it.
async fn built_tree(repo: &Repo, commit: &Checksum, target: &Path) -> Vec<Entry> {
    let direct = Direct::new();
    let root = mount_built(repo, commit, target, &read_only())
        .await
        .unwrap();
    drop(root);
    let tree = walk_mount(target);
    direct.unmount(target).unwrap();
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
            let (tree, image) = stored_tree(&repo, &commit, &target).await;
            assert_eq!(image.size % 4096, 0);
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

        assert_eq!(stored_tree(&repo, &commit, &target).await.0, source);

        // An unsealed object with other bytes of the same size.
        let object = object_with_content(&root, HELLO);
        let changed = b"HELLO composefs\n";
        std::fs::remove_file(&object).unwrap();
        std::fs::write(&object, changed).unwrap();
        drop(
            mount_stored(&repo, &commit, &target, &read_only())
                .await
                .unwrap(),
        );
        let err = std::fs::read(target.join("hello.txt")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(Errno::IO.raw_os_error()), "{err}");
        assert_eq!(
            std::fs::read(target.join("sub/nested.txt")).unwrap(),
            b"nested\n"
        );
        direct.unmount(&target).unwrap();

        // The same bytes with a seal: the digest is not the digest in the
        // image.
        let ro = std::fs::File::open(&object).unwrap();
        ostrya_sys::enable_verity(ro.as_fd()).unwrap();
        drop(ro);
        drop(
            mount_stored(&repo, &commit, &target, &read_only())
                .await
                .unwrap(),
        );
        let err = std::fs::read(target.join("hello.txt")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(Errno::IO.raw_os_error()), "{err}");
        direct.unmount(&target).unwrap();

        // With `verity=off`, the overlay reads the changed object.
        drop(repo);
        let config = root.join("config");
        let text = std::fs::read_to_string(&config)
            .unwrap()
            .replace("fsverity=yes", "fsverity=no");
        std::fs::write(&config, text).unwrap();
        let repo = Repo::open(&root).await.unwrap();
        drop(
            mount_stored(&repo, &commit, &target, &read_only())
                .await
                .unwrap(),
        );
        assert_eq!(std::fs::read(target.join("hello.txt")).unwrap(), changed);
        direct.unmount(&target).unwrap();
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
            let (stored, _) = stored_tree(&repo, &commit, &stored_at).await;
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

        let (root, image) = mount_stored(&repo, &commit, &target, &read_only())
            .await
            .unwrap();
        drop(root);
        let image =
            std::fs::read_link(format!("/proc/self/fd/{}", image.file.as_raw_fd())).unwrap();
        let image = image.to_str().unwrap();
        let number = loop_device_of(image, false).expect("a loop device");
        direct.unmount(&target).unwrap();
        wait_detached(number, image, false);

        drop(
            mount_built(&repo, &commit, &target, &read_only())
                .await
                .unwrap(),
        );
        let memfd = format!("/memfd:{}", memfd_name(&commit));
        let number = loop_device_of(&memfd, true).expect("a loop device");
        direct.unmount(&target).unwrap();
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
            mount_stored(&repo, &commit, &target, &read_write())
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
        direct.unmount(&target).unwrap();

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
        let (root, _image) = mount_stored(&repo, &commit, &target, &read_only())
            .await
            .unwrap();
        let err = direct.unmount(&target).unwrap_err();
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
        direct.unmount(&target).unwrap();
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
        repo.export_composefs_to(
            &commit,
            &ostrya::ComposefsOptions::default(),
            None,
            file.as_fd(),
        )
        .await
        .unwrap();
        drop(file);
        let file = std::fs::File::open(&path).unwrap();
        let direct = Direct::new();
        drop(
            direct
                .mount_image(
                    file.as_fd(),
                    repo.objects_dir(),
                    verity_of(&repo).0,
                    &target,
                    &read_only(),
                )
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
        direct.unmount(&target).unwrap();
        assert_eq!(tree, walk(&base.join("src"), &[]));
    });
}

/// Returns the mount options of the mount at `target`, the sixth field of
/// its mountinfo line.
fn mount_options_at(target: &Path) -> Vec<String> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let line = mountinfo
        .lines()
        .rfind(|l| l.split(' ').nth(4) == target.to_str())
        .expect("the mount is listed");
    line.split(' ')
        .nth(5)
        .unwrap()
        .split(',')
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_flags_of_the_options_show_on_the_mount() {
    if !require_mount() {
        return;
    }
    let scratch = TmpDir::new("flags");
    let base = scratch.path().join("tree");
    build_source(&base);
    let (target, _guard) = mount_point(&scratch, "mnt");
    let target = std::fs::canonicalize(target).unwrap();
    const FLAGS: [&str; 3] = ["nosuid", "nodev", "noexec"];
    block_on(async {
        let repo = new_repo(&scratch.path().join("repo"), RepoMode::BareUser, "").await;
        let commit = commit_tree(&repo, &base, 80, Key::Image).await;
        let direct = Direct::new();
        // One open checks the digest of the image. Each mount takes the same
        // descriptor.
        let image = stored_image(&repo, &commit).await;
        let (verity, _) = verity_of(&repo);
        let mount = |opts: &MountOptions| {
            direct
                .mount_image(
                    image.file.as_fd(),
                    repo.objects_dir(),
                    verity,
                    &target,
                    opts,
                )
                .unwrap()
        };
        for access in [Access::ReadOnly, Access::ReadWrite] {
            let mut opts = MountOptions::default();
            opts.access = access;
            drop(mount(&opts));
            let shown = mount_options_at(&target);
            for flag in FLAGS {
                assert!(!shown.iter().any(|o| o == flag), "{access:?}: {shown:?}");
            }
            direct.unmount(&target).unwrap();

            opts.flags.nosuid = true;
            opts.flags.nodev = true;
            opts.flags.noexec = true;
            drop(mount(&opts));
            let shown = mount_options_at(&target);
            for flag in FLAGS {
                assert!(shown.iter().any(|o| o == flag), "{access:?}: {shown:?}");
            }
            direct.unmount(&target).unwrap();

            let mut one = MountOptions::default();
            one.access = access;
            one.flags.nodev = true;
            drop(mount(&one));
            let shown = mount_options_at(&target);
            assert!(shown.iter().any(|o| o == "nodev"), "{access:?}: {shown:?}");
            assert!(
                !shown.iter().any(|o| o == "nosuid"),
                "{access:?}: {shown:?}"
            );
            assert!(
                !shown.iter().any(|o| o == "noexec"),
                "{access:?}: {shown:?}"
            );
            direct.unmount(&target).unwrap();
        }
    });
}

/// The name of the xattr that [`commit_labeled`] adds to `/hello.txt`.
const HOOK_XATTR: &str = "user.hooklabel";

/// The value of [`HOOK_XATTR`].
const HOOK_VALUE: &[u8] = b"labeled by the hook";

/// Commits `base/src` to `repo` at `timestamp`. The transaction writes the
/// image commit of the tree with a hook that adds [`HOOK_XATTR`] to
/// `/hello.txt`. The commit has the key with the digest of the image of the
/// tree with no hook and names the image commit as the attachment
/// `composefs`.
async fn commit_labeled(repo: &Repo, base: &Path, timestamp: u64) -> Checksum {
    let hook: ComposefsEntryFn<'_> = &|path, _, meta| {
        if path == Path::new("/hello.txt") {
            meta.xattrs
                .push((HOOK_XATTR.as_bytes().to_vec(), HOOK_VALUE.to_vec()));
        }
        Ok(())
    };
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("src"), &mut mtree, None)
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let (image, _labeled) = txn.write_composefs_commit(&root, Some(hook)).await.unwrap();
    let digest = txn.composefs_digest(&root).await.unwrap();
    let key = Value::Array(vec![Value::Tuple(vec![
        Value::Str(COMPOSEFS_DIGEST_KEY.to_owned()),
        Value::variant(Type::parse("ay").unwrap(), Value::Bytes(digest.to_vec())),
    ])]);
    let opts = CommitOptions {
        subject: Some("labeled mount tree".to_owned()),
        timestamp: Some(timestamp),
        metadata: Some(key),
        attachments: vec![(COMPOSEFS_RELATION.to_owned(), image)],
        ..CommitOptions::default()
    };
    let commit = txn.write_commit(opts, &root).await.unwrap();
    txn.commit().await.unwrap();
    commit
}

#[test]
fn the_image_of_a_hook_mounts_with_the_xattr_of_the_hook() {
    if !require_mount() {
        return;
    }
    let scratch = TmpDir::new("hook");
    let base = scratch.path().join("tree");
    build_source(&base);
    let (target, _guard) = mount_point(&scratch, "mnt");
    block_on(async {
        let repo = new_repo(
            &scratch.path().join("repo"),
            RepoMode::BareUser,
            "[ex-integrity]\nfsverity=no\n",
        )
        .await;
        let commit = commit_labeled(&repo, &base, 90).await;
        let (tree, _) = stored_tree(&repo, &commit, &target).await;

        let mut expected = walk(&base.join("src"), &[]);
        let hello = expected
            .iter_mut()
            .find(|entry| entry.path == Path::new("hello.txt"))
            .unwrap();
        hello
            .xattrs
            .push((HOOK_XATTR.to_owned(), HOOK_VALUE.to_vec()));
        hello.xattrs.sort();
        assert_eq!(tree, expected);
    });
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
}
