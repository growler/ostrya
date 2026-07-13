//! Overlay changeset import integration tests (Phase 7e).
//!
//! These synthesize overlayfs upperdir changesets on disk -- whiteout devices
//! through `mknodat` (char 0:0, unprivileged) and opacity through
//! `user.overlay.opaque` -- and merge them over a base `MutableTree` through
//! `merge_overlay_dfd_to_mtree`. The central check builds the expected merged
//! tree by hand and ingests it through `write_dfd_to_mtree`, asserting the two
//! roads reach the same root checksum. The rest cover whiteout deletion, opaque
//! replacement, `overlay.*` stripping, the metacopy/redirect hard errors,
//! cross-type replacement (a directory over a base symlink and leaves over base
//! directories), and the filter leaving base entries in place.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Error,
    FilterResult, MutableTree, Repo, RepoMode, TreeEntry,
};
use ostrya_rt::block_on;

/// Compile-time pin: the overlay merge future is `Send`, callbacks included.
fn assert_send<T: Send>(value: T) -> T {
    value
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mkdir(path: &Path, mode: u32) {
    std::fs::create_dir_all(path).unwrap();
    set_mode(path, mode);
}

fn write_file(path: &Path, content: &[u8], mode: u32) {
    std::fs::write(path, content).unwrap();
    set_mode(path, mode);
}

/// Create an overlayfs whiteout: a character device with device number 0:0.
/// Char 0:0 creation needs no capability.
fn whiteout(path: &Path) {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        rustix::fs::FileType::CharacterDevice,
        rustix::fs::Mode::from_raw_mode(0o600),
        rustix::fs::makedev(0, 0),
    )
    .unwrap();
}

/// Set an extended attribute (path-based, following) on `path`.
fn set_xattr(path: &Path, name: &str, value: &[u8]) {
    rustix::fs::setxattr(path, name, value, rustix::fs::XattrFlags::empty()).unwrap();
}

/// Mark a directory opaque in the rootless `user.*` namespace.
fn opaque(path: &Path) {
    set_xattr(path, "user.overlay.opaque", b"y");
}

/// Commit the on-disk tree at `path` (relative to `dfd`) onto `refname`, so it
/// can be hydrated with `MutableTree::from_commit`.
async fn commit_dir(
    repo: &Repo,
    dfd: std::os::fd::BorrowedFd<'_>,
    path: &Path,
    refname: &str,
    flags: CommitModifierFlags,
) {
    let txn = repo.transaction().await.unwrap();
    let mut modifier = CommitModifier::new(flags);
    let mut mtree = MutableTree::new();
    txn.write_dfd_to_mtree(dfd, path, &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(CommitOptions::default(), &root)
        .await
        .unwrap();
    txn.set_ref(refname, Some(&commit));
    txn.commit().await.unwrap();
}

/// The canonical-permissions, xattr-free flags the equivalence tests use so the
/// merge and the by-hand ingest agree on owner and mode.
fn canon_flags() -> CommitModifierFlags {
    CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS
}

#[test]
fn merge_equals_scratch_checkout_then_ingest() {
    // Merging a changeset over a hydrated base mtree reaches the same root
    // checksum as building the expected merged tree by hand and ingesting it.
    // Exercises: file modify, file add, whiteout delete, a merged directory
    // whose metadata changed and whose base-only file survives, and an opaque
    // directory replacement whose metadata changed.
    let tmp = TmpDir::new("overlay-equiv");
    let base = tmp.path();

    // Base tree on disk.
    let base_src = base.join("base");
    mkdir(&base_src, 0o755);
    write_file(&base_src.join("a.txt"), b"base-a", 0o644);
    write_file(&base_src.join("b.txt"), b"base-b", 0o644);
    mkdir(&base_src.join("sub"), 0o755);
    write_file(&base_src.join("sub/c.txt"), b"base-c", 0o644);
    write_file(&base_src.join("sub/d.txt"), b"base-d", 0o644);
    mkdir(&base_src.join("keep"), 0o755);
    write_file(&base_src.join("keep/old.txt"), b"old", 0o644);

    // Upperdir changeset.
    let upper = base.join("upper");
    mkdir(&upper, 0o755);
    write_file(&upper.join("a.txt"), b"UPPER-A", 0o644); // modify a
    write_file(&upper.join("e.txt"), b"upper-e", 0o644); // add e
    whiteout(&upper.join("b.txt")); // delete b
    mkdir(&upper.join("sub"), 0o700); // merged dir, mode 0755 -> 0700
    write_file(&upper.join("sub/c.txt"), b"UPPER-C", 0o644); // modify c; d untouched
    mkdir(&upper.join("keep"), 0o750); // opaque dir, mode 0755 -> 0750
    opaque(&upper.join("keep"));
    write_file(&upper.join("keep/new.txt"), b"new", 0o644);

    // The expected merged tree, built by hand.
    let scratch = base.join("scratch");
    mkdir(&scratch, 0o755);
    write_file(&scratch.join("a.txt"), b"UPPER-A", 0o644);
    write_file(&scratch.join("e.txt"), b"upper-e", 0o644);
    mkdir(&scratch.join("sub"), 0o700);
    write_file(&scratch.join("sub/c.txt"), b"UPPER-C", 0o644);
    write_file(&scratch.join("sub/d.txt"), b"base-d", 0o644);
    mkdir(&scratch.join("keep"), 0o750);
    write_file(&scratch.join("keep/new.txt"), b"new", 0o644);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();

        commit_dir(
            &repo,
            dfd.as_fd(),
            Path::new("base"),
            "test/base",
            canon_flags(),
        )
        .await;
        let mut mtree = MutableTree::from_commit(&repo, "test/base").await.unwrap();

        let txn = repo.transaction().await.unwrap();
        let mut modifier = CommitModifier::new(canon_flags());
        let upper_fd = std::fs::File::open(&upper).unwrap();
        assert_send(txn.merge_overlay_dfd_to_mtree(
            upper_fd.as_fd(),
            &mut mtree,
            Some(&mut modifier),
        ))
        .await
        .unwrap();
        let left = txn.write_mtree(&mut mtree).await.unwrap();
        let left_dirtree = *left.dirtree_checksum();
        let left_dirmeta = *left.dirmeta_checksum();
        txn.abort().await.unwrap();

        let txn = repo.transaction().await.unwrap();
        let mut modifier = CommitModifier::new(canon_flags());
        let mut scratch_mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("scratch"),
            &mut scratch_mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let right = txn.write_mtree(&mut scratch_mtree).await.unwrap();

        assert_eq!(
            left_dirtree,
            *right.dirtree_checksum(),
            "merge root dirtree equals the by-hand ingest"
        );
        assert_eq!(
            left_dirmeta,
            *right.dirmeta_checksum(),
            "merge root dirmeta equals the by-hand ingest"
        );
        txn.abort().await.unwrap();
    });
}

#[test]
fn whiteouts_remove_exactly_the_whited_out_paths() {
    // A whiteout removes its path (present or not) and leaves the rest intact.
    let tmp = TmpDir::new("overlay-whiteout");
    let base = tmp.path();

    let base_src = base.join("base");
    mkdir(&base_src, 0o755);
    write_file(&base_src.join("keep.txt"), b"keep", 0o644);
    write_file(&base_src.join("gone.txt"), b"gone", 0o644);

    let upper = base.join("upper");
    mkdir(&upper, 0o755);
    whiteout(&upper.join("gone.txt")); // deletes an existing entry
    whiteout(&upper.join("absent.txt")); // deletes a non-existent entry: a no-op

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        commit_dir(
            &repo,
            dfd.as_fd(),
            Path::new("base"),
            "test/base",
            canon_flags(),
        )
        .await;
        let mut mtree = MutableTree::from_commit(&repo, "test/base").await.unwrap();

        let txn = repo.transaction().await.unwrap();
        let mut modifier = CommitModifier::new(canon_flags());
        let upper_fd = std::fs::File::open(&upper).unwrap();
        txn.merge_overlay_dfd_to_mtree(upper_fd.as_fd(), &mut mtree, Some(&mut modifier))
            .await
            .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *root.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&base.join("repo")).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let names: Vec<&str> = tree.files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["keep.txt"], "only the whited-out entry is gone");
    });
}

#[test]
fn opaque_directory_drops_base_only_entries() {
    // An opaque upper directory drops the base's entries beneath that name and
    // keeps only what the upper provides.
    let tmp = TmpDir::new("overlay-opaque");
    let base = tmp.path();

    let base_src = base.join("base");
    mkdir(&base_src, 0o755);
    mkdir(&base_src.join("d"), 0o755);
    write_file(&base_src.join("d/base-only.txt"), b"base", 0o644);
    write_file(&base_src.join("d/shared.txt"), b"base-shared", 0o644);

    let upper = base.join("upper");
    mkdir(&upper, 0o755);
    mkdir(&upper.join("d"), 0o755);
    opaque(&upper.join("d"));
    write_file(&upper.join("d/shared.txt"), b"upper-shared", 0o644);
    write_file(&upper.join("d/upper-only.txt"), b"upper", 0o644);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        commit_dir(
            &repo,
            dfd.as_fd(),
            Path::new("base"),
            "test/base",
            canon_flags(),
        )
        .await;
        let mut mtree = MutableTree::from_commit(&repo, "test/base").await.unwrap();

        let txn = repo.transaction().await.unwrap();
        let mut modifier = CommitModifier::new(canon_flags());
        let upper_fd = std::fs::File::open(&upper).unwrap();
        txn.merge_overlay_dfd_to_mtree(upper_fd.as_fd(), &mut mtree, Some(&mut modifier))
            .await
            .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *root.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&base.join("repo")).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let d = tree.dirs.iter().find(|(n, ..)| n == "d").unwrap().1;
        let subtree = repo.load_dirtree(&d).await.unwrap();
        let names: Vec<&str> = subtree.files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec!["shared.txt", "upper-only.txt"],
            "the base-only entry is dropped; upper entries remain"
        );
    });
}

#[test]
fn overlay_xattrs_appear_in_no_staged_object() {
    // overlay.* control xattrs are stripped from every ingested object, while a
    // genuine user.* xattr survives. Committed without SKIP_XATTRS so content
    // xattrs are captured.
    let tmp = TmpDir::new("overlay-xattr-strip");
    let base = tmp.path();

    let upper = base.join("upper");
    mkdir(&upper, 0o755);
    write_file(&upper.join("file.txt"), b"content", 0o644);
    set_xattr(&upper.join("file.txt"), "user.keep", b"1");
    set_xattr(&upper.join("file.txt"), "user.overlay.foo", b"bar");
    mkdir(&upper.join("od"), 0o755);
    opaque(&upper.join("od")); // user.overlay.opaque=y
    set_xattr(&upper.join("od"), "user.dirkeep", b"1");
    write_file(&upper.join("od/inner.txt"), b"inner", 0o644);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let mut mtree = MutableTree::new();
        let txn = repo.transaction().await.unwrap();
        // No flags: on-disk xattrs are captured (minus overlay.*).
        let mut modifier = CommitModifier::new(CommitModifierFlags::NONE);
        let upper_fd = std::fs::File::open(&upper).unwrap();
        txn.merge_overlay_dfd_to_mtree(upper_fd.as_fd(), &mut mtree, Some(&mut modifier))
            .await
            .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *root.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&base.join("repo")).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();

        // The file keeps user.keep and carries no overlay.* xattr.
        let file = tree.files.iter().find(|(n, _)| n == "file.txt").unwrap().1;
        let file = repo.load_file(&file).await.unwrap();
        assert!(
            file.xattrs
                .iter()
                .any(|(n, v)| n == b"user.keep\0" && v == b"1"),
            "the genuine user.keep xattr survives"
        );
        assert!(
            !file.xattrs.iter().any(|(n, _)| is_overlay(n)),
            "no overlay.* xattr on the file object: {:?}",
            file.xattrs
        );

        // The opaque directory keeps user.dirkeep and drops user.overlay.opaque.
        let d = tree.dirs.iter().find(|(n, ..)| n == "od").unwrap();
        let dirmeta = repo.load_dirmeta(&d.2).await.unwrap();
        assert!(
            dirmeta
                .xattrs
                .iter()
                .any(|(n, v)| n == b"user.dirkeep\0" && v == b"1"),
            "the directory keeps its genuine xattr"
        );
        assert!(
            !dirmeta.xattrs.iter().any(|(n, _)| is_overlay(n)),
            "the opaque marker is stripped from the dirmeta: {:?}",
            dirmeta.xattrs
        );
    });
}

/// Whether a stored (NUL-terminated) xattr name is in an overlay namespace.
fn is_overlay(name: &[u8]) -> bool {
    name.starts_with(b"trusted.overlay.") || name.starts_with(b"user.overlay.")
}

#[test]
fn metacopy_is_a_hard_error() {
    let tmp = TmpDir::new("overlay-metacopy");
    let base = tmp.path();
    let upper = base.join("upper");
    mkdir(&upper, 0o755);
    write_file(&upper.join("file.txt"), b"content", 0o644);
    set_xattr(&upper.join("file.txt"), "user.overlay.metacopy", b"");

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let mut mtree = MutableTree::new();
        let txn = repo.transaction().await.unwrap();
        let mut modifier = CommitModifier::new(CommitModifierFlags::NONE);
        let upper_fd = std::fs::File::open(&upper).unwrap();
        let err = txn
            .merge_overlay_dfd_to_mtree(upper_fd.as_fd(), &mut mtree, Some(&mut modifier))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedOverlayFeature(_)),
            "metacopy is a dedicated error, got {err:?}"
        );
        txn.abort().await.unwrap();
    });
}

#[test]
fn redirect_is_a_hard_error() {
    let tmp = TmpDir::new("overlay-redirect");
    let base = tmp.path();
    let upper = base.join("upper");
    mkdir(&upper, 0o755);
    mkdir(&upper.join("d"), 0o755);
    set_xattr(&upper.join("d"), "user.overlay.redirect", b"/elsewhere");

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let mut mtree = MutableTree::new();
        let txn = repo.transaction().await.unwrap();
        let mut modifier = CommitModifier::new(CommitModifierFlags::NONE);
        let upper_fd = std::fs::File::open(&upper).unwrap();
        let err = txn
            .merge_overlay_dfd_to_mtree(upper_fd.as_fd(), &mut mtree, Some(&mut modifier))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedOverlayFeature(_)),
            "redirect is a dedicated error, got {err:?}"
        );
        txn.abort().await.unwrap();
    });
}

#[test]
fn dir_over_base_symlink_wins() {
    // An upper directory over a base symlink drops the symlink and creates a
    // fresh directory holding the upper entries; the symlink's former target
    // survives as its own base entry.
    let tmp = TmpDir::new("overlay-dir-over-symlink");
    let base = tmp.path();

    let base_src = base.join("base");
    mkdir(&base_src, 0o755);
    write_file(&base_src.join("target.txt"), b"target", 0o644);
    std::os::unix::fs::symlink("target.txt", base_src.join("link")).unwrap();

    let upper = base.join("upper");
    mkdir(&upper, 0o755);
    mkdir(&upper.join("link"), 0o755);
    write_file(&upper.join("link/inner.txt"), b"inner", 0o644);

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        commit_dir(
            &repo,
            dfd.as_fd(),
            Path::new("base"),
            "test/base",
            canon_flags(),
        )
        .await;
        let mut mtree = MutableTree::from_commit(&repo, "test/base").await.unwrap();

        let txn = repo.transaction().await.unwrap();
        let mut modifier = CommitModifier::new(canon_flags());
        let upper_fd = std::fs::File::open(&upper).unwrap();
        txn.merge_overlay_dfd_to_mtree(upper_fd.as_fd(), &mut mtree, Some(&mut modifier))
            .await
            .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *root.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&base.join("repo")).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        assert!(
            !tree.files.iter().any(|(n, _)| n == "link"),
            "the base symlink is gone from the file entries"
        );
        let link = tree.dirs.iter().find(|(n, ..)| n == "link").unwrap().1;
        let subtree = repo.load_dirtree(&link).await.unwrap();
        let names: Vec<&str> = subtree.files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec!["inner.txt"],
            "the fresh directory holds the upper entry"
        );
        assert!(
            tree.files.iter().any(|(n, _)| n == "target.txt"),
            "the symlink's former target survives"
        );
    });
}

#[test]
fn upper_leaf_replaces_base_directory() {
    // usrmerge-style: an upper file or symlink at a name the base holds as a
    // directory drops the base directory and applies the leaf. overlayfs records
    // this as a plain non-opaque leaf, needing no whiteout or opaque marker.
    let tmp = TmpDir::new("overlay-leaf-over-dir");
    let base = tmp.path();

    let base_src = base.join("base");
    mkdir(&base_src, 0o755);
    mkdir(&base_src.join("d"), 0o755);
    write_file(&base_src.join("d/inner.txt"), b"inner", 0o644);
    mkdir(&base_src.join("f"), 0o755);
    write_file(&base_src.join("f/inner.txt"), b"inner", 0o644);

    let upper = base.join("upper");
    mkdir(&upper, 0o755);
    std::os::unix::fs::symlink("target.txt", upper.join("d")).unwrap(); // dir -> symlink
    write_file(&upper.join("f"), b"now-a-file", 0o644); // dir -> file

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        commit_dir(
            &repo,
            dfd.as_fd(),
            Path::new("base"),
            "test/base",
            canon_flags(),
        )
        .await;
        let mut mtree = MutableTree::from_commit(&repo, "test/base").await.unwrap();

        let txn = repo.transaction().await.unwrap();
        let mut modifier = CommitModifier::new(canon_flags());
        let upper_fd = std::fs::File::open(&upper).unwrap();
        txn.merge_overlay_dfd_to_mtree(upper_fd.as_fd(), &mut mtree, Some(&mut modifier))
            .await
            .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *root.dirtree_checksum();
        txn.commit().await.unwrap();

        let repo = Repo::open(&base.join("repo")).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        assert!(
            tree.dirs.is_empty(),
            "both base directories are replaced by leaves: {:?}",
            tree.dirs.iter().map(|(n, ..)| n).collect::<Vec<_>>()
        );
        let file_names: Vec<&str> = tree.files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            file_names,
            vec!["d", "f"],
            "the leaves take the directories' names"
        );

        // d is a symlink, f is a regular file.
        let d = tree.files.iter().find(|(n, _)| n == "d").unwrap().1;
        assert!(
            repo.load_file(&d).await.unwrap().is_symlink(),
            "the dir-to-symlink replacement is a symlink"
        );
        let f = tree.files.iter().find(|(n, _)| n == "f").unwrap().1;
        assert!(
            !repo.load_file(&f).await.unwrap().is_symlink(),
            "the dir-to-file replacement is a regular file"
        );
    });
}

#[test]
fn filter_skip_leaves_base_entry_in_place() {
    // A filter that skips an upper file leaves the base version untouched, while
    // a non-skipped upper entry still applies.
    let tmp = TmpDir::new("overlay-filter");
    let base = tmp.path();

    let base_src = base.join("base");
    mkdir(&base_src, 0o755);
    write_file(&base_src.join("a.txt"), b"base-a", 0o644);

    let upper = base.join("upper");
    mkdir(&upper, 0o755);
    write_file(&upper.join("a.txt"), b"UPPER-A", 0o644); // skipped: base kept
    write_file(&upper.join("e.txt"), b"upper-e", 0o644); // allowed: added

    block_on(async {
        let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::BareUser))
            .await
            .unwrap();
        let dfd = std::fs::File::open(base).unwrap();
        commit_dir(
            &repo,
            dfd.as_fd(),
            Path::new("base"),
            "test/base",
            canon_flags(),
        )
        .await;

        // The base a.txt checksum, to prove it is unchanged after the skip.
        let (base_tree, _) = repo.read_commit("test/base").await.unwrap();
        let base_a = file_checksum(&base_tree, "a.txt").await;

        let mut mtree = MutableTree::from_commit(&repo, "test/base").await.unwrap();
        let txn = repo.transaction().await.unwrap();
        let mut modifier = CommitModifier::new(canon_flags());
        modifier.filter = Some(Box::new(|path, _meta| {
            if path == Path::new("/a.txt") {
                FilterResult::Skip
            } else {
                FilterResult::Allow
            }
        }));
        let upper_fd = std::fs::File::open(&upper).unwrap();
        txn.merge_overlay_dfd_to_mtree(upper_fd.as_fd(), &mut mtree, Some(&mut modifier))
            .await
            .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let root_dirtree = *root.dirtree_checksum();
        let stats = txn.commit().await.unwrap();
        assert_eq!(stats.filtered, 1, "one upper entry skipped");

        let repo = Repo::open(&base.join("repo")).await.unwrap();
        let tree = repo.load_dirtree(&root_dirtree).await.unwrap();
        let a = tree.files.iter().find(|(n, _)| n == "a.txt").unwrap().1;
        assert_eq!(a, base_a, "the skipped upper file left the base version");
        assert!(
            tree.files.iter().any(|(n, _)| n == "e.txt"),
            "the non-skipped upper file was applied"
        );
    });
}

/// The content checksum of a file `name` in the root of `tree`.
async fn file_checksum(tree: &ostrya::RepoTree, name: &str) -> Checksum {
    let Some(TreeEntry::File { checksum, .. }) = tree.lookup(Path::new(name)).await.unwrap() else {
        panic!("{name} is not a file");
    };
    checksum
}
