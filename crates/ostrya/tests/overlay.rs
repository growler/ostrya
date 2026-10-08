//! Integration tests for the import of an overlay changeset.
//!
//! The tests make overlayfs upper-directory changesets on disk. A whiteout is a
//! character device 0:0, which `mknodat` makes without privileges. An opaque
//! directory has the xattr `user.overlay.opaque`. The tests merge each
//! changeset over a base `MutableTree` with `merge_overlay_dfd_to_mtree`.
//!
//! The main test builds the expected merged tree by hand and ingests it with
//! `write_dfd_to_mtree`. The two paths must give the same root checksum. The
//! other tests cover:
//!
//! - whiteout deletion
//! - opaque replacement
//! - removal of the `overlay.*` xattrs
//! - the errors for metacopy and redirect
//! - replacement across types: a directory over a base symlink, and leaves
//!   over base directories
//! - a filter that keeps base entries in place

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Error,
    FilterResult, MutableTree, Repo, RepoMode, TreeEntry,
};
use ostrya_rt::block_on;

/// Returns `value` and checks at compile time that its type is `Send`.
/// A call pins that the overlay merge future, with its callbacks, is `Send`.
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

/// Creates an overlayfs whiteout: a character device with device number 0:0.
/// A process needs no capability to create a character device 0:0.
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

/// Sets an extended attribute on `path`. The call follows symlinks.
fn set_xattr(path: &Path, name: &str, value: &[u8]) {
    rustix::fs::setxattr(path, name, value, rustix::fs::XattrFlags::empty()).unwrap();
}

/// Marks a directory as opaque in the `user.*` namespace, which needs no root.
fn opaque(path: &Path) {
    set_xattr(path, "user.overlay.opaque", b"y");
}

/// Commits the tree on disk at `path` (relative to `dfd`) to `refname`.
/// `MutableTree::from_commit` can then load the tree from the ref.
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

/// Returns the flags for canonical permissions and no xattrs.
/// The equivalence tests use these flags so that the merge and the ingest by
/// hand get the same owner and mode.
fn canon_flags() -> CommitModifierFlags {
    CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS
}

#[test]
fn merge_equals_scratch_checkout_then_ingest() {
    // A merge of a changeset over a base mtree from a commit gives the same
    // root checksum as an ingest of the expected merged tree. The test builds
    // the expected tree by hand. The test covers these cases:
    // - a file change, a file addition, and a whiteout deletion
    // - a merged directory with changed metadata that keeps its base-only file
    // - an opaque directory replacement with changed metadata
    let tmp = TmpDir::new("overlay-equiv");
    let base = tmp.path();

    // The base tree on disk.
    let base_src = base.join("base");
    mkdir(&base_src, 0o755);
    write_file(&base_src.join("a.txt"), b"base-a", 0o644);
    write_file(&base_src.join("b.txt"), b"base-b", 0o644);
    mkdir(&base_src.join("sub"), 0o755);
    write_file(&base_src.join("sub/c.txt"), b"base-c", 0o644);
    write_file(&base_src.join("sub/d.txt"), b"base-d", 0o644);
    mkdir(&base_src.join("keep"), 0o755);
    write_file(&base_src.join("keep/old.txt"), b"old", 0o644);

    // The changeset in the upper directory.
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
    // A whiteout removes its path and keeps all other entries. A whiteout of a
    // path that does not exist is not an error.
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
    // An opaque upper directory removes the base entries under its name. Only
    // the entries of the upper directory stay.
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
    // The merge removes each xattr under `trusted.overlay.` or `user.overlay.`
    // from each ingested object. Every other xattr stays, also a name that
    // contains `overlay` without one of these prefixes. The test commits
    // without `SKIP_XATTRS`, so the merge records the xattrs of the content.
    let tmp = TmpDir::new("overlay-xattr-strip");
    let base = tmp.path();

    let upper = base.join("upper");
    mkdir(&upper, 0o755);
    write_file(&upper.join("file.txt"), b"content", 0o644);
    set_xattr(&upper.join("file.txt"), "user.keep", b"1");
    set_xattr(&upper.join("file.txt"), "user.overlay.foo", b"bar");
    // Neither name has the overlay prefix. The first has no final dot, and the
    // second has no dot after `overlay`. Both must stay after the merge.
    set_xattr(&upper.join("file.txt"), "user.overlay", b"kept-no-dot");
    set_xattr(&upper.join("file.txt"), "user.overlayish", b"kept-suffix");
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
        // No flags: the merge records the xattrs on disk, except `overlay.*`.
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

        // The file keeps `user.keep` and has no `trusted.overlay.` or
        // `user.overlay.` xattr.
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
        // A name that contains `overlay` without one of the two prefixes is not
        // a control xattr. It stays unchanged.
        assert!(
            file.xattrs
                .iter()
                .any(|(n, v)| n == b"user.overlay\0" && v == b"kept-no-dot"),
            "user.overlay (no trailing dot) is not the overlay prefix: {:?}",
            file.xattrs
        );
        assert!(
            file.xattrs
                .iter()
                .any(|(n, v)| n == b"user.overlayish\0" && v == b"kept-suffix"),
            "user.overlayish does not start with the overlay prefix: {:?}",
            file.xattrs
        );

        // The opaque directory keeps `user.dirkeep` and loses
        // `user.overlay.opaque`.
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

/// Returns `true` if a stored, NUL-terminated xattr name is in an overlay
/// namespace.
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
    // An upper directory over a base symlink removes the symlink. The merge
    // makes a new directory with the upper entries. The old target of the
    // symlink stays as a separate base entry.
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
    // This is the usrmerge case. An upper file or symlink at the name of a base
    // directory removes the base directory and adds the leaf. overlayfs records
    // this change as a plain leaf that is not opaque. The change needs no
    // whiteout and no opaque marker.
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

        // `d` is a symlink and `f` is a regular file.
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
    // If a filter skips an upper file, the base version stays unchanged. The
    // merge applies an upper entry that the filter does not skip.
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

        // The checksum of the base `a.txt`. The test uses it to show that the
        // skip keeps the base file.
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

/// Returns the content checksum of the file `name` in the root of `tree`.
async fn file_checksum(tree: &ostrya::RepoTree, name: &str) -> Checksum {
    let Some(TreeEntry::File { checksum, .. }) = tree.lookup(Path::new(name)).await.unwrap() else {
        panic!("{name} is not a file");
    };
    checksum
}
