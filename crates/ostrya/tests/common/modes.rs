//! Repositories of each mode with one commit of a small tree, for the tests
//! of the archive view and of the pull serving side.

use std::fs;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree,
    ObjectType, Repo, RepoMode, loose_path,
};
use ostrya_core::{ContentHasher, FileHeader, Xattrs};

/// The modes that ostrya writes.
pub const WRITABLE: [RepoMode; 5] = [
    RepoMode::Archive,
    RepoMode::Bare,
    RepoMode::BareUser,
    RepoMode::BareUserOnly,
    RepoMode::BareUserShared,
];

/// Builds a small tree in `base/src` and returns its path.
///
/// The tree has these entries:
///
/// - a regular file
/// - an executable
/// - an empty file
/// - a file larger than one 64 KiB chunk
/// - a symlink to the first file
pub fn build_tree(base: &Path) -> PathBuf {
    let src = base.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("hello"), b"hello ostree\n").unwrap();
    fs::write(src.join("exec"), b"#!/bin/sh\n").unwrap();
    fs::set_permissions(src.join("exec"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(src.join("empty"), b"").unwrap();
    let big: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    fs::write(src.join("big"), big).unwrap();
    symlink("hello", src.join("link")).unwrap();
    src
}

/// Commits the tree at `src` into `repo` with a fixed timestamp, and sets
/// `main` to the commit.
pub async fn commit(repo: &Repo, src: &Path) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
    let dfd = fs::File::open(src).unwrap();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some("view".to_owned()),
                timestamp: Some(1_700_000_000),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("main", Some(&commit));
    txn.commit().await.unwrap();
    commit
}

/// Creates a repository of `mode` in `base/<mode>`, with the tree of `src`
/// on `main`.
pub async fn repo_of(base: &Path, mode: RepoMode, src: &Path) -> (PathBuf, Repo, Checksum) {
    let path = base.join(mode.as_mode_str());
    let repo = Repo::create(&path, CreateOptions::new(mode)).await.unwrap();
    let commit = commit(&repo, src).await;
    (path, repo, commit)
}

/// Returns the checksums of the file objects of `commit`.
pub async fn file_objects(repo: &Repo, commit: &Checksum) -> Vec<Checksum> {
    repo.traverse_commit(commit, 0)
        .await
        .unwrap()
        .into_iter()
        .filter(|name| name.ty == ObjectType::File)
        .map(|name| name.checksum)
        .collect()
}

pub fn object_path(ty: ObjectType, checksum: &Checksum) -> String {
    format!("objects/{}", loose_path(checksum, ty, RepoMode::Archive))
}

/// Returns the uid and the gid that own `dir`.
///
/// The tests create `dir`, so these are the uid and the gid of the user that
/// runs the tests.
pub fn current_owner(dir: &Path) -> (u32, u32) {
    let md = fs::metadata(dir).unwrap();
    (md.uid(), md.gid())
}

/// Writes one `bare-split-xattrs` file object by hand and returns its
/// checksum.
///
/// The inode carries the owner and the mode. A `.file-xattrs-link` hardlink
/// to the shared `.file-xattrs` object carries the extended attributes.
pub fn write_split_object(
    root: &Path,
    mode: u32,
    target: &str,
    xattrs: &Xattrs,
    payload: &[u8],
) -> Checksum {
    let (uid, gid) = current_owner(root);
    let header = FileHeader {
        uid,
        gid,
        mode,
        symlink_target: target.to_owned(),
        xattrs: xattrs.clone(),
    };
    let mut hasher = ContentHasher::new(&header).unwrap();
    hasher.update(payload);
    let id = hasher.finish();
    let at = |checksum: &Checksum, ty| {
        let full = root
            .join("objects")
            .join(loose_path(checksum, ty, RepoMode::BareSplitXattrs));
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        full
    };
    let file = at(&id, ObjectType::File);
    if mode & 0o170000 == 0o120000 {
        symlink(target, &file).unwrap();
    } else {
        fs::write(&file, payload).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(mode & 0o7777)).unwrap();
    }
    let xbytes = xattrs.to_gvariant().unwrap();
    let xattrs_path = at(&Checksum::sha256(&xbytes), ObjectType::FileXattrs);
    if !xattrs_path.exists() {
        fs::write(&xattrs_path, &xbytes).unwrap();
    }
    fs::hard_link(&xattrs_path, at(&id, ObjectType::FileXattrsLink)).unwrap();
    id
}
