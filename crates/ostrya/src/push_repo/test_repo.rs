//! Repositories the push tests read from.

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use ostrya_core::{Checksum, RepoMode};

use crate::{CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree, Repo};

/// A scratch directory, removed when the value drops.
pub(super) struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    pub(super) fn new(label: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-push-repo-{label}-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch { dir }
    }

    pub(super) fn path(&self) -> &Path {
        &self.dir
    }

    /// A new repository of `mode` at `repo` in the scratch directory.
    pub(super) async fn create(&self, mode: RepoMode) -> Repo {
        Repo::create(&self.dir.join("repo"), CreateOptions::new(mode))
            .await
            .unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Commit a tree with `parent`, and point the ref `name` at the commit. The
/// tree holds a regular file `file` with `content`, and a symlink `link` to
/// `file`.
pub(super) async fn commit_tree(
    repo: &Repo,
    scratch: &Scratch,
    name: &str,
    parent: Option<Checksum>,
    content: &[u8],
) -> Checksum {
    let tree = scratch
        .path()
        .join(format!("tree-{}", crate::write::unique()));
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("file"), content).unwrap();
    std::os::unix::fs::symlink("file", tree.join("link")).unwrap();

    let txn = repo.transaction().await.unwrap();
    let dfd = std::fs::File::open(&tree).unwrap();
    let mut modifier = Some(CommitModifier::new(
        CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
    ));
    let mut mtree = MutableTree::new();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, modifier.as_mut())
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                parent,
                timestamp: Some(1_700_000_000),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref(name, Some(&commit));
    txn.commit().await.unwrap();
    commit
}
