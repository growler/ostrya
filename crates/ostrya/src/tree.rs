//! Read-only traversal of a commit's file tree.
//!
//! [`RepoTree`] is a lightweight handle to a directory within a commit: the
//! repository plus the directory's dirtree and dirmeta checksums. Children are
//! resolved lazily -- [`read_dir`](RepoTree::read_dir) and
//! [`lookup`](RepoTree::lookup) load a dirtree only when the directory is
//! visited. Within a directory, entries are name-sorted (files before
//! directories), and lookup uses a binary search over the sorted lists.

use std::path::Path;

use ostrya_core::Checksum;

use crate::error::{Error, Result};
use crate::repo::Repo;

/// A handle to one directory within a committed tree.
#[derive(Debug, Clone)]
pub struct RepoTree {
    repo: Repo,
    dirtree: Checksum,
    dirmeta: Checksum,
}

/// One entry in a directory listing.
#[derive(Debug, Clone)]
pub enum TreeEntry {
    /// A regular file or symlink, named by its content checksum.
    File {
        /// The entry name.
        name: String,
        /// The file object's checksum.
        checksum: Checksum,
    },
    /// A subdirectory, with a handle for descending into it.
    Dir {
        /// The entry name.
        name: String,
        /// A handle to the subdirectory.
        tree: RepoTree,
    },
}

impl Repo {
    /// Open a commit's root tree, returning the tree handle and the resolved
    /// commit checksum. `rev` may be a refspec, a bare commit checksum, or
    /// an abbreviated checksum naming the one commit whose checksum starts
    /// with it.
    pub async fn read_commit(&self, rev: &str) -> Result<(RepoTree, Checksum)> {
        let checksum = self
            .resolve_rev(rev, false)
            .await?
            .ok_or_else(|| Error::RefNotFound(rev.to_owned()))?;
        let (commit, _) = self.load_commit(&checksum).await?;
        let tree = RepoTree {
            repo: self.clone(),
            dirtree: commit.root_dirtree,
            dirmeta: commit.root_dirmeta,
        };
        Ok((tree, checksum))
    }
}

impl RepoTree {
    /// Build a handle from a repository and a directory's dirtree and dirmeta
    /// checksums. Used by `write_mtree` to name a freshly assembled root.
    pub(crate) fn from_parts(repo: Repo, dirtree: Checksum, dirmeta: Checksum) -> RepoTree {
        RepoTree {
            repo,
            dirtree,
            dirmeta,
        }
    }

    /// The dirtree checksum of this directory.
    pub fn dirtree_checksum(&self) -> &Checksum {
        &self.dirtree
    }

    /// The dirmeta checksum of this directory.
    pub fn dirmeta_checksum(&self) -> &Checksum {
        &self.dirmeta
    }

    /// List this directory's entries: files first, then subdirectories, each
    /// group name-sorted.
    pub async fn read_dir(&self) -> Result<Vec<TreeEntry>> {
        let dirtree = self.repo.load_dirtree(&self.dirtree).await?;
        let mut entries = Vec::with_capacity(dirtree.files.len() + dirtree.dirs.len());
        for (name, checksum) in dirtree.files {
            entries.push(TreeEntry::File { name, checksum });
        }
        for (name, tree, meta) in dirtree.dirs {
            entries.push(TreeEntry::Dir {
                name,
                tree: RepoTree {
                    repo: self.repo.clone(),
                    dirtree: tree,
                    dirmeta: meta,
                },
            });
        }
        Ok(entries)
    }

    /// Resolve a relative path within this tree, or `None` if any component is
    /// missing. A leading `/` and every `.` component are ignored. A trailing
    /// component may name either a file or a directory.
    ///
    /// A path names entries in the committed tree, and a `..` component names
    /// an entry that no directory holds. Such a path resolves to `None` at the
    /// `..`, once the components before it resolved.
    pub async fn lookup(&self, path: &Path) -> Result<Option<TreeEntry>> {
        let components = normalize(path);
        if components.is_empty() {
            return Ok(None);
        }
        let mut current = self.clone();
        for (index, component) in components.iter().enumerate() {
            let Comp::Normal(component) = component else {
                // A `..` component. No directory holds an entry of this name.
                return Ok(None);
            };
            let is_last = index + 1 == components.len();
            let dirtree = current.repo.load_dirtree(&current.dirtree).await?;

            if let Ok(pos) = dirtree
                .dirs
                .binary_search_by(|(name, _, _)| name.as_str().cmp(component))
            {
                let (name, tree, meta) = &dirtree.dirs[pos];
                let child = RepoTree {
                    repo: current.repo.clone(),
                    dirtree: *tree,
                    dirmeta: *meta,
                };
                if is_last {
                    return Ok(Some(TreeEntry::Dir {
                        name: name.clone(),
                        tree: child,
                    }));
                }
                current = child;
                continue;
            }

            if is_last
                && let Ok(pos) = dirtree
                    .files
                    .binary_search_by(|(name, _)| name.as_str().cmp(component))
            {
                let (name, checksum) = &dirtree.files[pos];
                return Ok(Some(TreeEntry::File {
                    name: name.clone(),
                    checksum: *checksum,
                }));
            }

            // A missing component, or a non-final component that is a file.
            return Ok(None);
        }
        Ok(None)
    }
}

/// One meaningful component of a lookup path.
pub(crate) enum Comp {
    /// An entry name to resolve in the directory the walk stands in.
    Normal(String),
    /// A `..` component. It is a marker: no directory holds an entry of this
    /// name, so the walk stops at it and the lookup resolves to nothing.
    Parent,
}

/// Split a path into its meaningful components, dropping the root and `.` and
/// keeping `..` as [`Comp::Parent`]. Every walk over a commit-tree path reads
/// its components through this function, so one path splits the same way at
/// every call site.
pub(crate) fn normalize(path: &Path) -> Vec<Comp> {
    use std::path::Component;
    path.components()
        .filter_map(|c| match c {
            Component::Normal(part) => Some(Comp::Normal(part.to_string_lossy().into_owned())),
            Component::ParentDir => Some(Comp::Parent),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => None,
        })
        .collect()
}

/// `RepoTree` moves freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RepoTree>();
    assert_send_sync::<TreeEntry>();
};
