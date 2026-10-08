//! The read-only walk of the file tree of a commit.
//!
//! [`Repo::read_commit`] opens the root directory of a commit as a
//! [`RepoTree`]. [`RepoTree::read_dir`] lists a directory, and
//! [`RepoTree::lookup`] resolves a path.

use std::path::Path;

use ostrya_core::Checksum;

use crate::error::{Error, Result};
use crate::repo::Repo;

/// A handle to one directory of a committed tree.
///
/// The handle holds the repository and the dirtree and dirmeta checksums of
/// the directory. It loads the dirtree only when
/// [`read_dir`](RepoTree::read_dir) or [`lookup`](RepoTree::lookup) visits the
/// directory.
#[derive(Debug, Clone)]
pub struct RepoTree {
    repo: Repo,
    dirtree: Checksum,
    dirmeta: Checksum,
}

/// One entry of a directory listing.
#[derive(Debug, Clone)]
pub enum TreeEntry {
    /// A regular file or a symlink, named by the checksum of its file object.
    File {
        /// The entry name.
        name: String,
        /// The checksum of the file object.
        checksum: Checksum,
    },
    /// A subdirectory, with a handle to it.
    Dir {
        /// The entry name.
        name: String,
        /// A handle to the subdirectory.
        tree: RepoTree,
    },
}

/// Methods that read the tree of a commit.
impl Repo {
    /// Opens the root tree of a commit and returns it with the commit checksum.
    ///
    /// `rev` takes the revision syntax of [`resolve_rev`](Repo::resolve_rev).
    /// It can be a refspec, a full commit checksum, or an abbreviated checksum
    /// that names the one commit whose checksum starts with it.
    ///
    /// # Errors
    ///
    /// - [`Error::RefNotFound`] if `rev` names no ref.
    /// - [`Error::InvalidRefspec`] if `rev` is not a checksum and not a valid
    ///   refspec.
    /// - [`Error::AmbiguousRefspec`] if more than one commit checksum starts
    ///   with the abbreviated checksum.
    /// - [`Error::NoParentCommit`] if a `^` steps back from a commit with no
    ///   parent.
    /// - [`Error::ObjectNotFound`] if the commit object, or a commit that a
    ///   `^` step reads, is not in the object store.
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8.
    /// - [`Error::Core`] if a ref file holds no checksum, or if a commit
    ///   object does not parse.
    /// - [`Error::Io`] if the commit object is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or is not a regular
    ///   file, or if a read from the file system fails.
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
    /// Creates a handle from a repository and the dirtree and dirmeta
    /// checksums of a directory.
    ///
    /// `write_mtree` calls it to name the root that it assembles.
    pub(crate) fn from_parts(repo: Repo, dirtree: Checksum, dirmeta: Checksum) -> RepoTree {
        RepoTree {
            repo,
            dirtree,
            dirmeta,
        }
    }

    /// Returns the dirtree checksum of this directory.
    pub fn dirtree_checksum(&self) -> &Checksum {
        &self.dirtree
    }

    /// Returns the dirmeta checksum of this directory.
    pub fn dirmeta_checksum(&self) -> &Checksum {
        &self.dirmeta
    }

    /// Lists the entries of this directory, files first and then subdirectories.
    ///
    /// Each group is in name order.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the dirtree object is not in the object
    ///   store.
    /// - [`Error::Io`] if the dirtree object is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or is not a regular
    ///   file, or if a read from the file system fails.
    /// - [`Error::Core`] if the dirtree object does not parse.
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

    /// Resolves a relative path in this tree to an entry.
    ///
    /// The result is `None` if a component is missing. The call ignores a
    /// leading `/` and each `.` component. The last component can name a file
    /// or a directory. A component before the last that names a file gives
    /// `None`, and so does a path with no component left, such as `/`.
    ///
    /// A path names entries in the committed tree. A `..` component names an
    /// entry that no directory holds. Such a path resolves to `None` at the
    /// `..`, after the components before it resolve.
    ///
    /// In each directory, the lookup is a binary search over the sorted lists
    /// of the dirtree.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if a dirtree object on the path is not in
    ///   the object store.
    /// - [`Error::Io`] if a dirtree object is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or is not a regular
    ///   file, or if a read from the file system fails.
    /// - [`Error::Core`] if a dirtree object does not parse.
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

            // A missing component, or a component before the last that names a
            // file.
            return Ok(None);
        }
        Ok(None)
    }
}

/// One component of a lookup path that the walk uses.
pub(crate) enum Comp {
    /// An entry name to resolve in the current directory of the walk.
    Normal(String),
    /// A `..` component. It is a marker: no directory holds an entry of this
    /// name, so the walk stops at it and the lookup resolves to nothing.
    Parent,
}

/// Splits a path into the components that a walk uses.
///
/// The call drops the root and each `.` component, and keeps `..` as
/// [`Comp::Parent`]. Each walk over a path of a commit tree reads its
/// components through this function. As a result, one path splits the same
/// way at each call site.
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

/// A compile-time check that `RepoTree` and `TreeEntry` are `Send` and
/// `Sync`, so that they can move across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RepoTree>();
    assert_send_sync::<TreeEntry>();
};
