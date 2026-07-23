//! Comparing two committed trees.
//!
//! [`Repo::diff_commits`] compares the trees of two commits and reports the
//! paths that changed. The classification reproduces `ostree diff` (recovered by
//! black-box observation):
//!
//! - A regular file present in both with a different content checksum is
//!   [`Modified`](DiffChange::Modified).
//! - A directory present in both whose metadata (dirmeta) differs is
//!   [`Modified`](DiffChange::Modified); its unchanged children are not listed,
//!   but the comparison still descends to find nested changes.
//! - A name whose type changes between the two commits (a file becoming a
//!   directory, or the reverse) is a single [`Modified`](DiffChange::Modified)
//!   entry, with no descent into it.
//! - A name only in the second commit is [`Added`](DiffChange::Added); an added
//!   directory lists itself and, recursively, every descendant.
//! - A name only in the first commit is [`Removed`](DiffChange::Removed); a
//!   removed directory is a single entry, without its former children.
//!
//! The returned entries are grouped as the tool prints them -- modified, then
//! removed, then added -- and sorted by path within each group.

use std::collections::HashMap;

use ostrya_core::{Checksum, DirTree};

use crate::error::Result;
use crate::repo::Repo;
use crate::tree::RepoTree;

/// The kind of change to a path between two commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffChange {
    /// The path exists only in the second commit.
    Added,
    /// The path exists only in the first commit.
    Removed,
    /// The path exists in both but its content, metadata, or type differs.
    Modified,
}

/// One entry in a commit-to-commit diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    /// What changed.
    pub change: DiffChange,
    /// The absolute path within the tree, for example `/etc/hostname`.
    pub path: String,
}

/// One directory entry, resolved to either a file or a subdirectory.
enum Node {
    File(Checksum),
    Dir {
        dirtree: Checksum,
        dirmeta: Checksum,
    },
}

impl Repo {
    /// Compare the trees of commits `from` and `to`, returning the changed
    /// paths.
    pub async fn diff_commits(&self, from: &Checksum, to: &Checksum) -> Result<Vec<DiffEntry>> {
        let (from_commit, _) = self.load_commit(from).await?;
        let (to_commit, _) = self.load_commit(to).await?;
        let from_root = RepoTree::from_parts(
            self.clone(),
            from_commit.root_dirtree,
            from_commit.root_dirmeta,
        );
        let to_root =
            RepoTree::from_parts(self.clone(), to_commit.root_dirtree, to_commit.root_dirmeta);

        let mut modified = Vec::new();
        let mut removed = Vec::new();
        let mut added = Vec::new();

        // A work stack of same-named directories to compare, path-prefixed.
        let mut stack = vec![(from_root, to_root, String::new())];
        while let Some((from_dir, to_dir, prefix)) = stack.pop() {
            let from_index = index_dirtree(&self.load_dirtree(from_dir.dirtree_checksum()).await?);
            let to_index = index_dirtree(&self.load_dirtree(to_dir.dirtree_checksum()).await?);

            let mut names: Vec<&String> = from_index.keys().chain(to_index.keys()).collect();
            names.sort_unstable();
            names.dedup();

            for name in names {
                let path = format!("{prefix}/{name}");
                match (from_index.get(name), to_index.get(name)) {
                    (Some(Node::File(a)), Some(Node::File(b))) => {
                        if a != b {
                            modified.push(path);
                        }
                    }
                    (
                        Some(Node::Dir {
                            dirtree: fa,
                            dirmeta: ma,
                        }),
                        Some(Node::Dir {
                            dirtree: fb,
                            dirmeta: mb,
                        }),
                    ) => {
                        if ma != mb {
                            modified.push(path.clone());
                        }
                        // Descend to find nested changes, even when only the
                        // metadata differs (identical checksums add nothing).
                        if fa != fb {
                            stack.push((
                                RepoTree::from_parts(self.clone(), *fa, *ma),
                                RepoTree::from_parts(self.clone(), *fb, *mb),
                                path,
                            ));
                        }
                    }
                    // A name that changed type is a single modification.
                    (Some(_), Some(_)) => modified.push(path),
                    (None, Some(node)) => self.collect_added(node, path, &mut added).await?,
                    (Some(_), None) => removed.push(path),
                    (None, None) => unreachable!("name came from one of the two indexes"),
                }
            }
        }

        modified.sort();
        removed.sort();
        added.sort();

        let mut out = Vec::with_capacity(modified.len() + removed.len() + added.len());
        out.extend(entries(DiffChange::Modified, modified));
        out.extend(entries(DiffChange::Removed, removed));
        out.extend(entries(DiffChange::Added, added));
        Ok(out)
    }

    /// Record an added node and, for a directory, every descendant beneath it.
    async fn collect_added(
        &self,
        node: &Node,
        path: String,
        added: &mut Vec<String>,
    ) -> Result<()> {
        added.push(path.clone());
        let Node::Dir { dirtree, .. } = node else {
            return Ok(());
        };
        let mut stack = vec![(*dirtree, path)];
        while let Some((dt, prefix)) = stack.pop() {
            let dirtree = self.load_dirtree(&dt).await?;
            for (name, _) in &dirtree.files {
                added.push(format!("{prefix}/{name}"));
            }
            for (name, sub, _) in &dirtree.dirs {
                let child = format!("{prefix}/{name}");
                added.push(child.clone());
                stack.push((*sub, child));
            }
        }
        Ok(())
    }
}

/// Index a dirtree's files and subdirectories by name.
fn index_dirtree(dirtree: &DirTree) -> HashMap<String, Node> {
    let mut map = HashMap::with_capacity(dirtree.files.len() + dirtree.dirs.len());
    for (name, checksum) in &dirtree.files {
        map.insert(name.clone(), Node::File(*checksum));
    }
    for (name, sub, meta) in &dirtree.dirs {
        map.insert(
            name.clone(),
            Node::Dir {
                dirtree: *sub,
                dirmeta: *meta,
            },
        );
    }
    map
}

/// Turn a sorted list of paths into diff entries of one change kind.
fn entries(change: DiffChange, paths: Vec<String>) -> impl Iterator<Item = DiffEntry> {
    paths
        .into_iter()
        .map(move |path| DiffEntry { change, path })
}
