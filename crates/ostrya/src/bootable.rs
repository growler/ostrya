//! The kernel version of a bootable commit, and the metadata pair that holds
//! it.
//!
//! A bootable commit holds two keys in its metadata:
//!
//! - `ostree.linux`, the name of the directory under `/usr/lib/modules` that
//!   holds an entry named `vmlinuz`. The tree of the commit holds exactly one
//!   such directory.
//! - `ostree.bootable`, the value `true`.
//!
//! [`Transaction::kernel_version`] finds the version in a staged tree.
//! [`RepoTree::kernel_version`] finds it in a committed tree.
//! [`BootableRefusal`] names the four tree shapes that give no version.
//! [`BootableMetadata`] adds the pair to a [`DictBuilder`].

use ostrya_core::DictBuilder;

use crate::error::Result;
use crate::transaction::Transaction;
use crate::tree::{RepoTree, TreeEntry};

/// The commit metadata key that holds the name of the kernel directory.
const LINUX_KEY: &str = "ostree.linux";
/// The commit metadata key that marks a commit as bootable.
const BOOTABLE_KEY: &str = "ostree.bootable";
/// The directory that the search reads, one level deep, for the kernel.
const MODULES_DIR: &str = "/usr/lib/modules";
/// The entry name that a kernel directory must hold.
const KERNEL_ENTRY: &str = "vmlinuz";

/// A tree shape that names no kernel version.
///
/// The `kernel_version` methods return it in the inner `Result`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootableRefusal {
    /// A component of `/usr/lib/modules` that the tree does not hold.
    MissingComponent {
        /// The absolute path of the first absent component.
        path: String,
    },
    /// A component of `/usr/lib/modules` that is not a directory.
    ///
    /// A regular file and a symlink both give this refusal.
    NotADirectory {
        /// The absolute path of the component that is not a directory.
        path: String,
    },
    /// No directory under `/usr/lib/modules` holds an entry named `vmlinuz`.
    NoKernel,
    /// Two or more directories under `/usr/lib/modules` hold a `vmlinuz` entry.
    ///
    /// No single kernel version names the tree.
    MultipleKernels,
}

/// The place where the search reads the directories of the tree.
#[derive(Clone, Copy)]
enum DirSource<'a> {
    /// A published repository. Every dirtree is a loose object under
    /// `objects/`.
    Published,
    /// A transaction. The search reads a dirtree that the transaction staged
    /// from the staging directory. It reads a dirtree that deduplicated
    /// against a stored object from `objects/`.
    Staged(&'a Transaction),
}

impl DirSource<'_> {
    async fn read_dir(&self, tree: &RepoTree) -> Result<Vec<TreeEntry>> {
        match self {
            DirSource::Published => tree.read_dir().await,
            DirSource::Staged(txn) => txn.read_dir(tree).await,
        }
    }
}

/// Methods that read the kernel version of a staged tree.
impl Transaction {
    /// Returns the kernel version of a tree that this transaction staged.
    ///
    /// The version is the value of `ostree.linux`. The search reads each
    /// dirtree with [`read_dir`](Transaction::read_dir), so it sees the objects
    /// that this transaction staged and the objects in `objects/`. A caller can
    /// derive the metadata of a commit before the transaction commit.
    ///
    /// The search rules are the same as in [`RepoTree::kernel_version`]. The
    /// inner `Result` holds the version or a [`BootableRefusal`]. A refusal is
    /// an outcome of the search. The outer `Result` holds the errors of the
    /// object reads.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if a dirtree on the search path is not
    ///   staged and not in `objects/`.
    /// - [`Error::Io`] if the read of a dirtree fails, or if a dirtree is
    ///   larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    /// - [`Error::Core`] if a dirtree does not parse.
    ///
    /// [`Error::ObjectNotFound`]: crate::error::Error::ObjectNotFound
    /// [`Error::Io`]: crate::error::Error::Io
    /// [`Error::Core`]: crate::error::Error::Core
    pub async fn kernel_version(
        &self,
        root: &RepoTree,
    ) -> Result<std::result::Result<String, BootableRefusal>> {
        kernel_version(DirSource::Staged(self), root).await
    }
}

impl RepoTree {
    /// Returns the kernel version of this tree.
    ///
    /// The version is the value of `ostree.linux`. The search reads each
    /// dirtree with [`read_dir`](RepoTree::read_dir), which reads `objects/`
    /// alone, so it sees a tree only after the transaction commit. A caller
    /// that reads a deployed commit uses this method.
    /// [`Transaction::kernel_version`] reads a tree that is still staged.
    ///
    /// The inner `Result` holds the version or a [`BootableRefusal`]. A refusal
    /// is an outcome of the search. The outer `Result` holds the errors of the
    /// object reads.
    ///
    /// # Search
    ///
    /// The search walks `/usr/lib/modules` from this tree. Then it reads each
    /// directory one level under `/usr/lib/modules` and looks for an entry
    /// named `vmlinuz`. It reads no deeper level.
    ///
    /// - An entry under `/usr/lib/modules` that is not a directory takes no
    ///   part in the search.
    /// - The search does not read the type of the `vmlinuz` entry. A regular
    ///   file, a symlink, and a directory of that name each count.
    /// - If exactly one directory holds `vmlinuz`, its name is the version.
    ///   Each other outcome is a [`BootableRefusal`].
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if a dirtree on the search path is not in
    ///   the object store. This includes a dirtree that a transaction staged
    ///   before its transaction commit.
    /// - [`Error::Io`] if a dirtree is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or is not a regular
    ///   file, and for other failures of the file system.
    /// - [`Error::Core`] if a dirtree does not parse.
    ///
    /// [`Error::ObjectNotFound`]: crate::error::Error::ObjectNotFound
    /// [`Error::Io`]: crate::error::Error::Io
    /// [`Error::Core`]: crate::error::Error::Core
    pub async fn kernel_version(&self) -> Result<std::result::Result<String, BootableRefusal>> {
        kernel_version(DirSource::Published, self).await
    }
}

/// Walks `/usr/lib/modules` from `root` and returns the name of the single
/// child directory that holds `vmlinuz`. Both `kernel_version` methods call it.
async fn kernel_version(
    source: DirSource<'_>,
    root: &RepoTree,
) -> Result<std::result::Result<String, BootableRefusal>> {
    let mut dir = root.clone();
    let mut walked = String::new();
    for component in MODULES_DIR.split('/').filter(|part| !part.is_empty()) {
        walked.push('/');
        walked.push_str(component);
        let entry = source
            .read_dir(&dir)
            .await?
            .into_iter()
            .find(|entry| entry_name(entry) == component);
        match entry {
            None => return Ok(Err(BootableRefusal::MissingComponent { path: walked })),
            Some(TreeEntry::File { .. }) => {
                return Ok(Err(BootableRefusal::NotADirectory { path: walked }));
            }
            Some(TreeEntry::Dir { tree, .. }) => dir = tree,
        }
    }
    let mut found = Vec::new();
    for entry in source.read_dir(&dir).await? {
        if let TreeEntry::Dir { name, tree } = entry
            && source
                .read_dir(&tree)
                .await?
                .iter()
                .any(|entry| entry_name(entry) == KERNEL_ENTRY)
        {
            found.push(name);
        }
    }
    match found.len() {
        0 => Ok(Err(BootableRefusal::NoKernel)),
        1 => Ok(Ok(found.remove(0))),
        _ => Ok(Err(BootableRefusal::MultipleKernels)),
    }
}

/// Returns the name of a directory entry of either kind.
fn entry_name(entry: &TreeEntry) -> &str {
    match entry {
        TreeEntry::File { name, .. } | TreeEntry::Dir { name, .. } => name,
    }
}

/// An extension of [`DictBuilder`] that adds the bootable metadata pair.
pub trait BootableMetadata {
    /// Appends `ostree.linux` with `kernel_version`, then `ostree.bootable`
    /// with `true`.
    ///
    /// The pair goes in at the current position of the builder. If the caller
    /// inserted its own keys before this call, the pair comes after them.
    ///
    /// The `ostree` command writes the pair at the head of the dict, before
    /// every other key. If the dict holds the pair at another position, the
    /// commit gets a different checksum for the same tree.
    fn insert_bootable(&mut self, kernel_version: &str) -> &mut Self;
}

impl BootableMetadata for DictBuilder {
    fn insert_bootable(&mut self, kernel_version: &str) -> &mut Self {
        self.insert_str(LINUX_KEY, kernel_version)
            .insert_bool(BOOTABLE_KEY, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_core::{Type, Value, to_bytes};

    /// Checks that the trait writes the two keys in order, with the types of
    /// the format. The bytes match a pair built by hand.
    #[test]
    fn writes_the_pair_in_order() {
        let mut builder = DictBuilder::new();
        builder.insert_bootable("6.1.0-test");
        let dict = builder.build();

        let hand = Value::Array(vec![
            Value::Tuple(vec![
                Value::Str(LINUX_KEY.to_owned()),
                Value::variant(Type::Str, Value::Str("6.1.0-test".to_owned())),
            ]),
            Value::Tuple(vec![
                Value::Str(BOOTABLE_KEY.to_owned()),
                Value::variant(Type::Bool, Value::Bool(true)),
            ]),
        ]);
        assert_eq!(dict, hand);

        let ty = Type::parse("a{sv}").unwrap();
        assert_eq!(to_bytes(&ty, &dict).unwrap(), to_bytes(&ty, &hand).unwrap());
    }

    /// Checks that the pair goes after the keys that the builder holds.
    #[test]
    fn appends_after_the_keys_already_inserted() {
        let mut builder = DictBuilder::new();
        builder
            .insert_str("first", "x")
            .insert_bootable("6.1.0-test");
        let dict = builder.build();

        let keys: Vec<&str> = dict
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry.as_tuple().unwrap()[0].as_str().unwrap())
            .collect();
        assert_eq!(keys, ["first", LINUX_KEY, BOOTABLE_KEY]);
    }
}
