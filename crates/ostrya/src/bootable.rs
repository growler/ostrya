//! The kernel version a bootable commit records, and the metadata pair that
//! carries it.
//!
//! A bootable commit holds `ostree.linux` and `ostree.bootable`. `ostree.linux`
//! is the name of the one directory under `/usr/lib/modules` in the commit's
//! tree that holds an entry named `vmlinuz`, and `ostree.bootable` is `true`
//! beside it (`docs/format-reference.md`, "CLI output formats", `commit`).
//!
//! The search is one level deep under `/usr/lib/modules`. An entry there that
//! is not a directory takes no part, and the type of the `vmlinuz` entry is not
//! read: a regular file, a symlink, and a directory of that name each count.
//!
//! Four tree shapes give no kernel version, and [`BootableRefusal`] names them.
//! They are outcomes of the search rather than failures of it, so they arrive
//! through the inner `Result` and leave the outer one for the object reads.
//!
//! The search runs over a staged tree through
//! [`Transaction::kernel_version`] and over a published one through
//! [`RepoTree::kernel_version`]. A caller deriving the pair for a commit it is
//! about to write uses the first; a caller reading a deployment uses the second.
//!
//! [`BootableMetadata`] adds the pair to a [`DictBuilder`] in the order the pair
//! holds on disk.

use ostrya_core::DictBuilder;

use crate::error::Result;
use crate::transaction::Transaction;
use crate::tree::{RepoTree, TreeEntry};

/// The commit metadata key holding the kernel directory's name.
const LINUX_KEY: &str = "ostree.linux";
/// The commit metadata key marking a commit as bootable.
const BOOTABLE_KEY: &str = "ostree.bootable";
/// The directory the search reads, one level deep, for the kernel.
const MODULES_DIR: &str = "/usr/lib/modules";
/// The entry name a kernel directory must hold.
const KERNEL_ENTRY: &str = "vmlinuz";

/// A tree shape that names no kernel version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootableRefusal {
    /// The tree does not hold this component of `/usr/lib/modules`. The path is
    /// absolute and names the first component that is absent.
    MissingComponent {
        /// The absolute path of the absent component.
        path: String,
    },
    /// The tree holds this component of `/usr/lib/modules` as something other
    /// than a directory. A regular file and a symlink both reach this.
    NotADirectory {
        /// The absolute path of the component that is not a directory.
        path: String,
    },
    /// No directory under `/usr/lib/modules` holds an entry named `vmlinuz`.
    NoKernel,
    /// More than one directory under `/usr/lib/modules` holds an entry named
    /// `vmlinuz`, so no single version names the tree.
    MultipleKernels,
}

/// Where the search reads the tree's directories.
#[derive(Clone, Copy)]
enum DirSource<'a> {
    /// A published repository: every dirtree is a loose object under
    /// `objects/`.
    Published,
    /// A transaction: a dirtree it staged is read from the staging directory,
    /// and one that deduplicated from `objects/`.
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

impl Transaction {
    /// The kernel version of a tree this transaction assembled, the value
    /// `ostree.linux` holds.
    ///
    /// The tree is read through [`Transaction::read_dir`], so the search sees
    /// the objects this transaction staged as well as those already in
    /// `objects/`. That makes the version available before the transaction
    /// publishes, which is what a caller deriving the metadata of the commit it
    /// is about to write needs.
    ///
    /// The outer `Result` carries the object reads. The inner one carries the
    /// four tree shapes that name no version.
    pub async fn kernel_version(
        &self,
        root: &RepoTree,
    ) -> Result<std::result::Result<String, BootableRefusal>> {
        kernel_version(DirSource::Staged(self), root).await
    }
}

impl RepoTree {
    /// The kernel version of this tree, the value `ostree.linux` holds.
    ///
    /// The tree is read through [`RepoTree::read_dir`], which reads `objects/`
    /// alone, so the search sees a tree only once the transaction that
    /// assembled it has committed. [`Transaction::kernel_version`] covers a tree
    /// that is still staged.
    ///
    /// The outer `Result` carries the object reads. The inner one carries the
    /// four tree shapes that name no version.
    pub async fn kernel_version(&self) -> Result<std::result::Result<String, BootableRefusal>> {
        kernel_version(DirSource::Published, self).await
    }
}

/// The one walk both entry points expose: descend `/usr/lib/modules` from
/// `root`, then take the name of the single child directory holding `vmlinuz`.
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

/// The name of a directory entry, whichever kind it is.
fn entry_name(entry: &TreeEntry) -> &str {
    match entry {
        TreeEntry::File { name, .. } | TreeEntry::Dir { name, .. } => name,
    }
}

/// The bootable pair, added to a metadata dict under construction.
pub trait BootableMetadata {
    /// Append `ostree.linux` holding `kernel_version`, then `ostree.bootable`
    /// holding true.
    ///
    /// The pair goes in at the position the builder has reached, so a caller
    /// that has already inserted its own keys puts the pair after them. The
    /// tool writes the pair at the head of the dict, ahead of every other key,
    /// and a commit whose dict holds the pair elsewhere carries another
    /// checksum for the same tree.
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

    /// The pair the trait writes: the two keys, in that order, with the types
    /// the format states, and the same bytes as the pair assembled by hand.
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

    /// The pair appends, so keys inserted before it stand ahead of it.
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
