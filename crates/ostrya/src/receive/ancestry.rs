//! The fast-forward walk of a ref update: whether the current commit of a ref
//! is in the parent chain of the new commit.

use std::collections::{HashMap, HashSet};
use std::os::fd::AsFd;

use ostrya_core::{Checksum, Commit, ObjectType, loose_path};

use super::session::Failure;
use crate::error::{Error, Result};
use crate::object::{MAX_METADATA_SIZE, read_meta_object};
use crate::transaction::Transaction;

/// The parent of each commit that a walk can read without a read of the
/// repository: every commit of the session, and each stored commit a walk
/// read. `None` is a commit with no parent.
pub(super) type Parents = HashMap<Checksum, Option<Checksum>>;

/// The fast-forward walks of the ref updates of one `Commit`, which share the
/// parent map. Two updates with the same new commit and the same tip share
/// one walk.
pub(super) struct Walks {
    parents: Parents,
    chains: Vec<Chain>,
    /// The chain of each walk, by its new commit and the commit it looked
    /// for first.
    index: HashMap<(Checksum, Checksum), usize>,
}

impl Walks {
    /// Walks that read `parents` before the repository.
    pub(super) fn new(parents: Parents) -> Walks {
        Walks {
            parents,
            chains: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// The chain of the walk from `new` to `target`, walked on the first call
    /// for the pair. Gives its index for [`reaches`](Walks::reaches).
    pub(super) async fn chain(
        &mut self,
        txn: &Transaction,
        new: Checksum,
        target: Checksum,
    ) -> std::result::Result<usize, Failure> {
        if let Some(&i) = self.index.get(&(new, target)) {
            return Ok(i);
        }
        let chain = Chain::walk(txn, &mut self.parents, new, target).await?;
        self.chains.push(chain);
        let i = self.chains.len() - 1;
        self.index.insert((new, target), i);
        Ok(i)
    }

    /// Whether `current` is in the chain `chain`, as [`Chain::reaches`] tells.
    pub(super) async fn reaches(
        &mut self,
        txn: &Transaction,
        chain: usize,
        current: Checksum,
    ) -> std::result::Result<bool, Failure> {
        let Walks {
            parents, chains, ..
        } = self;
        chains[chain].reaches(txn, parents, current).await
    }
}

/// The part of the parent chain of one new commit that a walk read.
struct Chain {
    /// Each commit the walk passed, the new commit included.
    seen: HashSet<Checksum>,
    /// Where the walk stopped.
    end: End,
}

/// Where a walk of the parent chain stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// At the commit the walk looked for.
    Target(Checksum),
    /// At a commit that neither the session nor the repository holds.
    Absent(Checksum),
    /// At a commit with no parent.
    Root,
}

impl Chain {
    /// Walk the parent chain of `new` until `target`, a commit that neither
    /// the session nor the repository holds, or a commit with no parent. The
    /// walk reads `parents` before the repository, and it adds each stored
    /// commit it reads to the map.
    async fn walk(
        txn: &Transaction,
        parents: &mut Parents,
        new: Checksum,
        target: Checksum,
    ) -> std::result::Result<Chain, Failure> {
        let mut chain = Chain {
            seen: HashSet::new(),
            end: End::Root,
        };
        chain.extend(txn, parents, new, target).await?;
        Ok(chain)
    }

    /// Whether `current` is in the parent chain of the new commit, or is the
    /// new commit. Where the part of the chain read so far does not hold
    /// `current`, the walk goes on from the commit it stopped at: past the
    /// target of an earlier walk, because the ref moved since, or at a commit
    /// that was absent, because the repository can hold it now. A chain that
    /// reached a commit with no parent is complete.
    async fn reaches(
        &mut self,
        txn: &Transaction,
        parents: &mut Parents,
        current: Checksum,
    ) -> std::result::Result<bool, Failure> {
        if self.seen.contains(&current) {
            return Ok(true);
        }
        match self.end {
            End::Root => return Ok(false),
            End::Target(from) | End::Absent(from) => {
                self.extend(txn, parents, from, current).await?
            }
        }
        Ok(self.seen.contains(&current))
    }

    /// Walk from `from` until `target`, an absent commit, or a root commit,
    /// and record each commit passed.
    async fn extend(
        &mut self,
        txn: &Transaction,
        parents: &mut Parents,
        from: Checksum,
        target: Checksum,
    ) -> std::result::Result<(), Failure> {
        let mut next = from;
        loop {
            self.seen.insert(next);
            if next == target {
                self.end = End::Target(next);
                return Ok(());
            }
            let parent = match parents.get(&next) {
                Some(&parent) => parent,
                None => match stored_parent(txn, next).await.map_err(Failure::Internal)? {
                    Some(parent) => {
                        parents.insert(next, parent);
                        parent
                    }
                    None => {
                        self.end = End::Absent(next);
                        return Ok(());
                    }
                },
            };
            match parent {
                Some(parent) => next = parent,
                None => {
                    self.end = End::Root;
                    return Ok(());
                }
            }
        }
    }
}

/// The parent of `commit`, read and parsed from `objects/` on the blocking
/// pool: `None` for a commit the repository does not hold. Every commit of
/// the session is in the parent map before a walk, so the walk reads only
/// stored commits, and one that does not parse fails on the server side.
async fn stored_parent(txn: &Transaction, commit: Checksum) -> Result<Option<Option<Checksum>>> {
    let repo = txn.repo();
    let path = loose_path(&commit, ObjectType::Commit, repo.mode());
    let objects = repo.objects_fd().try_clone_to_owned()?;
    ostrya_rt::unblock(move || {
        let bytes = match read_meta_object(objects.as_fd(), &path, MAX_METADATA_SIZE) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        };
        let commit = Commit::parse(&bytes)
            .map_err(|e| Error::InvalidFormat(format!("commit {commit} does not parse: {e}")))?;
        Ok(Some(commit.parent))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CreateOptions, Repo, RepoMode};
    use ostrya_rt::block_on;

    /// A throwaway directory removed on drop.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!(
                "ostrya-ancestry-{tag}-{}-{}",
                std::process::id(),
                crate::write::unique()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sha(bytes: &[u8]) -> Checksum {
        use sha2::Digest;
        Checksum::from_bytes(sha2::Sha256::digest(bytes).into())
    }

    /// The bytes and the checksum of a commit with `parent`.
    fn commit(parent: Option<Checksum>, subject: &str) -> (Checksum, Vec<u8>) {
        let bytes = Commit {
            metadata: ostrya_core::Value::Array(Vec::new()),
            parent,
            related: Vec::new(),
            subject: subject.into(),
            body: String::new(),
            timestamp: 1_700_000_000,
            root_dirtree: sha(b"tree"),
            root_dirmeta: sha(b"meta"),
        }
        .serialize()
        .unwrap();
        (sha(&bytes), bytes)
    }

    /// Store `bytes` as the commit `checksum` through a transaction of its own.
    async fn store(repo: &Repo, checksum: Checksum, bytes: Vec<u8>) {
        let txn = repo.transaction().await.unwrap();
        txn.stage_metadata(checksum, ObjectType::Commit, bytes)
            .await
            .unwrap();
        txn.commit().await.unwrap();
    }

    /// A walk that stopped at its target goes on past it when the ref moved
    /// to an older commit, and a chain that reached the root is complete.
    #[test]
    fn a_walk_goes_on_past_its_target() {
        let scratch = Scratch::new("target");
        block_on(async {
            let repo = Repo::create(
                &scratch.0.join("repo"),
                CreateOptions::new(RepoMode::Archive),
            )
            .await
            .unwrap();
            let (root, root_bytes) = commit(None, "root");
            let (mid, mid_bytes) = commit(Some(root), "mid");
            let (tip, tip_bytes) = commit(Some(mid), "tip");
            store(&repo, root, root_bytes).await;
            store(&repo, mid, mid_bytes).await;
            store(&repo, tip, tip_bytes).await;
            let txn = repo.transaction().await.unwrap();
            let mut walks = Walks::new(Parents::new());
            let chain = walks.chain(&txn, tip, mid).await.map_err(drop).unwrap();
            assert_eq!(walks.chains[chain].end, End::Target(mid));
            assert!(
                !walks.parents.contains_key(&root),
                "the walk stopped at mid"
            );
            assert_eq!(
                walks.chain(&txn, tip, mid).await.map_err(drop).unwrap(),
                chain
            );
            assert!(
                walks
                    .reaches(&txn, chain, root)
                    .await
                    .map_err(drop)
                    .unwrap()
            );
            assert!(walks.reaches(&txn, chain, mid).await.map_err(drop).unwrap());
            let other = sha(b"a commit off the chain");
            assert!(
                !walks
                    .reaches(&txn, chain, other)
                    .await
                    .map_err(drop)
                    .unwrap()
            );
            assert_eq!(walks.chains[chain].end, End::Root);
            txn.abort().await.unwrap();
        });
    }

    /// A walk that stopped at a commit the repository did not hold goes on
    /// from it once the repository holds it.
    #[test]
    fn a_walk_goes_on_from_a_commit_that_became_present() {
        let scratch = Scratch::new("absent");
        block_on(async {
            let repo = Repo::create(
                &scratch.0.join("repo"),
                CreateOptions::new(RepoMode::Archive),
            )
            .await
            .unwrap();
            let (root, root_bytes) = commit(None, "root");
            let (mid, mid_bytes) = commit(Some(root), "mid");
            let (tip, _) = commit(Some(mid), "tip");
            let mut parents = Parents::new();
            parents.insert(tip, Some(mid));
            let txn = repo.transaction().await.unwrap();
            let mut walks = Walks::new(parents);
            let chain = walks.chain(&txn, tip, root).await.map_err(drop).unwrap();
            assert_eq!(walks.chains[chain].end, End::Absent(mid));
            store(&repo, mid, mid_bytes).await;
            store(&repo, root, root_bytes).await;
            assert!(
                walks
                    .reaches(&txn, chain, root)
                    .await
                    .map_err(drop)
                    .unwrap()
            );
            assert_eq!(walks.parents.get(&mid), Some(&Some(root)));
            txn.abort().await.unwrap();
        });
    }
}
