//! The fast-forward walk of a ref update. The walk checks if the current
//! commit of a ref is in the parent chain of the new commit.

use std::collections::{HashMap, HashSet};
use std::os::fd::AsFd;

use ostrya_core::{Checksum, Commit, ObjectType, loose_path};

use super::session::Failure;
use crate::error::{Error, Result};
use crate::object::{MAX_METADATA_SIZE, read_meta_object};
use crate::transaction::Transaction;

/// The parent of each commit that a walk can read without a read of the
/// repository.
///
/// The map holds each commit of the session and each stored commit that a
/// walk read. A `None` value is a commit with no parent.
pub(super) type Parents = HashMap<Checksum, Option<Checksum>>;

/// The fast-forward walks of the ref updates of one `Commit`.
///
/// The walks share the parent map. Two updates with the same new commit and
/// the same tip share one walk.
pub(super) struct Walks {
    parents: Parents,
    chains: Vec<Chain>,
    /// The chain of each walk, keyed by its new commit and the commit that it
    /// looked for first.
    index: HashMap<(Checksum, Checksum), usize>,
}

impl Walks {
    /// Creates the walks of one `Commit`, which read `parents` before the
    /// repository.
    pub(super) fn new(parents: Parents) -> Walks {
        Walks {
            parents,
            chains: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Returns the index of the chain of the walk from `new` to `target`.
    ///
    /// The first call for the pair walks the chain.
    /// [`reaches`](Walks::reaches) takes the index.
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

    /// Returns `true` if `current` is in the chain `chain`, as
    /// [`Chain::reaches`] states.
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
    /// Each commit that the walk passed, also the new commit.
    seen: HashSet<Checksum>,
    /// Where the walk stopped.
    end: End,
}

/// Where a walk of the parent chain stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// At the commit that the walk looked for.
    Target(Checksum),
    /// At a commit that neither the session nor the repository holds.
    Absent(Checksum),
    /// At a commit with no parent.
    Root,
}

impl Chain {
    /// Walks the parent chain of `new` to `target`, to an absent commit, or to
    /// a commit with no parent.
    ///
    /// An absent commit is a commit that neither the session nor the
    /// repository holds. The walk reads `parents` before the repository. It
    /// adds each stored commit that it reads to the map.
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

    /// Returns `true` if `current` is in the parent chain of the new commit,
    /// or is the new commit.
    ///
    /// If the part of the chain that the walk read does not hold `current`,
    /// the walk goes on from the commit where it stopped. This can be the
    /// target of an earlier walk, because the ref moved after that walk. It
    /// can also be a commit that was absent, because the repository can hold
    /// it now. A chain that reached a commit with no parent is complete.
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

    /// Walks from `from` to `target`, to an absent commit, or to a root
    /// commit, and records each commit that it passes.
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

/// Returns the parent of `commit`, which the call reads from `objects/` and
/// parses on the blocking pool.
///
/// The outer `None` is a commit that the repository does not hold. Each
/// commit of the session is in the parent map before a walk, so the walk
/// reads only stored commits. A stored commit that does not parse is a
/// failure of the server side.
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

    /// A temporary directory that is removed on drop.
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

    /// Returns the checksum and the bytes of a commit with `parent`.
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

    /// Stores `bytes` as the commit `checksum` in a transaction of its own.
    async fn store(repo: &Repo, checksum: Checksum, bytes: Vec<u8>) {
        let txn = repo.transaction().await.unwrap();
        txn.stage_metadata(checksum, ObjectType::Commit, bytes)
            .await
            .unwrap();
        txn.commit().await.unwrap();
    }

    /// A walk that stopped at its target goes on past it if the ref moved to
    /// an older commit. A chain that reached the root is complete.
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

    /// A walk that stopped at a commit that the repository did not hold goes
    /// on from it after the repository holds it.
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
