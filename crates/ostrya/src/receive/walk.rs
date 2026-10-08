//! The completeness walk of the commits of a push session. The walk checks that
//! each object that the tree of a commit reaches is staged in the session or
//! present in the repository.

use std::collections::HashSet;
use std::os::fd::AsFd;
use std::sync::Arc;

use ostrya_core::{Checksum, DirTree, ObjectName, ObjectType, loose_path};

use super::session::Failure;
use crate::error::{Error, Result};
use crate::object::{MAX_METADATA_SIZE, object_exists, read_meta_object};
use crate::push::{self, proto::MAX_HAVE};
use crate::transaction::Transaction;
use crate::write::flat_name;

/// The objects the walk did not find.
#[derive(Debug, Default)]
pub(super) struct Missing {
    /// The first missing objects in the order the walk met them, at most
    /// `MAX_HAVE` of them. An `Error` frame that lists them then fits the
    /// frame limit.
    pub(super) listed: Vec<ObjectName>,
    /// The number of missing objects.
    pub(super) total: usize,
}

impl Missing {
    pub(super) fn add(&mut self, name: ObjectName) {
        self.total += 1;
        if self.listed.len() < MAX_HAVE as usize {
            self.listed.push(name);
        }
    }
}

/// Walks the trees of `roots` and returns the objects that neither the
/// session nor the repository holds.
///
/// Each root is a root dirtree and its root dirmeta. The walk reads a staged
/// dirtree from the staging directory and each other dirtree from `objects/`.
/// It reads each subtree of a dirtree, also of a dirtree that the repository
/// holds. It checks each object once, also if more than one root reaches it.
///
/// A dirmeta or a content object that the session staged needs no check. The
/// walk probes the other objects in one batch with the read of the next
/// dirtree. This gives one trip to the blocking pool for each dirtree, and at
/// most one more trip at the end.
///
/// If a staged dirtree does not parse, the walk returns a `protocol` error to
/// the client (`Failure::Wire`), because the client sent the dirtree. If a
/// stored dirtree does not parse, or if an I/O error occurs, the failure is on
/// the server side (`Failure::Internal`).
pub(super) async fn completeness(
    txn: &Transaction,
    roots: impl IntoIterator<Item = (Checksum, Checksum)>,
) -> std::result::Result<Missing, Failure> {
    let mut walk = Walk {
        txn,
        seen: HashSet::new(),
        trees: Vec::new(),
        probes: Vec::new(),
        missing: Missing::default(),
    };
    for (dirtree, dirmeta) in roots {
        walk.visit(ObjectName::new(dirmeta, ObjectType::DirMeta));
        walk.visit(ObjectName::new(dirtree, ObjectType::DirTree));
    }
    walk.run().await?;
    Ok(walk.missing)
}

struct Walk<'a> {
    txn: &'a Transaction,
    /// Every object that the walk met.
    seen: HashSet<ObjectName>,
    /// The dirtrees to read.
    trees: Vec<Checksum>,
    /// The dirmeta and content objects to probe in `objects/`.
    probes: Vec<ObjectName>,
    missing: Missing,
}

/// Where the walk reads one dirtree from.
enum TreeSource {
    Staged(String),
    Stored(String),
}

impl Walk<'_> {
    /// Records one object and queues it for a read or a probe.
    ///
    /// A dirtree goes in the read queue. Another object goes in the probe
    /// queue if the session did not stage it. The walk skips an object that it
    /// met before.
    fn visit(&mut self, name: ObjectName) {
        if !self.seen.insert(name) {
            return;
        }
        if name.ty == ObjectType::DirTree {
            self.trees.push(name.checksum);
        } else if !self.txn.is_staged(&name.checksum, name.ty) {
            self.probes.push(name);
        }
    }

    async fn run(&mut self) -> std::result::Result<(), Failure> {
        let repo = self.txn.repo();
        let mode = repo.mode();
        let clone = |fd: std::os::fd::BorrowedFd<'_>| {
            fd.try_clone_to_owned()
                .map(Arc::new)
                .map_err(|e| Failure::Internal(e.into()))
        };
        let objects = clone(repo.objects_fd())?;
        let staging = clone(self.txn.staging_fd())?;
        loop {
            let tree = self.trees.pop();
            if tree.is_none() && self.probes.is_empty() {
                return Ok(());
            }
            let probes = std::mem::take(&mut self.probes);
            let source = tree.map(|checksum| {
                let source = if self.txn.is_staged(&checksum, ObjectType::DirTree) {
                    TreeSource::Staged(flat_name(&checksum, ObjectType::DirTree, mode))
                } else {
                    TreeSource::Stored(loose_path(&checksum, ObjectType::DirTree, mode))
                };
                (checksum, source)
            });
            let objects = Arc::clone(&objects);
            let staging = Arc::clone(&staging);
            // The blocking pool parses the dirtree with its read, so a large
            // dirtree does not hold the async executor.
            let (probes, present, read) = ostrya_rt::unblock(move || -> Result<_> {
                let present = probes
                    .iter()
                    .map(|n| object_exists(objects.as_fd(), &loose_path(&n.checksum, n.ty, mode)))
                    .collect::<Result<Vec<bool>>>()?;
                let read = match source {
                    None => None,
                    Some((checksum, TreeSource::Staged(name))) => {
                        let bytes = read_meta_object(staging.as_fd(), &name, MAX_METADATA_SIZE)?;
                        Some((checksum, true, Some(DirTree::parse(&bytes))))
                    }
                    Some((checksum, TreeSource::Stored(path))) => {
                        match read_meta_object(objects.as_fd(), &path, MAX_METADATA_SIZE) {
                            Ok(bytes) => Some((checksum, false, Some(DirTree::parse(&bytes)))),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                Some((checksum, false, None))
                            }
                            Err(e) => return Err(Error::Io(e)),
                        }
                    }
                };
                Ok((probes, present, read))
            })
            .await
            .map_err(Failure::Internal)?;
            for (name, present) in probes.into_iter().zip(present) {
                if !present {
                    self.missing.add(name);
                }
            }
            let Some((checksum, staged, parsed)) = read else {
                continue;
            };
            let Some(parsed) = parsed else {
                self.missing
                    .add(ObjectName::new(checksum, ObjectType::DirTree));
                continue;
            };
            let dirtree = parsed.map_err(|e| {
                let message = format!("dirtree {checksum} does not parse: {e}");
                if staged {
                    Failure::Wire(push::Error::Protocol(message))
                } else {
                    Failure::Internal(Error::InvalidFormat(message))
                }
            })?;
            for (_, file) in dirtree.files {
                self.visit(ObjectName::new(file, ObjectType::File));
            }
            for (_, subtree, submeta) in dirtree.dirs {
                self.visit(ObjectName::new(submeta, ObjectType::DirMeta));
                self.visit(ObjectName::new(subtree, ObjectType::DirTree));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CreateOptions, DirMeta, Repo, RepoMode};
    use ostrya_core::Xattrs;
    use ostrya_rt::block_on;

    /// A throwaway directory removed on drop.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!(
                "ostrya-walk-{tag}-{}-{}",
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

    /// A tree whose root holds two subdirectories that share one subtree and
    /// one dirmeta, and a file that the session did not send. The walk reports
    /// the file once and reads the shared subtree once.
    #[test]
    fn an_object_reached_twice_is_checked_once() {
        let scratch = Scratch::new("twice");
        block_on(async {
            let repo = Repo::create(
                &scratch.0.join("repo"),
                CreateOptions::new(RepoMode::Archive),
            )
            .await
            .unwrap();
            let txn = repo.transaction().await.unwrap();
            let absent = sha(b"a file the session did not send");
            let meta = DirMeta {
                uid: 0,
                gid: 0,
                mode: 0o40755,
                xattrs: Xattrs::empty(),
            }
            .serialize()
            .unwrap();
            let meta_sum = sha(&meta);
            txn.stage_metadata(meta_sum, ObjectType::DirMeta, meta)
                .await
                .unwrap();
            let sub = DirTree {
                files: vec![("f".into(), absent)],
                dirs: vec![],
            }
            .serialize()
            .unwrap();
            let sub_sum = sha(&sub);
            txn.stage_metadata(sub_sum, ObjectType::DirTree, sub)
                .await
                .unwrap();
            let root = DirTree {
                files: vec![("g".into(), absent)],
                dirs: vec![
                    ("a".into(), sub_sum, meta_sum),
                    ("b".into(), sub_sum, meta_sum),
                ],
            }
            .serialize()
            .unwrap();
            let root_sum = sha(&root);
            txn.stage_metadata(root_sum, ObjectType::DirTree, root)
                .await
                .unwrap();

            let mut walk = Walk {
                txn: &txn,
                seen: HashSet::new(),
                trees: Vec::new(),
                probes: Vec::new(),
                missing: Missing::default(),
            };
            walk.visit(ObjectName::new(meta_sum, ObjectType::DirMeta));
            walk.visit(ObjectName::new(root_sum, ObjectType::DirTree));
            // A second root over the same tree adds nothing.
            walk.visit(ObjectName::new(meta_sum, ObjectType::DirMeta));
            walk.visit(ObjectName::new(root_sum, ObjectType::DirTree));
            assert_eq!(walk.trees, vec![root_sum]);
            assert!(walk.probes.is_empty(), "a staged dirmeta needs no probe");
            walk.run().await.map_err(|_| "walk failed").unwrap();
            assert_eq!(walk.missing.total, 1);
            assert_eq!(
                walk.missing.listed,
                vec![ObjectName::new(absent, ObjectType::File)]
            );
            assert_eq!(walk.seen.len(), 4, "root, subtree, dirmeta, file");
            txn.abort().await.unwrap();
        });
    }

    /// The missing list holds the first `MAX_HAVE` objects, in the order the
    /// walk met them, and the count holds every missing object.
    #[test]
    fn the_missing_list_stops_at_max_have() {
        let mut missing = Missing::default();
        let extra = 5;
        let names: Vec<ObjectName> = (0..MAX_HAVE as usize + extra)
            .map(|i| ObjectName::new(sha(&i.to_le_bytes()), ObjectType::File))
            .collect();
        for name in &names {
            missing.add(*name);
        }
        assert_eq!(missing.total, names.len());
        assert_eq!(missing.listed, names[..MAX_HAVE as usize]);
    }

    /// A dirtree that the repository does not hold is missing, and the walk
    /// does not read its subtrees.
    #[test]
    fn an_absent_dirtree_is_missing() {
        let scratch = Scratch::new("absent-tree");
        block_on(async {
            let repo = Repo::create(
                &scratch.0.join("repo"),
                CreateOptions::new(RepoMode::Archive),
            )
            .await
            .unwrap();
            let txn = repo.transaction().await.unwrap();
            let tree = sha(b"tree");
            let meta = sha(b"meta");
            let missing = completeness(&txn, [(tree, meta)])
                .await
                .map_err(|_| "walk failed")
                .unwrap();
            assert_eq!(missing.total, 2);
            let mut listed = missing.listed;
            listed.sort_by_key(|n| n.ty as u8);
            assert_eq!(
                listed,
                vec![
                    ObjectName::new(tree, ObjectType::DirTree),
                    ObjectName::new(meta, ObjectType::DirMeta),
                ]
            );
            txn.abort().await.unwrap();
        });
    }
}
