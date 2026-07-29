//! The metadata reading path: loading objects, commits, and trees, and
//! resolving commit state.
//!
//! Metadata objects (commit, dirtree, dirmeta, detached commit metadata) are
//! small and bounded, so they load whole into memory and parse through the
//! `ostrya-core` object model. File content objects have their own path in
//! [`crate::file`], which streams the payload. Every entry point is `async fn`
//! and offloads its syscalls to the blocking pool; a missing object surfaces as
//! [`Error::ObjectNotFound`].

use ostrya_core::{
    Checksum, Commit, DirMeta, DirTree, ObjectType, Type, Value, from_bytes, loose_path,
};

use crate::error::{Error, Result};
use crate::object::{self, MAX_METADATA_SIZE};
use crate::repo::Repo;

/// The completeness state of a commit in the local store.
///
/// A commit is [`Partial`](CommitState::Partial) while a
/// `state/<checksum>.commitpartial` marker is present, which a pull writes
/// before the commit's objects are all local and removes once the commit is
/// complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitState {
    /// The commit and its reachable objects are fully present.
    Normal,
    /// A `.commitpartial` marker is present: the commit may be incomplete.
    Partial,
}

impl Repo {
    /// Load the raw serialized bytes of a metadata object. Views borrow this
    /// buffer. Intended for metadata objects, whose size the format caps.
    pub async fn load_object_bytes(&self, ty: ObjectType, checksum: &Checksum) -> Result<Vec<u8>> {
        let path = loose_path(checksum, ty, self.mode());
        let repo = self.clone();
        let key = *checksum;
        let res = ostrya_rt::unblock(move || {
            object::read_meta_object(repo.objects_fd(), &path, MAX_METADATA_SIZE)
        })
        .await;
        match res {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::ObjectNotFound { checksum: key, ty })
            }
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Load a metadata object as a dynamic [`Value`] tree, parsed against the
    /// object type's GVariant signature. Supports the metadata object types;
    /// other types return [`Error::Unsupported`].
    pub async fn load_variant(&self, ty: ObjectType, checksum: &Checksum) -> Result<Value> {
        // The metadata object GVariant type strings, from `format-reference.md`.
        let signature = match ty {
            ObjectType::DirTree => "(a(say)a(sayay))",
            ObjectType::DirMeta => "(uuua(ayay))",
            ObjectType::Commit => "(a{sv}aya(say)sstayay)",
            ObjectType::CommitMeta => "a{sv}",
            other => {
                return Err(Error::Unsupported(format!(
                    "load_variant does not support {other:?} objects"
                )));
            }
        };
        let bytes = self.load_object_bytes(ty, checksum).await?;
        let ty = Type::parse(signature).map_err(ostrya_core::Error::from)?;
        Ok(from_bytes(&ty, &bytes).map_err(ostrya_core::Error::from)?)
    }

    /// Load and parse a commit object together with its completeness state.
    pub async fn load_commit(&self, checksum: &Checksum) -> Result<(Commit, CommitState)> {
        let bytes = self.load_object_bytes(ObjectType::Commit, checksum).await?;
        let commit = Commit::parse(&bytes)?;
        let state = self.commit_state(checksum).await?;
        Ok((commit, state))
    }

    /// Load and parse a dirtree object.
    pub async fn load_dirtree(&self, checksum: &Checksum) -> Result<DirTree> {
        let bytes = self
            .load_object_bytes(ObjectType::DirTree, checksum)
            .await?;
        Ok(DirTree::parse(&bytes)?)
    }

    /// Load and parse a dirmeta object.
    pub async fn load_dirmeta(&self, checksum: &Checksum) -> Result<DirMeta> {
        let bytes = self
            .load_object_bytes(ObjectType::DirMeta, checksum)
            .await?;
        Ok(DirMeta::parse(&bytes)?)
    }

    /// The on-disk (compressed) size of a loose object, used to recover an
    /// `ostree.sizes` record for an object that deduplicated against `objects/`.
    pub(crate) async fn loose_object_size(
        &self,
        ty: ObjectType,
        checksum: &Checksum,
    ) -> Result<u64> {
        let path = loose_path(checksum, ty, self.mode());
        let repo = self.clone();
        let key = *checksum;
        let res = ostrya_rt::unblock(move || object::object_size(repo.objects_fd(), &path)).await;
        match res {
            Ok(size) => Ok(size),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::ObjectNotFound { checksum: key, ty })
            }
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Whether a loose object of the given type is present.
    pub async fn has_object(&self, ty: ObjectType, checksum: &Checksum) -> Result<bool> {
        let path = loose_path(checksum, ty, self.mode());
        let repo = self.clone();
        ostrya_rt::unblock(move || object::object_exists(repo.objects_fd(), &path)).await
    }

    /// The completeness state of a commit: [`Partial`](CommitState::Partial)
    /// when a `.commitpartial` marker is present, else
    /// [`Normal`](CommitState::Normal).
    pub async fn commit_state(&self, checksum: &Checksum) -> Result<CommitState> {
        let path = crate::pull::partial_path(checksum);
        let repo = self.clone();
        let partial =
            ostrya_rt::unblock(move || object::object_exists(repo.repo_fd(), &path)).await?;
        Ok(if partial {
            CommitState::Partial
        } else {
            CommitState::Normal
        })
    }
}
