//! Ref resolution, listing, and writes.
//!
//! A ref is a file under `refs/` that names a commit by its checksum. The
//! entry points are:
//!
//! - [`Repo::resolve_rev`] resolves a revision string to a commit. Its doc
//!   gives the revision syntax.
//! - [`Repo::resolve_ref_tip`] reads one ref from the ref store.
//! - [`Repo::list_refs`], [`Repo::list_remote_refs`],
//!   [`Repo::list_mirror_refs`], [`Repo::list_collection_refs`], and
//!   [`Repo::list_ref_aliases`] list refs.
//! - [`Repo::set_ref_immediate`] writes one ref outside a transaction. Its doc
//!   gives the ref file format and the durability rules.
//! - [`Transaction::set_ref`] queues a ref write for the transaction commit.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
#[cfg(feature = "receive")]
use std::sync::Arc;

use ostrya_core::{Checksum, RefPattern, RefSelector, RepoMode};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::access::{Namespace, ReadAccess};
use crate::archive::{Walked, resolve_alias, walk};
use crate::error::{Error, Result};
use crate::perm;
use crate::repo::Repo;
use crate::staging::{REF_TEMP_PREFIX, TempEntry, open_tmp_dir};
use crate::summary::SelectionFloor;
use crate::transaction::Transaction;
use crate::traverse::read_dir_names;

/// A ref name with an optional collection id.
///
/// A ref with a collection id maps to `refs/mirrors/<collection>/<name>`. A
/// ref with no collection id maps to the local ref `refs/heads/<name>`. The
/// collection id is one path component: it is not `.` or `..`, it holds no
/// `/`, and it can hold dots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionRef {
    /// The collection id, or `None` for a local ref.
    pub collection_id: Option<String>,
    /// The ref name, which can contain `/`.
    pub ref_name: String,
}

impl CollectionRef {
    /// Creates a ref bound to a collection id.
    pub fn new(collection_id: impl Into<String>, ref_name: impl Into<String>) -> CollectionRef {
        CollectionRef {
            collection_id: Some(collection_id.into()),
            ref_name: ref_name.into(),
        }
    }

    /// Creates a local ref with no collection id.
    pub fn local(ref_name: impl Into<String>) -> CollectionRef {
        CollectionRef {
            collection_id: None,
            ref_name: ref_name.into(),
        }
    }
}

/// One collection-qualified ref of a repository.
///
/// [`Repo::list_collection_refs`] returns these entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionRefEntry {
    /// The collection id that qualifies the ref.
    pub collection: String,
    /// The ref name.
    ///
    /// For a local ref, this is its refspec.
    pub name: String,
    /// The commit that the ref names.
    pub commit: Checksum,
    /// `true` for a ref under `refs/heads`, `false` for a ref under
    /// `refs/mirrors`.
    ///
    /// The collection id of the repository qualifies a ref under `refs/heads`.
    pub local: bool,
}

/// A ref stored as an alias: a relative symlink to the file of another ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefAlias {
    /// The refspec of the alias itself.
    pub refspec: String,
    /// The symlink target, as stored.
    pub target: String,
}

/// A queued ref target: a refspec or a collection ref.
enum QueuedRef {
    Ref(String),
    Collection(CollectionRef),
}

impl QueuedRef {
    /// Returns the path under `refs/` that this target writes to. Refuses a
    /// name that leaves the tree.
    fn relpath(&self) -> Result<String> {
        match self {
            QueuedRef::Ref(refspec) => refspec_to_relpath(refspec),
            QueuedRef::Collection(cref) => collection_ref_to_relpath(cref),
        }
    }
}

/// The state of one ref path, as the receive path reads it under its lock.
#[cfg(feature = "receive")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefFileState {
    /// No file stands at the path.
    Absent,
    /// A ref file, and the commit it names.
    Commit(Checksum),
    /// A symlink: an alias of another ref.
    Alias,
    /// Something a ref write cannot replace: a directory, a path that passes
    /// through a file, or a special file.
    NotARef,
}

/// One queued ref write: a target and the checksum to point it at (`None`
/// removes the ref).
pub(crate) struct RefWrite {
    target: QueuedRef,
    checksum: Option<Checksum>,
}

/// Methods that queue ref writes for the transaction commit.
impl Transaction {
    /// Queues a ref write for the transaction commit.
    ///
    /// [`commit`](Transaction::commit) writes the ref after it publishes the
    /// objects. If `checksum` is `None`, the commit removes the ref. The
    /// commit checks the refspec before it publishes any object.
    pub fn set_ref(&self, refspec: &str, checksum: Option<&Checksum>) {
        self.refs.lock().unwrap().push(RefWrite {
            target: QueuedRef::Ref(refspec.to_owned()),
            checksum: checksum.copied(),
        });
    }

    /// Queues a collection ref write for the transaction commit.
    ///
    /// [`commit`](Transaction::commit) writes the ref after it publishes the
    /// objects. If `checksum` is `None`, the commit removes the ref. The
    /// commit checks the collection id and the ref name before it publishes
    /// any object.
    pub fn set_collection_ref(&self, cref: &CollectionRef, checksum: Option<&Checksum>) {
        self.refs.lock().unwrap().push(RefWrite {
            target: QueuedRef::Collection(cref.clone()),
            checksum: checksum.copied(),
        });
    }

    /// Maps each queued ref to its path under `refs/`. A malformed refspec
    /// fails the call. [`commit`](Transaction::commit) calls it first, so a
    /// malformed refspec fails before the commit publishes any object.
    pub(crate) fn resolve_ref_queue(&self) -> Result<Vec<(String, Option<Checksum>)>> {
        let queue = self.refs.lock().unwrap();
        queue
            .iter()
            .map(|w| Ok((w.target.relpath()?, w.checksum)))
            .collect()
    }
}

/// Writes the resolved refs of a transaction, each one atomically, on the
/// blocking pool.
///
/// The call uses the fsync policy that the transaction resolved, so the
/// object writes, the publication step, and the ref writes read one value.
///
/// The durability invariant: with fsync on, each ref file is `fdatasync`-ed
/// before its rename. After the last rename, each directory that gained or
/// lost a name is `fsync`-ed once, deepest first, before the call returns.
///
/// Before the call, the caller made durable the objects and the detached
/// metadata that the refs name. So no ref is durable before what it names. A
/// write that fails still syncs the directories of the refs written before
/// it.
///
/// `tmp_fd` is the open `tmp/` of the repository. Each ref write creates its
/// temp file there.
pub(crate) fn write_resolved_refs_blocking(
    repo_fd: BorrowedFd<'_>,
    tmp_fd: BorrowedFd<'_>,
    refs: &[(String, Option<Checksum>)],
    fsync: bool,
    repo_mode: RepoMode,
) -> Result<()> {
    let mut dirs = Vec::new();
    let written = refs
        .iter()
        .try_for_each(|(relpath, checksum)| match checksum {
            Some(checksum) => put_ref_file_blocking(
                repo_fd, tmp_fd, relpath, *checksum, fsync, repo_mode, &mut dirs,
            ),
            None => remove_ref_blocking(repo_fd, relpath, fsync, &mut dirs),
        });
    if !fsync {
        return written;
    }
    let synced = sync_ref_dirs(repo_fd, dirs);
    written.and(synced)
}

/// The largest ref file that the reader loads. A ref file is 65 bytes.
const REF_READ_CAP: u64 = 4096;

/// Methods that resolve, list, and write refs.
impl Repo {
    /// Resolves a revision string to a commit checksum.
    ///
    /// If the revision names no ref, `allow_noent` selects the result:
    /// `Ok(None)` if it is `true`, and [`Error::RefNotFound`] if it is
    /// `false`. No other failure depends on `allow_noent`.
    ///
    /// # Revision syntax
    ///
    /// A revision is a base, followed by zero or more `^` characters. The call
    /// tries these forms of the base in this order:
    ///
    /// 1. A full checksum: 64 lowercase hex characters. It resolves to itself.
    ///    The call does not check that the commit object exists.
    /// 2. An abbreviated checksum: 1 to 63 lowercase hex characters. It
    ///    resolves to the one commit object whose checksum starts with it.
    /// 3. A refspec. It resolves to the commit that the ref names, as
    ///    [`resolve_ref_tip`](Repo::resolve_ref_tip) reads it.
    ///
    /// A checksum is in lowercase hex only. A 64-character name with an
    /// uppercase character is a refspec.
    ///
    /// Only commit objects match an abbreviated checksum. A `dirtree`, a
    /// `dirmeta`, or a file object with the same prefix does not match.
    ///
    /// An abbreviated checksum comes before the ref store. If a hex name is
    /// also a ref, and a commit checksum starts with that name, the name
    /// resolves to the commit. If no commit checksum starts with the name,
    /// the name resolves as a refspec.
    ///
    /// Each `^` steps one generation back along the `parent` field of the
    /// commit.
    ///
    /// # Errors
    ///
    /// - [`Error::RefNotFound`] if the base names no ref and `allow_noent` is
    ///   `false`.
    /// - [`Error::InvalidRefspec`] if the base is not a checksum and not a
    ///   valid refspec.
    /// - [`Error::AmbiguousRefspec`] if more than one commit checksum starts
    ///   with the abbreviated checksum.
    /// - [`Error::NoParentCommit`] if a `^` steps back from a commit with no
    ///   parent.
    /// - [`Error::ObjectNotFound`] if a `^` step reads a commit that is not in
    ///   the repository.
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8.
    /// - [`Error::Core`] if a ref file holds no checksum, or a commit object
    ///   does not parse.
    /// - [`Error::Io`] if a read from the file system fails.
    pub async fn resolve_rev(&self, rev: &str, allow_noent: bool) -> Result<Option<Checksum>> {
        Ok(self
            .resolve_rev_kind(rev, allow_noent)
            .await?
            .map(|(checksum, _)| checksum))
    }

    /// Resolves a revision as [`resolve_rev`](Repo::resolve_rev) does, and
    /// also returns the kind of its base.
    ///
    /// The kind is the kind of name that the base of `rev` resolved as: a
    /// full or an abbreviated checksum, or a ref.
    pub(crate) async fn resolve_rev_kind(
        &self,
        rev: &str,
        allow_noent: bool,
    ) -> Result<Option<(Checksum, RevKind)>> {
        let (base, generations) = split_ancestry(rev);
        let Some((mut checksum, kind)) = self.resolve_base_rev(base, allow_noent).await? else {
            return Ok(None);
        };
        for _ in 0..generations {
            let (commit, _) = self.load_commit(&checksum).await?;
            checksum = commit.parent.ok_or(Error::NoParentCommit(checksum))?;
        }
        Ok(Some((checksum, kind)))
    }

    /// Resolves a revision with no ancestry suffix: a full checksum, an
    /// abbreviated checksum, or a refspec, tried in that order. The result
    /// holds the kind that the revision resolved as.
    ///
    /// A 64-character name is a checksum only in lowercase hex, so an
    /// uppercase or mixed-case name of that length is a refspec. The checksum
    /// parser keeps its case tolerance where it reads a checksum from stored
    /// bytes: ref file content and delta metadata.
    ///
    /// A shorter run of lowercase hex is an abbreviated checksum, and it comes
    /// before the ref store. If the store also holds a ref of that name, the
    /// name resolves to the commit that it prefixes. The call does not read
    /// the ref target.
    ///
    /// A prefix that no commit object has falls through to the ref store. So
    /// a hex name is a ref name while no commit starts with it.
    async fn resolve_base_rev(
        &self,
        rev: &str,
        allow_noent: bool,
    ) -> Result<Option<(Checksum, RevKind)>> {
        if let Ok(checksum) = Checksum::from_hex_lower(rev) {
            return Ok(Some((checksum, RevKind::Checksum)));
        }

        if is_abbreviated_checksum(rev) {
            let repo = self.clone();
            let prefix = rev.to_owned();
            match ostrya_rt::unblock(move || match_abbreviated(repo.objects_fd(), &prefix)).await? {
                AbbrevMatch::One(checksum) => return Ok(Some((checksum, RevKind::Checksum))),
                AbbrevMatch::Ambiguous => return Err(Error::AmbiguousRefspec(rev.to_owned())),
                AbbrevMatch::None => {}
            }
        }

        match self.resolve_ref_tip(rev).await? {
            Some(checksum) => Ok(Some((checksum, RevKind::Ref))),
            None if allow_noent => Ok(None),
            None => Err(Error::RefNotFound(rev.to_owned())),
        }
    }

    /// Returns the commit that a refspec names, read from the ref store only.
    ///
    /// The call does not read `refspec` as a checksum, as an abbreviated
    /// checksum, or with a `^` suffix. If the ref is an alias, the call
    /// follows the link. The result is `None` if the store holds no such ref.
    ///
    /// Callers that hold a ref name and not a revision use this call. These
    /// are a pull for its local tip, a summary for the metadata ref that it
    /// chains, and the CLI for its alias-target check. An alias records a
    /// name, so the CLI uses this call.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if `refspec` is not a valid refspec.
    /// - [`Error::InvalidFormat`] if the ref file is not UTF-8.
    /// - [`Error::Core`] if the ref file holds no checksum.
    /// - [`Error::Io`] if the read fails, for example if the ref path names a
    ///   directory.
    pub async fn resolve_ref_tip(&self, refspec: &str) -> Result<Option<Checksum>> {
        self.resolve_relpath_tip(refspec_to_relpath(refspec)?).await
    }

    /// Returns the commit that the ref file at `relpath` names, read as
    /// [`resolve_ref_tip`](Repo::resolve_ref_tip) reads a refspec. The call
    /// follows an alias. The result is `None` if no file is at the path.
    ///
    /// The read and the parse run in one call on the blocking pool.
    pub(crate) async fn resolve_relpath_tip(&self, relpath: String) -> Result<Option<Checksum>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || repo.resolve_relpath_tip_blocking(&relpath)).await
    }

    /// Runs [`resolve_relpath_tip`](Repo::resolve_relpath_tip) on the calling
    /// thread.
    pub(crate) fn resolve_relpath_tip_blocking(&self, relpath: &str) -> Result<Option<Checksum>> {
        match read_ref_file(self.repo_fd(), relpath)? {
            Some(bytes) => Ok(Some(parse_ref_content(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Returns the commits of the ref files at several paths under `refs/`,
    /// each read as [`resolve_ref_tip`](Repo::resolve_ref_tip) reads a
    /// refspec, in one pass on the blocking pool. The result holds one entry
    /// for each path, in order. A ref path that names a directory, or that
    /// passes through a file, holds no ref and reads as absent.
    #[cfg(feature = "receive")]
    pub(crate) async fn resolve_relpath_tips(
        &self,
        relpaths: Arc<[String]>,
    ) -> Result<Vec<Option<Checksum>>> {
        let repo = self.clone();
        let contents = ostrya_rt::unblock(move || {
            relpaths
                .iter()
                .map(|p| match read_ref_file(repo.repo_fd(), p) {
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::IsADirectory | std::io::ErrorKind::NotADirectory
                        ) =>
                    {
                        Ok(None)
                    }
                    other => other,
                })
                .collect::<std::io::Result<Vec<_>>>()
        })
        .await?;
        contents
            .into_iter()
            .map(|bytes| bytes.map(|b| parse_ref_content(&b)).transpose())
            .collect()
    }

    /// Returns the state of the ref file at each of several paths under
    /// `refs/`, and the commit of the refspec `tip`, in one pass on the
    /// blocking pool. The result holds one state for each path, in order.
    ///
    /// The call reads each ref path with `lstat` first. It then opens a
    /// regular file with `O_NOFOLLOW` and parses it. A ref that does not parse
    /// fails the call.
    ///
    /// If `tip` is given, the call reads it as
    /// [`resolve_ref_tip`](Repo::resolve_ref_tip) does. The result holds the
    /// failure of `tip` separately, so the caller decides if it needs the
    /// value.
    #[cfg(feature = "receive")]
    #[allow(clippy::type_complexity)]
    pub(crate) async fn read_ref_states(
        &self,
        relpaths: Arc<[String]>,
        tip: Option<&str>,
    ) -> Result<(Vec<RefFileState>, Option<Result<Option<Checksum>>>)> {
        let tip = tip.map(refspec_to_relpath);
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            let states = relpaths
                .iter()
                .map(|p| ref_file_state(repo.repo_fd(), p))
                .collect::<Result<Vec<_>>>()?;
            let tip = tip.map(|relpath| match read_ref_file(repo.repo_fd(), &relpath?)? {
                Some(bytes) => Ok(Some(parse_ref_content(&bytes)?)),
                None => Ok(None),
            });
            Ok((states, tip))
        })
        .await
    }

    /// Returns the local refs as `(name, commit)` pairs, sorted by name.
    ///
    /// The local refs are under `refs/heads`. If `prefix` is given, the result
    /// holds only the ref named `prefix` and the refs below `prefix/`. The call
    /// follows each alias. An alias whose target names no ref is not in the
    /// result.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8.
    /// - [`Error::Core`] if a ref file holds no checksum.
    /// - [`Error::Io`] if a read from the file system fails, for example for
    ///   an alias that names a directory.
    pub async fn list_refs(&self, prefix: Option<&str>) -> Result<Vec<(String, Checksum)>> {
        let repo = self.clone();
        let mut refs = ostrya_rt::unblock(move || collect_heads(&repo)).await?;
        if let Some(prefix) = prefix {
            refs.retain(|(name, _)| ref_prefixes(name).any(|part| part == prefix));
        }
        refs.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(refs)
    }

    /// Returns the refs that `refs` and `collections` select and `access`
    /// reads, for a ref listing.
    ///
    /// # Local refs
    ///
    /// The local refs are the refs of `refs/heads` and, when the config sets
    /// `[core] collection-id`, the refs of `refs/mirrors/ID/` of that id.
    /// When a name is in the two directories, the result holds the commit of
    /// the mirror ref, and the call does not read the ref of `refs/heads`.
    /// `refs` selects the local refs by name, and `access`
    /// reads them in the local namespace.
    ///
    /// A ref is selected when the selector has no positive pattern or a
    /// positive pattern matches its name, and no negative pattern matches it.
    /// The walk reads only the directories that the literal leading parts of
    /// a positive pattern name, and below them only the directories that the
    /// pattern can match. It applies the negative patterns to a name before
    /// it reads the ref file, so a ref that no entry selects is never read.
    /// The walk drops a positive pattern that another positive pattern
    /// covers: if `q` is literal parts and a final `**`, a pattern that
    /// starts with the same literal parts and has at least one more part
    /// selects only names that `q` selects. The walk does not read a
    /// directory that a negative pattern covers: a negative pattern of
    /// literal or `*` parts and a final `**` matches each name below a
    /// directory whose path starts with these parts.
    /// With no positive pattern the walk covers all of each directory. The
    /// walk enumerates a name that the ref-name rule refuses, and a wildcard
    /// selects it.
    ///
    /// The result holds a ref only when `access` reads its name. The call
    /// checks the name before it reads the ref file, so a ref file that
    /// `access` does not read is never read. When `access` reads no local
    /// ref, the call opens neither directory. The call opens `refs/heads/`
    /// and `refs/mirrors/` by their paths from the repository. Below these
    /// two directories, it opens each ref file and each directory with no
    /// symlink followed. An alias resolves by the rule of
    /// the archive view: its body is relative, it names a regular file under
    /// `refs/` by one link, and `access` reads the target path. The call
    /// opens the target with no symlink followed. An alias that breaks one
    /// of these rules, and an alias whose target names no regular file, are
    /// not in the result.
    ///
    /// # Collection refs
    ///
    /// With `collections`, the call reads the top level of `refs/mirrors/`
    /// one time. `collections` selects the refs of each other collection by
    /// `ID/NAME`, with the rules above, and `access` reads them with the
    /// group of the item in the namespace of `ID`. The call skips a
    /// collection whose group gives no `r` before it reads the directory. It
    /// also skips a name that is not UTF-8, and an entry that is no
    /// directory. A directory whose name fails the collection-id rule goes to
    /// `invalid_dirs`, and the call reads no entry in it. The call skips the
    /// directory of an id that no positive pattern can reach, or that a
    /// negative pattern covers, before it reads the rights of the id. With
    /// `None`, the call reads `refs/mirrors/` only for the collection id of
    /// the config. The call opens `refs/mirrors/` at most one time.
    ///
    /// # Size
    ///
    /// With `cap`, the call keeps the lower bound of the size of the listing
    /// that the first size check of
    /// [`build_ref_listing`](Repo::build_ref_listing) computes, and adds each
    /// ref that it selects. When the bound passes `cap`, the call stops and
    /// fails with the error of that check, and it reads no more ref file.
    /// With `None`, the selection has no cap.
    ///
    /// The call runs on the blocking pool.
    ///
    /// # Errors
    ///
    /// - The errors of [`list_refs`](Repo::list_refs), for a selected ref.
    /// - [`Error::Remote`] with
    ///   [`LimitExceeded`](crate::remote::Error::LimitExceeded) if the lower
    ///   bound passes `cap`.
    pub(crate) async fn select_refs(
        &self,
        refs: &RefSelector,
        collections: Option<&RefSelector>,
        access: &ReadAccess,
        cap: Option<u64>,
    ) -> Result<RefSelection> {
        let repo = self.clone();
        let refs = refs.clone();
        let collections = collections.cloned();
        let access = access.clone();
        ostrya_rt::unblock(move || {
            let mut floor = SelectionFloor::new(cap);
            let own = repo.config().collection_id();
            // The one open of `refs/mirrors`, for the refs of the own
            // collection and for the collection refs.
            let mirrors = if collections.is_some() || (own.is_some() && access.reads_local_refs()) {
                open_refs_dir(&repo, MIRRORS_DIR)?
            } else {
                None
            };
            let mirrors = mirrors.as_ref().map(AsFd::as_fd);
            let mut selection = RefSelection {
                local: collect_local_selected(&repo, mirrors, &refs, &access, &mut floor)?,
                collections: BTreeMap::new(),
                invalid_dirs: Vec::new(),
            };
            if let Some(collections) = &collections
                && let Some(mirrors) = mirrors
            {
                collect_collections_selected(
                    &repo,
                    mirrors,
                    collections,
                    &access,
                    &mut floor,
                    &mut selection,
                )?;
            }
            Ok(selection)
        })
        .await
    }

    /// Returns the remote refs as `(refspec, commit)` pairs, sorted by refspec.
    ///
    /// The remote refs are under `refs/remotes`. The first path component
    /// below `refs/remotes` is the remote name, so the refspec of each ref is
    /// `remote:name`. A file directly under `refs/remotes` names no remote,
    /// and the result does not hold it.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8.
    /// - [`Error::Core`] if a ref file holds no checksum.
    /// - [`Error::Io`] if a read from the file system fails.
    pub async fn list_remote_refs(&self) -> Result<Vec<(String, Checksum)>> {
        let repo = self.clone();
        let mut refs = ostrya_rt::unblock(move || collect_remotes(&repo)).await?;
        refs.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(refs)
    }

    /// Returns the mirror refs as `(collection_id, ref_name, commit)` triples.
    ///
    /// The mirror refs are under `refs/mirrors`. The first path component
    /// below `refs/mirrors` is the collection id. The rest of the path is the
    /// ref name, which can contain `/`. A file directly under `refs/mirrors`
    /// has no collection id, and the result does not hold it.
    ///
    /// The result is not sorted. A caller that needs a stable order sorts it.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8.
    /// - [`Error::Core`] if a ref file holds no checksum.
    /// - [`Error::Io`] if a read from the file system fails.
    pub async fn list_mirror_refs(&self) -> Result<Vec<(String, String, Checksum)>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || collect_mirrors(&repo)).await
    }

    /// Returns the collection-qualified refs, sorted by collection id and ref
    /// name.
    ///
    /// The result holds:
    ///
    /// - The local refs, qualified by the `[core] collection-id` of the
    ///   repository, if the config sets one.
    /// - Each ref under `refs/mirrors`, which holds its collection id in its
    ///   path.
    ///
    /// A mirror ref under the collection id of the repository is in the result
    /// as a mirror ref.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8.
    /// - [`Error::Core`] if a ref file holds no checksum.
    /// - [`Error::Io`] if a read from the file system fails.
    pub async fn list_collection_refs(&self) -> Result<Vec<CollectionRefEntry>> {
        let heads = match self.config().collection_id() {
            Some(_) => self.list_refs(None).await?,
            None => Vec::new(),
        };
        self.collection_refs_over(&heads).await
    }

    /// Returns the listing of
    /// [`list_collection_refs`](Repo::list_collection_refs), made over a
    /// `refs/heads` listing that the caller read before. A repository with no
    /// `[core] collection-id` qualifies no local ref, and the call then
    /// ignores `heads`.
    pub(crate) async fn collection_refs_over(
        &self,
        heads: &[(String, Checksum)],
    ) -> Result<Vec<CollectionRefEntry>> {
        let mut all = Vec::new();
        if let Some(collection) = self.config().collection_id().map(str::to_owned) {
            for (name, commit) in heads {
                all.push(CollectionRefEntry {
                    collection: collection.clone(),
                    name: name.clone(),
                    commit: *commit,
                    local: true,
                });
            }
        }
        for (collection, name, commit) in self.list_mirror_refs().await? {
            all.push(CollectionRefEntry {
                collection,
                name,
                commit,
                local: false,
            });
        }
        all.sort_by(|a, b| (&a.collection, &a.name).cmp(&(&b.collection, &b.name)));
        Ok(all)
    }

    /// Returns the local and remote refs that are aliases, sorted by refspec.
    ///
    /// The result holds an alias whose target names no ref, because the call
    /// reads the link and not the ref behind it. An alias whose target is not
    /// UTF-8 is not in the result.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if a read from the file system fails.
    pub async fn list_ref_aliases(&self) -> Result<Vec<RefAlias>> {
        let repo = self.clone();
        let mut aliases = ostrya_rt::unblock(move || collect_aliases(&repo)).await?;
        aliases.sort_by(|a, b| a.refspec.cmp(&b.refspec));
        Ok(aliases)
    }

    /// Checks a path below `refs/` for a component that is not a directory.
    ///
    /// `relpath` is relative to `refs/`, as a listing prefix names it. The
    /// call fails for one condition only: a component before the last one is
    /// not a directory (`ENOTDIR`). This condition ends a listing.
    ///
    /// If the path names nothing, the call returns `Ok(())`, because a prefix
    /// that matches no ref lists nothing. Each other failure of the check also
    /// returns `Ok(())`, and the prefix then filters the listing. The call
    /// does not follow the last component, so a path that names an alias is
    /// the link itself.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] with `ENOTDIR` if a component before the last one is
    ///   not a directory.
    pub async fn check_refs_path(&self, relpath: &str) -> Result<()> {
        let path = format!("refs/{relpath}");
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            match rustix::fs::statat(repo.repo_fd(), &path, AtFlags::SYMLINK_NOFOLLOW) {
                Err(Errno::NOTDIR) => Err(Error::Io(Errno::NOTDIR.into())),
                _ => Ok(()),
            }
        })
        .await
    }

    /// Writes one ref outside a transaction.
    ///
    /// If `checksum` is `None`, the call removes the ref file. The removal of
    /// an absent ref file is not an error. The call reads `[core] fsync` from
    /// the config. A transaction writes its queued refs in the same way, under
    /// its own fsync policy (see [`Transaction::commit`]).
    ///
    /// # Ref files
    ///
    /// A ref is a file under `refs/`. It holds a 64-character hex checksum and
    /// a newline, 65 bytes in all. The file mode is `0644`, independent of the
    /// umask. The refspec gives the path:
    ///
    /// - The local ref `name` is at `refs/heads/name`.
    /// - The remote ref `remote:name` is at `refs/remotes/remote/name`.
    /// - A collection ref is at `refs/mirrors/collection/name` (see
    ///   [`set_collection_ref_immediate`](Repo::set_collection_ref_immediate)).
    ///
    /// A ref can also be an alias: a relative symlink to the file of another
    /// ref. A read follows the link and reads the checksum of the target ref.
    /// [`validate_refspec`] checks each component of the name against the
    /// ref-name rule, so a ref path stays inside `refs/`.
    ///
    /// The call creates the missing parent directories of a name with `/` in
    /// it. It requests mode `0777` for them, which the umask reduces. In a
    /// `bare-user-shared` repository, each directory that the call creates
    /// gets mode `02770`.
    ///
    /// # Durability
    ///
    /// The write is atomic. The call writes the content to a new temp file in
    /// the `tmp/` directory of the repository. Then it renames the temp file
    /// over the ref file. No temp entry is under `refs/`, so a listing never
    /// reads one.
    ///
    /// If `tmp/` is on a different file system, the rename fails with
    /// `EXDEV`, and the call removes the temp file.
    ///
    /// If `[core] fsync` is on:
    ///
    /// - The call runs `fdatasync` on the temp file before the rename.
    /// - After the rename, the call runs `fsync` on the directory that holds
    ///   the ref, so the name is durable together with the content.
    /// - If the call created parent directories, it also runs `fsync` on the
    ///   directory that holds each created directory, deepest first. So the
    ///   full path of the name is durable, and not only the last entry.
    ///
    /// A removal and an alias write have no content of their own, so they sync
    /// directories only. A write that fails still syncs the directories that it
    /// changed before the failure.
    ///
    /// # Locks
    ///
    /// The call takes the repository lock
    /// [`Shared`](crate::LockKind::Shared) and then the update lock, as
    /// [`begin_update`](Repo::begin_update) does, and writes under both. A
    /// caller that holds an [`UpdateGuard`](crate::UpdateGuard) of this
    /// repository must write through the guard, with
    /// [`UpdateGuard::set_ref`](crate::UpdateGuard::set_ref). If `[core]
    /// locking` is on and the caller holds the repository lock exclusive, the
    /// call waits for that lock. [`LockKind`](crate::LockKind) states the
    /// result of this wait.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if `refspec` is not a valid refspec.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or `[core]
    ///   lock-timeout-secs` does not parse.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is below `-1`.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn set_ref_immediate(
        &self,
        refspec: &str,
        checksum: Option<&Checksum>,
    ) -> Result<()> {
        let relpath = refspec_to_relpath(refspec)?;
        self.write_ref_relpath(relpath, checksum).await
    }

    /// Writes one collection ref outside a transaction.
    ///
    /// A ref with a collection id is at `refs/mirrors/<collection>/<name>`. A
    /// ref with no collection id is at `refs/heads/<name>`. If `checksum` is
    /// `None`, the call removes the ref file. The file format, the durability
    /// rules, and the locks are those of
    /// [`set_ref_immediate`](Repo::set_ref_immediate).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if the collection id is not one path
    ///   component, or the ref name is not valid. The error holds
    ///   `collection:name`, or the ref name alone for a local ref.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or `[core]
    ///   lock-timeout-secs` does not parse.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is below `-1`.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn set_collection_ref_immediate(
        &self,
        cref: &CollectionRef,
        checksum: Option<&Checksum>,
    ) -> Result<()> {
        let relpath = collection_ref_to_relpath(cref)?;
        self.write_ref_relpath(relpath, checksum).await
    }

    async fn write_ref_relpath(&self, relpath: String, checksum: Option<&Checksum>) -> Result<()> {
        let fsync = self.config().fsync()?;
        let repo_mode = self.mode();
        let checksum = checksum.copied();
        self.write_locked(move |repo| {
            write_ref_blocking(repo.repo_fd(), &relpath, checksum, fsync, repo_mode)
        })
        .await
    }

    /// Writes one ref as an alias of another ref, outside a transaction.
    ///
    /// The alias is a relative symlink from the file of `refspec` to the file
    /// of `target`. It replaces the ref or the alias that `refspec` named
    /// before. The call checks both refspecs. The call does not require
    /// either ref to exist, because the link records a name and not a
    /// checksum.
    ///
    /// The write is atomic: the call creates the link under a temp name in
    /// `tmp/` and renames it over the ref path. If `[core] fsync` is on, the
    /// call runs `fsync` on the directory that holds the link. It also runs
    /// `fsync` on the directory that holds each parent directory that the
    /// call created. The locks are those of
    /// [`set_ref_immediate`](Repo::set_ref_immediate).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if `refspec` or `target` is not a valid
    ///   refspec.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or `[core]
    ///   lock-timeout-secs` does not parse.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is below `-1`.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn set_ref_alias_immediate(&self, refspec: &str, target: &str) -> Result<()> {
        let fsync = self.config().fsync()?;
        let repo_mode = self.mode();
        let relpath = refspec_to_relpath(refspec)?;
        let link = relative_link(&relpath, &refspec_to_relpath(target)?);
        self.write_locked(move |repo| {
            write_alias_blocking(repo.repo_fd(), &relpath, &link, fsync, repo_mode)
        })
        .await
    }
}

/// The kind of name the base of a revision resolved as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RevKind {
    /// A full checksum, or an abbreviated checksum of a commit object.
    Checksum,
    /// A ref of the ref store.
    Ref,
}

/// Splits a revision string into its base and the number of trailing `^`
/// characters. Each `^` asks for one more generation of ancestry.
fn split_ancestry(rev: &str) -> (&str, usize) {
    let base = rev.trim_end_matches('^');
    (base, rev.len() - base.len())
}

/// Returns `true` if a revision names a commit by an abbreviated checksum: a
/// run of 1 to 63 lowercase hex characters. A 64-character run is the
/// checksum itself. One uppercase character makes the name a refspec, the
/// case rule of a full checksum.
fn is_abbreviated_checksum(rev: &str) -> bool {
    !rev.is_empty()
        && rev.len() < 64
        && rev
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// What an abbreviated checksum matched among the commit objects present.
enum AbbrevMatch {
    /// No commit object has a checksum that starts with the prefix.
    None,
    /// Exactly one does.
    One(Checksum),
    /// More than one does.
    Ambiguous,
}

/// Scans the loose commit objects for the ones whose checksum starts with
/// `prefix`.
///
/// Only commit objects match. A `dirtree`, a `dirmeta`, or a file object with
/// the same prefix does not match. A prefix that only such an object has
/// matches nothing.
///
/// The `objects/<xx>/` fanout holds the first two characters
/// of a checksum. A prefix of two or more characters names one fanout with its
/// first two characters, and the call opens that directory by name. A
/// one-character prefix scans the sixteen fanouts whose name starts with it,
/// found from a listing of `objects/`.
fn match_abbreviated(objects_fd: BorrowedFd<'_>, prefix: &str) -> Result<AbbrevMatch> {
    let mut found: Option<Checksum> = None;
    if prefix.len() >= 2 {
        let (fanout, within) = prefix.split_at(2);
        if scan_fanout(objects_fd, fanout, within, &mut found)? {
            return Ok(AbbrevMatch::Ambiguous);
        }
    } else {
        for fanout in read_dir_names(objects_fd)? {
            // The name of an object fanout directory is two hex characters.
            // Each other entry under `objects/` is not a loose-object fanout.
            if fanout.len() != 2 || !fanout.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            if !fanout.starts_with(prefix) {
                continue;
            }
            if scan_fanout(objects_fd, &fanout, "", &mut found)? {
                return Ok(AbbrevMatch::Ambiguous);
            }
        }
    }
    Ok(match found {
        Some(checksum) => AbbrevMatch::One(checksum),
        None => AbbrevMatch::None,
    })
}

/// Scans one `objects/<fanout>/` directory for the commit objects whose name
/// starts with `within`, and records each match in `found`. An absent fanout
/// directory holds no match. Returns `true` if the prefix is ambiguous.
fn scan_fanout(
    objects_fd: BorrowedFd<'_>,
    fanout: &str,
    within: &str,
    found: &mut Option<Checksum>,
) -> Result<bool> {
    let dir = match rustix::fs::openat(
        objects_fd,
        fanout,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(false),
        Err(e) => return Err(Error::Io(e.into())),
    };
    for entry in read_dir_names(dir.as_fd())? {
        let Some(checksum) = matching_commit(fanout, &entry, within) else {
            continue;
        };
        // The fanout holds the first two characters of a checksum, so two
        // entries are two commits, and a second match makes the prefix
        // ambiguous.
        if found.replace(checksum).is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Returns the checksum of one `objects/<fanout>/<rest>.commit` entry whose
/// name starts with `within`, or `None` for each other entry.
fn matching_commit(fanout: &str, entry: &str, within: &str) -> Option<Checksum> {
    let (rest, ext) = entry.rsplit_once('.')?;
    if ext != "commit" || rest.len() != 62 || !rest.starts_with(within) {
        return None;
    }
    Checksum::from_hex_lower(&format!("{fanout}{rest}")).ok()
}

/// Returns the symlink body that an alias at `from_relpath` needs to point at
/// `to_relpath`.
///
/// Both paths are relative to the repository root. The body drops the shared
/// leading components. It then has one `..` for each further component of
/// the directory of the alias. It ends with the other components of the
/// target.
pub(crate) fn relative_link(from_relpath: &str, to_relpath: &str) -> String {
    let from: Vec<&str> = from_relpath.split('/').collect();
    let to: Vec<&str> = to_relpath.split('/').collect();
    // The name of the alias is not part of the directory that the link is
    // read in. The name of the target is never a shared component.
    let from_dir = &from[..from.len() - 1];
    let common = from_dir
        .iter()
        .zip(&to[..to.len() - 1])
        .take_while(|(a, b)| a == b)
        .count();
    let mut parts = vec![".."; from_dir.len() - common];
    parts.extend_from_slice(&to[common..]);
    parts.join("/")
}

/// Collects each ref under `refs/heads` and its subdirectories.
fn collect_heads(repo: &Repo) -> Result<Vec<(String, Checksum)>> {
    let Some(heads) = open_refs_dir(repo, "refs/heads")? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    walk_ref_dir(heads.as_fd(), "", &mut |entry| push_head(&mut out, &entry))?;
    Ok(out)
}

/// The directory of the local refs.
const HEADS_DIR: &str = "refs/heads";

/// The directory of the mirror refs, one subdirectory for each collection id.
const MIRRORS_DIR: &str = "refs/mirrors";

/// The refs of one ref listing, which [`Repo::select_refs`] returns.
pub(crate) struct RefSelection {
    /// The local refs, sorted byte-wise by name, each one time.
    pub(crate) local: Vec<(String, Checksum)>,
    /// The refs of each collection other than the own collection, by
    /// collection id, each list sorted byte-wise by name. A collection with
    /// no selected ref is not in the map.
    pub(crate) collections: BTreeMap<String, Vec<(String, Checksum)>>,
    /// The names of the directories under `refs/mirrors/` that fail the
    /// collection-id rule, sorted byte-wise, each one time.
    pub(crate) invalid_dirs: Vec<String>,
}

/// Returns the local refs that `selector` selects and `access` reads, sorted
/// by name, each one time: the refs of `refs/heads`, and the refs of
/// `refs/mirrors/ID/` of `[core] collection-id` under `mirrors`, the open
/// `refs/mirrors`. A mirror ref takes the place of the ref of `refs/heads` of
/// the same name, and the call does not read that ref of `refs/heads`. When
/// `access` reads no local ref, the call opens neither directory. The call
/// adds each ref to `floor`.
fn collect_local_selected(
    repo: &Repo,
    mirrors: Option<BorrowedFd<'_>>,
    selector: &RefSelector,
    access: &ReadAccess,
    floor: &mut SelectionFloor,
) -> Result<Vec<(String, Checksum)>> {
    if !access.reads_local_refs() {
        return Ok(Vec::new());
    }
    let mut local = BTreeMap::new();
    // The mirror refs come first, so the walk of `refs/heads` skips a name
    // that a mirror ref has.
    if let Some(own) = repo.config().collection_id()
        && let Some(mirrors) = mirrors
        && let Some(dir) = open_ref_subdir(mirrors, own)?
    {
        let root = format!("{MIRRORS_DIR}/{own}");
        collect_dir_selected(
            repo,
            &root,
            dir.as_fd(),
            selector,
            access,
            floor,
            &mut local,
        )?;
    }
    if let Some(heads) = open_refs_dir(repo, HEADS_DIR)? {
        collect_dir_selected(
            repo,
            HEADS_DIR,
            heads.as_fd(),
            selector,
            access,
            floor,
            &mut local,
        )?;
    }
    Ok(local.into_iter().collect())
}

/// Adds to `out` each ref of `dir`, the directory `root` under `refs/`, that
/// `selector` selects and `access` reads in the local namespace, each one
/// time, and adds it to `floor`. A ref that no entry selects, that `access`
/// does not read, or that is in `out` already is not read, and a directory
/// that a negative pattern covers is not read.
fn collect_dir_selected(
    repo: &Repo,
    root: &str,
    dir: BorrowedFd<'_>,
    selector: &RefSelector,
    access: &ReadAccess,
    floor: &mut SelectionFloor,
    out: &mut BTreeMap<String, Checksum>,
) -> Result<()> {
    // Reads the ref of `entry` unless it is in `out` already, a negative
    // pattern matches it, or `access` does not read it. The positive match
    // is the duty of the walk.
    let mut take = |entry: RefEntry<'_>| -> Result<()> {
        if out.contains_key(entry.path)
            || selector.negative().iter().any(|p| p.matches(entry.path))
            || !access.can_read(&Namespace::Local, entry.path)
        {
            return Ok(());
        }
        if let Some(bytes) = read_listed_ref(repo, root, &entry, access)? {
            let commit = parse_ref_content(&bytes)?;
            floor.add_ref(entry.path)?;
            out.insert(entry.path.to_owned(), commit);
        }
        Ok(())
    };
    walk_selected(dir, selector, &mut take)
}

/// Adds to `selection` the collection refs that `selector` selects by
/// `ID/NAME` and `access` reads, and the names of the directories under
/// `mirrors`, the open `refs/mirrors`, that fail the collection-id rule. The
/// call adds each ref and each collection of the map to `floor`.
///
/// The call reads the top level of `mirrors` one time. Then it walks the
/// directory of each collection that a positive pattern can reach and whose
/// group gives `r`, and no other directory. The own collection id is not a
/// collection of the map. A name that is not UTF-8 and an entry at the top
/// level that is no directory are skipped.
fn collect_collections_selected(
    repo: &Repo,
    mirrors: BorrowedFd<'_>,
    selector: &RefSelector,
    access: &ReadAccess,
    floor: &mut SelectionFloor,
    selection: &mut RefSelection,
) -> Result<()> {
    let own = repo.config().collection_id();
    let walk = CollectionWalk::new(selector);
    // The rules of each collection that the walk can reach and the client
    // can read, computed one time for the listing.
    let mut readable = BTreeMap::new();
    for name in read_dir_names(mirrors)? {
        if Some(name.as_str()) == own {
            continue;
        }
        if ref_entry_type(mirrors, &name)? != Some(FileType::Directory) {
            continue;
        }
        if !ostrya_core::is_collection_id(&name) {
            selection.invalid_dirs.push(name);
            continue;
        }
        if !walk.reaches(&name) {
            continue;
        }
        if let Some(rules) = access.collection_rules(&name)
            && rules.gives_read()
        {
            readable.insert(name, rules);
        }
    }
    selection.invalid_dirs.sort();
    selection.invalid_dirs.dedup();
    for (id, rules) in readable {
        let mut names: BTreeMap<String, Checksum> = BTreeMap::new();
        let mut take = |entry: RefEntry<'_>| -> Result<()> {
            // The walk gives each entry of the directory of `id` as `id/NAME`.
            let Some((_, name)) = entry.path.split_once('/') else {
                return Ok(());
            };
            if names.contains_key(name)
                || selector.negative().iter().any(|p| p.matches(entry.path))
                || !crate::access::reads(&rules, name)
            {
                return Ok(());
            }
            if let Some(bytes) = read_listed_ref(repo, MIRRORS_DIR, &entry, access)? {
                let commit = parse_ref_content(&bytes)?;
                if names.is_empty() {
                    floor.add_collection(&id)?;
                }
                floor.add_ref(name)?;
                names.insert(name.to_owned(), commit);
            }
            Ok(())
        };
        walk.walk(mirrors, &id, &mut take)?;
        if !names.is_empty() {
            selection
                .collections
                .insert(id, names.into_iter().collect());
        }
    }
    Ok(())
}

/// Walks the ref tree of `dir` for `selector`, and gives `take` each entry
/// whose path a positive pattern can match. With no positive pattern, `take`
/// gets each entry. The walk does not read a directory that a negative
/// pattern covers. `take` applies the negative patterns.
fn walk_selected(
    dir: BorrowedFd<'_>,
    selector: &RefSelector,
    take: &mut dyn FnMut(RefEntry<'_>) -> Result<()>,
) -> Result<()> {
    let covers = negative_covers(selector);
    let skip = |dir: &str| dir_is_covered(&covers, dir);
    if selector.positive().is_empty() {
        walk_ref_dir_skipping(dir, "", &skip, &mut &mut *take)?;
    } else {
        for pattern in uncovered_patterns(selector.positive()) {
            let parts: Vec<&str> = pattern.as_str().split('/').collect();
            walk_ref_pattern(dir, "", &parts, pattern, &skip, take)?;
        }
    }
    Ok(())
}

/// The walk of the collection directories under `refs/mirrors` for a
/// selector of `ID/NAME` paths, with each pattern split one time.
///
/// The first part of a pattern names collection ids: a literal names one id,
/// and `*` and `**` name each id. A pattern of one part other than `**`
/// selects no ref. Below the directory of an id, `**` as the first part takes
/// each entry whose whole path the pattern matches, and each other first
/// part takes the rest of the parts.
struct CollectionWalk<'a> {
    /// The selector of the walk.
    selector: &'a RefSelector,
    /// The leading parts of each negative pattern that covers a directory.
    covers: Vec<Vec<&'a str>>,
    /// The positive patterns that no other positive pattern covers, each
    /// with its parts.
    patterns: Vec<(&'a RefPattern, Vec<&'a str>)>,
    /// The ids that the first parts name, when no first part is a wildcard.
    literal_ids: Option<BTreeSet<&'a str>>,
}

impl<'a> CollectionWalk<'a> {
    /// Returns the walk of `selector`.
    fn new(selector: &'a RefSelector) -> CollectionWalk<'a> {
        let patterns: Vec<(&RefPattern, Vec<&str>)> = uncovered_patterns(selector.positive())
            .into_iter()
            .map(|pattern| (pattern, pattern.as_str().split('/').collect()))
            .collect();
        let literal = patterns
            .iter()
            .all(|(_, parts)| parts[0] != "*" && parts[0] != "**");
        let literal_ids = literal.then(|| {
            patterns
                .iter()
                .filter(|(_, parts)| parts.len() > 1)
                .map(|(_, parts)| parts[0])
                .collect()
        });
        CollectionWalk {
            selector,
            covers: negative_covers(selector),
            patterns,
            literal_ids,
        }
    }

    /// Returns `true` if a positive pattern can select a ref of the
    /// collection `id` and no negative pattern covers its directory. With no
    /// positive pattern, each id that no negative pattern covers is reached.
    fn reaches(&self, id: &str) -> bool {
        if dir_is_covered(&self.covers, id) {
            return false;
        }
        if self.selector.positive().is_empty() {
            return true;
        }
        match &self.literal_ids {
            Some(ids) => ids.contains(id),
            None => self
                .patterns
                .iter()
                .any(|(_, parts)| first_part_reaches(parts, id)),
        }
    }

    /// Walks the directory `id` of `mirrors`, the open `refs/mirrors`, as
    /// [`walk_selected`] walks a directory, and gives `take` each entry as
    /// `id/NAME`. The walk does not read the top level of `mirrors`.
    fn walk(
        &self,
        mirrors: BorrowedFd<'_>,
        id: &str,
        take: &mut dyn FnMut(RefEntry<'_>) -> Result<()>,
    ) -> Result<()> {
        let skip = |dir: &str| dir_is_covered(&self.covers, dir);
        let Some(sub) = open_ref_subdir(mirrors, id)? else {
            return Ok(());
        };
        if self.selector.positive().is_empty() {
            return walk_ref_dir_skipping(sub.as_fd(), id, &skip, &mut &mut *take);
        }
        for (pattern, parts) in &self.patterns {
            if !first_part_reaches(parts, id) {
                continue;
            }
            match parts.split_first() {
                Some((&"**", _)) => {
                    walk_ref_dir_skipping(sub.as_fd(), id, &skip, &mut |entry| {
                        if pattern.matches(entry.path) {
                            take(entry)
                        } else {
                            Ok(())
                        }
                    })?;
                }
                Some((_, rest)) => walk_ref_pattern(sub.as_fd(), id, rest, pattern, &skip, take)?,
                None => {}
            }
        }
        Ok(())
    }
}

/// Returns `true` if the pattern of the parts `parts` can select a ref of the
/// collection `id`: its first part is `**`, or it has more than one part and
/// its first part is `*` or `id`.
fn first_part_reaches(parts: &[&str], id: &str) -> bool {
    match parts.split_first() {
        Some((&"**", _)) => true,
        Some((first, rest)) => !rest.is_empty() && (*first == "*" || *first == id),
        None => false,
    }
}

/// Returns the leading parts of each negative pattern of `selector` that
/// covers a directory, for [`dir_is_covered`].
fn negative_covers(selector: &RefSelector) -> Vec<Vec<&str>> {
    selector
        .negative()
        .iter()
        .filter_map(|pattern| covering_lead(pattern.as_str()))
        .collect()
}

/// Reads the ref of the entry `entry` of a walk of the directory `root`
/// under `refs/` for the listing of `access`, or returns `None`.
///
/// An alias goes to [`read_alias_ref`]. The call opens each other entry
/// with no symlink followed. An entry that is an alias at the open goes to
/// `read_alias_ref`, as the classification of the walk sends an alias. An
/// entry removed after the walk read its type gives `None`.
fn read_listed_ref(
    repo: &Repo,
    root: &str,
    entry: &RefEntry<'_>,
    access: &ReadAccess,
) -> Result<Option<Vec<u8>>> {
    if entry.file_type == FileType::Symlink {
        return read_alias_ref(repo, root, entry, access);
    }
    let fd = match rustix::fs::openat(
        entry.dir,
        entry.name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => return read_alias_ref(repo, root, entry, access),
        Err(e) => return Err(Error::Io(e.into())),
    };
    let mut buf = Vec::with_capacity(REF_READ_CAP as usize);
    std::fs::File::from(fd)
        .take(REF_READ_CAP)
        .read_to_end(&mut buf)?;
    Ok(Some(buf))
}

/// Reads the ref that the alias `entry` of a walk of the directory `root`
/// under `refs/` names, or returns `None`.
///
/// The body of the alias resolves by the rule of the archive view. The
/// result is `None` when the body breaks that rule, when `access` does not
/// read the target path, and when the target is no regular file. The path of
/// the target gives its namespace. The read of the target follows no
/// symlink.
fn read_alias_ref(
    repo: &Repo,
    root: &str,
    entry: &RefEntry<'_>,
    access: &ReadAccess,
) -> Result<Option<Vec<u8>>> {
    let body = match rustix::fs::readlinkat(entry.dir, entry.name, Vec::new()) {
        Ok(body) => body,
        // The entry was removed after the walk read its type.
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(Error::Io(e.into())),
    };
    let link_dir = match entry.path.rsplit_once('/') {
        Some((dir, _)) => format!("{root}/{dir}"),
        None => root.to_owned(),
    };
    let Some(target) = resolve_alias(&link_dir, body.as_bytes()) else {
        return Ok(None);
    };
    if !access.can_read_path(&target) {
        return Ok(None);
    }
    match walk(repo.repo_fd(), &target, false)? {
        Walked::File(file, _) => {
            let mut buf = Vec::with_capacity(REF_READ_CAP as usize);
            file.take(REF_READ_CAP).read_to_end(&mut buf)?;
            Ok(Some(buf))
        }
        Walked::NotFound | Walked::Refused | Walked::Alias(_) => Ok(None),
    }
}

/// Reads the ref entry `entry` of a walk of `refs/heads` and adds it to
/// `out`. An alias resolves to the commit of its target, and a dangling alias
/// adds nothing.
fn push_head(out: &mut Vec<(String, Checksum)>, entry: &RefEntry<'_>) -> Result<()> {
    if let Some(bytes) = read_ref_file(entry.dir, entry.name)? {
        out.push((entry.path.to_owned(), parse_ref_content(&bytes)?));
    }
    Ok(())
}

/// Collects each ref under `refs/remotes`, named by its `remote:name`
/// refspec. The first path component is the remote, and the rest is the ref
/// name.
fn collect_remotes(repo: &Repo) -> Result<Vec<(String, Checksum)>> {
    let Some(remotes) = open_refs_dir(repo, "refs/remotes")? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    walk_ref_dir(remotes.as_fd(), "", &mut |entry| {
        let Some(bytes) = read_ref_file(entry.dir, entry.name)? else {
            return Ok(());
        };
        let checksum = parse_ref_content(&bytes)?;
        // A file directly under refs/remotes names no remote. The walk skips
        // it, as collect_mirrors skips a file that names no collection.
        if let Some((remote, ref_name)) = entry.path.split_once('/') {
            out.push((format!("{remote}:{ref_name}"), checksum));
        }
        Ok(())
    })?;
    Ok(out)
}

/// Collects the aliases under `refs/heads` and `refs/remotes`. Each alias
/// gets the name that the listing of its directory gives a ref.
fn collect_aliases(repo: &Repo) -> Result<Vec<RefAlias>> {
    let mut out = Vec::new();
    if let Some(heads) = open_refs_dir(repo, "refs/heads")? {
        walk_ref_dir(heads.as_fd(), "", &mut |entry| {
            if let Some(target) = read_alias_target(&entry)? {
                out.push(RefAlias {
                    refspec: entry.path.to_owned(),
                    target,
                });
            }
            Ok(())
        })?;
    }
    if let Some(remotes) = open_refs_dir(repo, "refs/remotes")? {
        walk_ref_dir(remotes.as_fd(), "", &mut |entry| {
            if let Some(target) = read_alias_target(&entry)?
                && let Some((remote, ref_name)) = entry.path.split_once('/')
            {
                out.push(RefAlias {
                    refspec: format!("{remote}:{ref_name}"),
                    target,
                });
            }
            Ok(())
        })?;
    }
    Ok(out)
}

/// Opens one directory under `refs/`. Returns `None` if it does not exist.
fn open_refs_dir(repo: &Repo, relpath: &str) -> Result<Option<OwnedFd>> {
    match rustix::fs::openat(
        repo.repo_fd(),
        relpath,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Collects each ref under `refs/mirrors`, split into its collection id (the
/// first path component) and its ref name (the rest of the path).
fn collect_mirrors(repo: &Repo) -> Result<Vec<(String, String, Checksum)>> {
    let Some(mirrors) = open_refs_dir(repo, "refs/mirrors")? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    walk_ref_dir(mirrors.as_fd(), "", &mut |entry| {
        let Some(bytes) = read_ref_file(entry.dir, entry.name)? else {
            return Ok(());
        };
        let checksum = parse_ref_content(&bytes)?;
        // A mirror ref is <collection>/<ref>. The collection id is one
        // component, and the ref name is the path after the first slash. A
        // file directly under refs/mirrors has no collection component. The
        // walk skips it, which matches the collection-qualified layout of the
        // `ostree` command.
        if let Some((collection, ref_name)) = entry.path.split_once('/') {
            out.push((collection.to_owned(), ref_name.to_owned(), checksum));
        }
        Ok(())
    })?;
    Ok(out)
}

/// One entry a ref-tree walk reports.
pub(crate) struct RefEntry<'a> {
    /// The open directory holding the entry.
    pub(crate) dir: BorrowedFd<'a>,
    /// The name of the entry in that directory.
    pub(crate) name: &'a str,
    /// The path from the root of the walk to the entry.
    pub(crate) path: &'a str,
    /// The type of the entry, read with no symlink followed.
    pub(crate) file_type: FileType,
}

/// Walks a directory under `refs/`. The walk descends into each subdirectory
/// and reports each other entry to `visit`.
///
/// The walk classifies entries with `SYMLINK_NOFOLLOW`, so it descends only
/// into a real directory, and an alias has [`FileType::Symlink`] whatever it
/// names. The walk reports a link that names a directory and does not
/// descend into it. A caller that reads it as a ref fails the read with
/// `EISDIR`, and a caller that reads it as an alias reads the link. The walk
/// skips a name that is not UTF-8, and a name removed between the directory
/// read and the classification.
///
/// The walk opens a subdirectory with no symlink followed. When the entry is
/// no directory at the open, the walk reads its type again and reports it
/// with that type. When the entry is removed, or is a directory again, the
/// walk skips it.
pub(crate) fn walk_ref_dir(
    dir: BorrowedFd<'_>,
    prefix: &str,
    visit: &mut impl FnMut(RefEntry<'_>) -> Result<()>,
) -> Result<()> {
    walk_ref_dir_skipping(dir, prefix, &|_| false, visit)
}

/// Walks a directory as [`walk_ref_dir`] does, and does not read a
/// subdirectory when `skip` returns `true` for its path below the top.
fn walk_ref_dir_skipping(
    dir: BorrowedFd<'_>,
    prefix: &str,
    skip: &dyn Fn(&str) -> bool,
    visit: &mut impl FnMut(RefEntry<'_>) -> Result<()>,
) -> Result<()> {
    for name in read_dir_names(dir)? {
        // A name removed between the directory read and the classification
        // has no type.
        let Some(mut file_type) = ref_entry_type(dir, &name)? else {
            continue;
        };
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if file_type == FileType::Directory {
            if skip(&path) {
                continue;
            }
            if let Some(sub) = open_ref_subdir(dir, &name)? {
                walk_ref_dir_skipping(sub.as_fd(), &path, skip, visit)?;
                continue;
            }
            // The entry changed after its classification. It takes the type
            // that it has now.
            match ref_entry_type(dir, &name)? {
                Some(now) if now != FileType::Directory => file_type = now,
                _ => continue,
            }
        }
        visit(RefEntry {
            dir,
            name: &name,
            path: &path,
            file_type,
        })?;
    }
    Ok(())
}

/// Walks the part of a ref tree that `pattern` can match. `parts` are the
/// parts of the pattern that remain below `dir`, and `prefix` is the path of
/// `dir` below the top, or empty for the top. `visit` gets each entry that
/// [`walk_ref_dir`] gives from the top with a path that `pattern` matches,
/// and no other entry. The call does not read a subdirectory when `skip`
/// returns `true` for its path.
///
/// The call classifies each entry with `SYMLINK_NOFOLLOW`, and opens a
/// subdirectory with no symlink followed, as `walk_ref_dir` does, so it
/// descends only into a real directory. It reads no ref file
/// outside the literal leading parts of the pattern and the matches. A
/// leading wildcard lists the directories at its level. For the first of
/// `parts`:
///
/// - A literal part names one entry. If the entry is missing, or is longer
///   than a file name can be, the pattern selects nothing. If more parts
///   follow, the entry must be a real directory, and the call goes down into
///   it. If the part is the last, the entry goes to `visit` unless it is a
///   directory. A symlink that names a directory is such an entry.
/// - `*` reads `dir` and takes each entry as a literal part does.
/// - `**` walks `dir` with `walk_ref_dir`. If no part follows it, each entry
///   goes to `visit`. Otherwise `visit` gets each entry whose whole path the
///   pattern matches.
fn walk_ref_pattern(
    dir: BorrowedFd<'_>,
    prefix: &str,
    parts: &[&str],
    pattern: &RefPattern,
    skip: &dyn Fn(&str) -> bool,
    visit: &mut dyn FnMut(RefEntry<'_>) -> Result<()>,
) -> Result<()> {
    let Some((first, rest)) = parts.split_first() else {
        return Ok(());
    };
    if *first == "**" {
        return walk_ref_dir_skipping(dir, prefix, skip, &mut |entry| {
            if rest.is_empty() || pattern.matches(entry.path) {
                visit(entry)
            } else {
                Ok(())
            }
        });
    }
    let names = if *first == "*" {
        read_dir_names(dir)?
    } else {
        vec![(*first).to_owned()]
    };
    for name in names {
        // A name removed after the directory read has no type.
        let Some(file_type) = ref_entry_type(dir, &name)? else {
            continue;
        };
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        match (file_type == FileType::Directory, rest.is_empty()) {
            (true, false) if !skip(&path) => {
                // An entry that is no directory at the open matches no
                // pattern with more parts.
                if let Some(sub) = open_ref_subdir(dir, &name)? {
                    walk_ref_pattern(sub.as_fd(), &path, rest, pattern, skip, visit)?;
                }
            }
            (false, true) => visit(RefEntry {
                dir,
                name: &name,
                path: &path,
                file_type,
            })?,
            _ => {}
        }
    }
    Ok(())
}

/// Returns the leading parts of the negative pattern `text` when the
/// pattern is these parts, each a literal or `*`, followed by a final `**`.
/// Such a pattern matches each name below a directory whose path starts with
/// the parts. `**` alone has no leading part.
fn covering_lead(text: &str) -> Option<Vec<&str>> {
    let lead = if text == "**" {
        ""
    } else {
        text.strip_suffix("/**")?
    };
    let parts: Vec<&str> = if lead.is_empty() {
        Vec::new()
    } else {
        lead.split('/').collect()
    };
    if parts.contains(&"**") {
        return None;
    }
    Some(parts)
}

/// Returns `true` if a negative pattern with one of the leading parts
/// `covers` matches each name below the directory `dir`. That holds when
/// `dir` has at least as many parts as the lead, and each lead part is `*` or
/// equals the part of `dir` at its place.
fn dir_is_covered(covers: &[Vec<&str>], dir: &str) -> bool {
    covers.iter().any(|lead| {
        let mut parts = dir.split('/');
        lead.iter()
            .all(|l| parts.next().is_some_and(|part| *l == "*" || *l == part))
    })
}

/// Returns the patterns of `patterns` that no other pattern of the slice
/// covers, in order. A pattern `q` covers a pattern `p` when `q` is literal
/// parts followed by a final `**`, and `p` starts with the same literal
/// parts and has at least one more part: each name that `p` matches is below
/// the literal parts, and `q` matches it. Of two patterns with the same text
/// the first stays. A pattern that only a combination of patterns covers
/// stays.
fn uncovered_patterns(patterns: &[RefPattern]) -> Vec<&RefPattern> {
    // The text of each pattern that has the shape of `q`, up to its `**`.
    let leads: Vec<(usize, &str)> = patterns
        .iter()
        .enumerate()
        .filter_map(|(i, q)| {
            let text = q.as_str();
            let lead = if text == "**" {
                ""
            } else {
                &text[..text.strip_suffix("/**")?.len() + 1]
            };
            let literal = lead.split('/').all(|part| part != "*" && part != "**");
            literal.then_some((i, lead))
        })
        .collect();
    patterns
        .iter()
        .enumerate()
        .filter(|(i, p)| {
            let text = p.as_str();
            let repeat = patterns[..*i].iter().any(|q| q.as_str() == text);
            !repeat
                && !leads.iter().any(|(j, lead)| {
                    patterns[*j].as_str() != text
                        && text.len() > lead.len()
                        && text.starts_with(lead)
                })
        })
        .map(|(_, p)| p)
        .collect()
}

/// Returns the type of the entry `name` of `dir`, read with no symlink
/// followed, or `None` if the entry does not exist.
///
/// A name longer than the file system permits (`ENAMETOOLONG`) names no
/// entry, so it also gives `None`.
fn ref_entry_type(dir: BorrowedFd<'_>, name: &str) -> Result<Option<FileType>> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(FileType::from_raw_mode(stat.st_mode))),
        Err(Errno::NOENT | Errno::NAMETOOLONG) => Ok(None),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Opens the subdirectory `name` of `dir` in a ref-tree walk, with no
/// symlink followed. Returns `None` if the entry is removed or is no
/// directory, a symlink included.
fn open_ref_subdir(dir: BorrowedFd<'_>, name: &str) -> Result<Option<OwnedFd>> {
    match rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT | Errno::NOTDIR | Errno::LOOP) => Ok(None),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Returns the symlink target of an alias entry, as stored. Returns `None`
/// for an entry that is not a symlink and for a target that is not UTF-8.
fn read_alias_target(entry: &RefEntry<'_>) -> Result<Option<String>> {
    if entry.file_type != FileType::Symlink {
        return Ok(None);
    }
    let target = rustix::fs::readlinkat(entry.dir, entry.name, Vec::new())
        .map_err(|e| Error::Io(e.into()))?;
    Ok(target.into_string().ok())
}

/// Reads a ref file relative to `dir`, and follows alias symlinks. Returns
/// `None` if the file does not exist.
fn read_ref_file(
    dir: rustix::fd::BorrowedFd<'_>,
    relpath: &str,
) -> std::io::Result<Option<Vec<u8>>> {
    let fd = match rustix::fs::openat(
        dir,
        relpath,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    // The buffer holds the whole cap before the read, so a ref file takes
    // one read and the read that finds its end.
    let mut buf = Vec::with_capacity(REF_READ_CAP as usize);
    std::fs::File::from(fd)
        .take(REF_READ_CAP)
        .read_to_end(&mut buf)?;
    Ok(Some(buf))
}

/// Returns the state of the ref path `relpath`, read with `lstat` and then an
/// `O_NOFOLLOW` open of a regular file. A path that passes through a file
/// (`ENOTDIR`) is [`RefFileState::NotARef`].
#[cfg(feature = "receive")]
fn ref_file_state(dir: BorrowedFd<'_>, relpath: &str) -> Result<RefFileState> {
    let stat = match rustix::fs::statat(dir, relpath, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(RefFileState::Absent),
        Err(Errno::NOTDIR) => return Ok(RefFileState::NotARef),
        Err(e) => return Err(e.into()),
    };
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Symlink => return Ok(RefFileState::Alias),
        FileType::RegularFile => {}
        _ => return Ok(RefFileState::NotARef),
    }
    let fd = match rustix::fs::openat(
        dir,
        relpath,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(RefFileState::Absent),
        Err(Errno::LOOP) => return Ok(RefFileState::Alias),
        Err(e) => return Err(e.into()),
    };
    let mut buf = Vec::with_capacity(REF_READ_CAP as usize);
    std::fs::File::from(fd)
        .take(REF_READ_CAP)
        .read_to_end(&mut buf)?;
    Ok(RefFileState::Commit(parse_ref_content(&buf)?))
}

/// Parses the content of a ref file: a hex checksum with trailing white
/// space.
fn parse_ref_content(bytes: &[u8]) -> Result<Checksum> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::InvalidFormat("ref content is not valid UTF-8".into()))?;
    Ok(Checksum::from_hex(text.trim())?)
}

/// Checks that a refspec names a path under `refs/`.
///
/// A refspec is a ref name, with an optional `<remote>:` prefix.
/// [`ostrya_core::is_refspec`] holds the rule. Each component of the name, and
/// the remote, is not empty, does not start with `-` or `.`, and holds only
/// ASCII alphanumerics, `-`, `.`, `_`, and alphanumeric characters that are
/// not ASCII. So the name holds no `:`, no space, and no wildcard, and the
/// remote holds no `/`, no space, and no wildcard.
///
/// # Errors
///
/// - [`Error::InvalidRefspec`] if `refspec` does not obey the rule, for
///   example if it names a path outside `refs/` or holds a character that
///   the rule refuses. The error holds the refspec as given.
pub fn validate_refspec(refspec: &str) -> Result<()> {
    if ostrya_core::is_refspec(refspec) {
        Ok(())
    } else {
        Err(Error::InvalidRefspec(refspec.to_owned()))
    }
}

/// Maps a refspec to its path under `refs/`. Refuses a refspec that
/// [`validate_refspec`] refuses.
pub(crate) fn refspec_to_relpath(refspec: &str) -> Result<String> {
    validate_refspec(refspec)?;
    Ok(match refspec.split_once(':') {
        Some((remote, name)) => format!("refs/remotes/{remote}/{name}"),
        None => format!("refs/heads/{refspec}"),
    })
}

/// Returns `true` if the name that a listing gave a ref addresses the file
/// that the listing read: if [`refspec_to_relpath`] maps `name` to exactly
/// `<top>/<path>`. `top` is the directory of `refs/` that the listing walked,
/// and `path` is the path of the ref file below it.
///
/// Prune classifies a ref only where this returns `true`. So each ref that
/// the classifier sees reads and deletes through the file that the listing
/// read. A name that the mapping refuses gives `false`.
///
/// The name alone decides this for a ref below `refs/heads`. There, a `:` in
/// the name sends the mapping to `refs/remotes` and so to a different file.
///
/// For a ref below `refs/remotes`, the path must be `<remote>/<rest>`, where
/// the name is `<remote>:<rest>`. A listing names such a ref with a `:` in
/// place of the first `/` of its path.
///
/// A name that the ref-name rule refuses is not addressable, so prune never
/// classifies it as weak. Only an out-of-band write can put such a name on
/// disk. The rule refuses a `:` in the name part, so a name that a listing
/// gives for a file below `refs/remotes` addresses that file alone.
///
/// No refspec maps to a path below `refs/mirrors`, so a mirror ref always
/// gives `false`.
///
/// The body mirrors [`refspec_to_relpath`] branch for branch and allocates
/// nothing, because prune calls it once for each ref in the repository.
pub(crate) fn listed_name_addresses_it(name: &str, top: &str, path: &str) -> bool {
    match name.split_once(':') {
        Some((remote, rest)) => {
            top == "refs/remotes"
                && ostrya_core::is_ref_name_component(remote)
                && is_ref_path(rest)
                && path
                    .split_once('/')
                    .is_some_and(|(dir, below)| dir == remote && below == rest)
        }
        None => top == "refs/heads" && is_ref_path(name) && path == name,
    }
}

/// Checks a bare ref name with the ref-name rule of [`validate_refspec`], and
/// fails with [`Error::InvalidRefspec`].
///
/// An HTTP pull applies it before a ref name becomes a request path. A
/// component that the rule refuses, such as a traversal component, asks the
/// server for a different resource, as it names a different file in the
/// repository.
pub(crate) fn check_ref_path(name: &str) -> Result<()> {
    if is_ref_path(name) {
        Ok(())
    } else {
        Err(Error::InvalidRefspec(name.to_owned()))
    }
}

/// Returns each prefix that selects the ref `name`: each leading part of
/// `name` that ends before a `/`, and then `name` itself.
///
/// The prefix `a/b` selects the ref `a/b` and each ref below `a/b/`. It does
/// not select `a/bc`. [`Repo::list_refs`] applies this rule.
pub(crate) fn ref_prefixes(name: &str) -> impl Iterator<Item = &str> {
    name.match_indices('/')
        .map(|(end, _)| &name[..end])
        .chain(std::iter::once(name))
}

// A ref name can contain `/`. A component of a ref name, and a remote, is not
// empty, does not start with `-` or `.`, and holds ASCII alphanumerics, `-`,
// `.`, `_`, and alphanumeric characters that are not ASCII. The collection id
// uses the wider `is_ref_component`: not empty, not `.` or `..`, no slash, no
// NUL. `ostrya-core` holds the rule.
pub(crate) use ostrya_core::{is_ref_component as is_component, is_ref_name as is_ref_path};

/// The longest collection id, in bytes, that a push session names.
///
/// The id is one path component under `refs/mirrors/`, and a Linux file
/// system takes a name of 255 bytes at most (`NAME_MAX`).
#[cfg(any(feature = "push", feature = "receive"))]
pub(crate) const MAX_COLLECTION_ID_LEN: usize = 255;

/// Maps a collection ref to its path under `refs/`. A collection id puts the
/// ref under `refs/mirrors/<collection>/`. A `None` id gives a local ref under
/// `refs/heads/`. The collection id is one component (dots are allowed, a
/// slash or a traversal is not).
pub(crate) fn collection_ref_to_relpath(cref: &CollectionRef) -> Result<String> {
    let name = &cref.ref_name;
    match &cref.collection_id {
        Some(collection_id) => {
            if !is_component(collection_id) || !is_ref_path(name) {
                return Err(Error::InvalidRefspec(format!("{collection_id}:{name}")));
            }
            Ok(format!("refs/mirrors/{collection_id}/{name}"))
        }
        None => {
            if !is_ref_path(name) {
                return Err(Error::InvalidRefspec(name.to_owned()));
            }
            Ok(format!("refs/heads/{name}"))
        }
    }
}

/// The permission bits forced on a ref file, independent of the umask. The
/// `ostree` command writes its ref files with mode `0644`.
const REF_FILE_MODE: u32 = 0o644;
/// The request mode for a created ref parent directory, reduced by the umask.
/// The ref subdirectories of the `ostree` command are `0755` under a `022`
/// umask. In a `bare-user-shared` repository, the write then forces a parent
/// directory that it creates to [`perm::SHARED_DIR_MODE`]. So each member of
/// the repository group can publish a ref under it.
const REF_DIR_MODE: u32 = 0o777;

/// Writes or removes one ref file relative to `repo_fd`, atomically.
///
/// For `Some(checksum)`, the call:
///
/// 1. Opens `tmp/`, and creates it if it is missing.
/// 2. Creates the missing parent directories of the target.
/// 3. Writes the 65-byte `<hex>\n` content to a new temp file in `tmp/`.
/// 4. Runs `fdatasync` on the temp file if `fsync` is set.
/// 5. Renames the temp file over the target.
///
/// If `tmp/` is on a different file system, the rename fails with `EXDEV`,
/// and the call removes the temp file. `None` unlinks the ref and does not
/// use `tmp/`. An absent file is success.
///
/// Under `fsync`, the call runs `fsync` on the directory that holds the ref
/// after the rename or the unlink. So the name that the operation created or
/// removed is durable, and not only the content of the file. The call also
/// makes the name of each parent directory that it created durable, deepest
/// first. A write that fails still syncs the directories that it changed
/// before the failure.
fn write_ref_blocking(
    repo_fd: BorrowedFd<'_>,
    relpath: &str,
    checksum: Option<Checksum>,
    fsync: bool,
    repo_mode: RepoMode,
) -> Result<()> {
    let mut dirs = Vec::new();
    let written = put_ref_blocking(repo_fd, relpath, checksum, fsync, repo_mode, &mut dirs);
    written.and(sync_ref_dirs(repo_fd, dirs))
}

/// Runs the body of [`write_ref_blocking`], and leaves the directory syncs to
/// the caller.
///
/// Under `fsync`, the call adds each directory that gained or lost a name to
/// `dirs`, for [`sync_ref_dirs`]. These are the directory that holds the ref,
/// and the directory that holds each parent that this write created. The
/// call adds a created parent when it creates it, so a write that fails after
/// that step still adds it.
pub(crate) fn put_ref_blocking(
    repo_fd: BorrowedFd<'_>,
    relpath: &str,
    checksum: Option<Checksum>,
    fsync: bool,
    repo_mode: RepoMode,
    dirs: &mut Vec<String>,
) -> Result<()> {
    match checksum {
        Some(checksum) => {
            let tmp_fd = open_tmp_dir(repo_fd, repo_mode)?;
            put_ref_file_blocking(
                repo_fd,
                tmp_fd.as_fd(),
                relpath,
                checksum,
                fsync,
                repo_mode,
                dirs,
            )
        }
        None => remove_ref_blocking(repo_fd, relpath, fsync, dirs),
    }
}

/// Unlinks the ref file `relpath`. An absent file is success. Under `fsync`,
/// the call adds the directory that holds the ref to `dirs`.
fn remove_ref_blocking(
    repo_fd: BorrowedFd<'_>,
    relpath: &str,
    fsync: bool,
    dirs: &mut Vec<String>,
) -> Result<()> {
    match rustix::fs::unlinkat(repo_fd, relpath, AtFlags::empty()) {
        Ok(()) => {
            if fsync {
                dirs.push(ref_parent(relpath).to_owned());
            }
            Ok(())
        }
        Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Writes the ref file `relpath` through a temp file in the open `tmp/` at
/// `tmp_fd`, as [`put_ref_blocking`] writes a `Some` checksum.
fn put_ref_file_blocking(
    repo_fd: BorrowedFd<'_>,
    tmp_fd: BorrowedFd<'_>,
    relpath: &str,
    checksum: Checksum,
    fsync: bool,
    repo_mode: RepoMode,
    dirs: &mut Vec<String>,
) -> Result<()> {
    create_ref_parents(repo_fd, relpath, repo_mode, fsync, dirs)?;
    let content = format!("{}\n", checksum.to_hex());
    let (temp, fd) = TempEntry::create_file(tmp_fd, REF_TEMP_PREFIX, REF_FILE_MODE)?;
    let mut file = std::fs::File::from(fd);
    file.write_all(content.as_bytes())?;
    file.flush()?;
    rustix::fs::fchmod(file.as_fd(), Mode::from_raw_mode(REF_FILE_MODE))?;
    if fsync {
        rustix::fs::fdatasync(file.as_fd())?;
    }
    drop(file);
    temp.rename_into(repo_fd, relpath)?;
    if fsync {
        dirs.push(ref_parent(relpath).to_owned());
    }
    Ok(())
}

/// Sorts `dirs` deepest first, then by name, and drops the repeats.
fn sort_dirs_deepest_first(dirs: &mut Vec<String>) {
    let depth = |dir: &str| {
        if dir == "." {
            0
        } else {
            dir.split('/').count()
        }
    };
    dirs.sort_by(|a, b| depth(b).cmp(&depth(a)).then_with(|| a.cmp(b)));
    dirs.dedup();
}

/// Runs `fsync` once on each distinct directory of `dirs`, deepest first. The
/// names are relative to the repository root.
///
/// The call syncs a deeper directory before the directory above it. The
/// first sync records the name of the ref file. The next records the name of
/// the directory that holds it, and the next the name of the directory above
/// that. The object fanout uses the same order.
///
/// So a crash part way through leaves a prefix of each path recorded. It
/// never leaves a directory entry that names a directory with unrecorded
/// contents.
fn sync_ref_dirs(repo_fd: BorrowedFd<'_>, mut dirs: Vec<String>) -> Result<()> {
    sort_dirs_deepest_first(&mut dirs);
    for dir in &dirs {
        sync_dir(repo_fd, dir)?;
    }
    Ok(())
}

/// Runs `fsync` once on each distinct directory of `dirs`, in the order of
/// [`sync_ref_dirs`], and returns the first error. A failed sync does not stop
/// the syncs after it.
pub(crate) fn sync_dirs_all(repo_fd: BorrowedFd<'_>, mut dirs: Vec<String>) -> Result<()> {
    sort_dirs_deepest_first(&mut dirs);
    let mut first = Ok(());
    for dir in &dirs {
        let synced = sync_dir(repo_fd, dir);
        #[cfg(test)]
        test_syncs::record(repo_fd);
        if first.is_ok() {
            first = synced;
        }
    }
    first
}

/// The directory syncs that [`sync_dirs_all`] made, for the unit tests. Each
/// sync has one entry. The entry holds the `(device, inode)` of the
/// repository root, and a flag. The flag is `true` if a guard of this process
/// held the update lock of that repository when the sync ran.
#[cfg(test)]
pub(crate) mod test_syncs {
    use std::os::fd::BorrowedFd;
    use std::sync::Mutex;

    type Record = ((u64, u64), bool);

    static SYNCS: Mutex<Vec<Record>> = Mutex::new(Vec::new());

    pub(crate) fn record(repo_fd: BorrowedFd<'_>) {
        let held = crate::lock::update_lock_held_in_process(repo_fd);
        if let Ok(stat) = rustix::fs::fstat(repo_fd) {
            SYNCS
                .lock()
                .unwrap()
                .push(((stat.st_dev, stat.st_ino), held));
        }
    }

    fn syncs(root: &std::path::Path) -> Vec<bool> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(root).unwrap();
        let key = (meta.dev(), meta.ino());
        let syncs = SYNCS.lock().unwrap();
        syncs
            .iter()
            .filter(|(k, _)| *k == key)
            .map(|(_, held)| *held)
            .collect()
    }

    /// The number of syncs made under the repository root `root`.
    pub(crate) fn count(root: &std::path::Path) -> usize {
        syncs(root).len()
    }

    /// The number of syncs made under the repository root `root` while no
    /// guard of this process held its update lock.
    pub(crate) fn unlocked(root: &std::path::Path) -> usize {
        syncs(root).into_iter().filter(|held| !held).count()
    }
}

/// Writes one alias symlink relative to `repo_fd`, atomically.
///
/// The call:
///
/// 1. Opens `tmp/`, and creates it if it is missing.
/// 2. Creates the missing parent directories of the target.
/// 3. Creates the link under a new temp name in `tmp/`.
/// 4. Renames the link over the target.
///
/// So the call replaces an existing ref file or an existing alias in one
/// step. A symlink has no content of its own to sync. So `fsync` reaches the
/// directory that holds the link, and the directory that holds each parent
/// that this write created.
///
/// A write that fails still syncs the directories that it changed before the
/// failure.
fn write_alias_blocking(
    repo_fd: BorrowedFd<'_>,
    relpath: &str,
    link: &str,
    fsync: bool,
    repo_mode: RepoMode,
) -> Result<()> {
    let mut dirs = Vec::new();
    let written = put_alias_blocking(repo_fd, relpath, link, fsync, repo_mode, &mut dirs);
    written.and(sync_ref_dirs(repo_fd, dirs))
}

/// Runs the body of [`write_alias_blocking`], and leaves the directory syncs
/// to the caller. Under `fsync`, the call adds to `dirs` the directory that
/// holds the link, and the directory that holds each parent that this write
/// created. It adds each parent when it creates it.
pub(crate) fn put_alias_blocking(
    repo_fd: BorrowedFd<'_>,
    relpath: &str,
    link: &str,
    fsync: bool,
    repo_mode: RepoMode,
    dirs: &mut Vec<String>,
) -> Result<()> {
    let tmp_fd = open_tmp_dir(repo_fd, repo_mode)?;
    create_ref_parents(repo_fd, relpath, repo_mode, fsync, dirs)?;
    TempEntry::create_symlink(tmp_fd.as_fd(), REF_TEMP_PREFIX, link)?
        .rename_into(repo_fd, relpath)?;
    if fsync {
        dirs.push(ref_parent(relpath).to_owned());
    }
    Ok(())
}

/// Removes each ref that still names the checksum that the caller recorded
/// for it, relative to `repo_fd`, in one blocking pass.
///
/// The call maps each name to its path with the refspec rule of the
/// asynchronous writes. So the read and the unlink address the same file as
/// the rest of the library.
///
/// Each read comes immediately before its own unlink. The call leaves a ref
/// that now names a different commit where it is. This covers a repository
/// whose `[core] locking` is false, and a caller that moved the ref after it
/// recorded the checksum.
///
/// A read that finds no file unlinks all the same. The name that the caller
/// recorded is gone or dangles. `unlinkat` removes a symlink and not the file
/// that it names, and an absent name is success.
///
/// Under `fsync`, after the last unlink, the call runs `fsync` once on each
/// directory from which an unlink removed a name. So each removed name is
/// durable. The call records a directory only if its own unlink reported
/// success. A recorded directory that is gone when the pass reaches it holds
/// no entry to make durable, so its absence is success as well.
///
/// A hash set holds the membership test. A vector holds the order of the
/// `fsync` calls, which is the order of the first unlink in each directory. The
/// membership test reads the borrowed path, so a parent that the set already
/// holds costs no allocation.
///
/// Returns the names that it removed, in the order that it got them.
pub(crate) fn delete_matching_refs_blocking(
    repo_fd: BorrowedFd<'_>,
    refs: Vec<(String, Checksum)>,
    fsync: bool,
) -> Result<Vec<String>> {
    let mut removed = Vec::with_capacity(refs.len());
    let mut parents: Vec<String> = Vec::new();
    let mut held: HashSet<String> = HashSet::new();
    for (name, target) in refs {
        let relpath = refspec_to_relpath(&name)?;
        if let Some(bytes) = read_ref_file(repo_fd, &relpath)?
            && parse_ref_content(&bytes)? != target
        {
            continue;
        }
        match rustix::fs::unlinkat(repo_fd, relpath.as_str(), AtFlags::empty()) {
            Ok(()) => {
                if fsync {
                    let parent = ref_parent(&relpath);
                    if !held.contains(parent) {
                        held.insert(parent.to_owned());
                        parents.push(parent.to_owned());
                    }
                }
            }
            Err(Errno::NOENT) => {}
            Err(e) => return Err(Error::Io(e.into())),
        }
        removed.push(name);
    }
    for parent in &parents {
        sync_dir_present(repo_fd, parent)?;
    }
    Ok(removed)
}

/// Returns the directory that holds the ref at `relpath`. A refspec always
/// maps below `refs/`, so the path has a parent. For a bare name, the result
/// is the repository root.
fn ref_parent(relpath: &str) -> &str {
    relpath.rsplit_once('/').map_or(".", |(dir, _)| dir)
}

/// Runs `fsync` on one directory, named relative to the repository root, if
/// the directory still exists. A directory that is gone holds no entry to make
/// durable, so its absence is success.
fn sync_dir_present(repo_fd: BorrowedFd<'_>, path: &str) -> Result<()> {
    match sync_dir(repo_fd, path) {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Runs `fsync` on one directory, named relative to the repository root.
pub(crate) fn sync_dir(repo_fd: BorrowedFd<'_>, path: &str) -> Result<()> {
    let dir = rustix::fs::openat(
        repo_fd,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    rustix::fs::fsync(dir.as_fd())?;
    Ok(())
}

/// Creates the parent directories of a ref path, idempotently.
///
/// The call creates each component except the last, and leaves existing
/// directories in place. Under `fsync`, the call adds the directory that holds
/// each created directory to `dirs` when the `mkdirat` returns, before any
/// step that can fail. So a write that fails later still leaves the new name
/// to a sync.
///
/// A `mkdirat` adds a name to the directory that it is called in. So to make
/// a created `refs/heads/deep/nest` durable, a caller syncs `refs/heads/deep`,
/// which holds the `nest` entry: the [`ref_parent`] of the created path. A
/// directory that was already in place needs no sync, because its name is
/// already durable.
///
/// In a `bare-user-shared` repository, the call forces each directory that it
/// creates to [`perm::SHARED_DIR_MODE`]. A directory that already exists
/// keeps its mode and its group.
fn create_ref_parents(
    repo_fd: BorrowedFd<'_>,
    relpath: &str,
    repo_mode: RepoMode,
    fsync: bool,
    dirs: &mut Vec<String>,
) -> Result<()> {
    let mut acc = String::new();
    let mut components: Vec<&str> = relpath.split('/').collect();
    components.pop(); // the final component is the ref file itself
    for component in components {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(component);
        match rustix::fs::mkdirat(repo_fd, acc.as_str(), Mode::from_raw_mode(REF_DIR_MODE)) {
            Ok(()) => {
                if fsync {
                    dirs.push(ref_parent(&acc).to_owned());
                }
                perm::force_created_dir(repo_fd, acc.as_str(), repo_mode)?;
            }
            Err(Errno::EXIST) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refspec_maps_local_and_remote() {
        assert_eq!(
            refspec_to_relpath("test/main").unwrap(),
            "refs/heads/test/main"
        );
        assert_eq!(
            refspec_to_relpath("origin:test/main").unwrap(),
            "refs/remotes/origin/test/main"
        );
    }

    #[test]
    fn refspec_rejects_traversal() {
        // The error names the whole refspec, which a caller that reports a
        // refused name has in hand. It does not name the failed component.
        for bad in [
            "",
            "..",
            "a/../b",
            "/a",
            "a/",
            "a//b",
            "a/..",
            "origin:../escape",
            // A name outside the ref-name rule.
            "a b",
            "a*",
            "-a",
            "a/.b",
            "a^b",
            "a~b",
            "origin:a:b",
            "origin:a b",
            // A remote outside the ref-name rule.
            "o r:main",
            "o*:main",
            "-o:main",
            ".o:main",
            "o~:main",
            // A remote is one component, so a `/` in it names no remote.
            "a/b:x",
            ":x",
            "origin:",
        ] {
            let err = refspec_to_relpath(bad).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidRefspec(name) if name == bad),
                "should reject {bad:?}, got {err}"
            );
        }
        assert!(validate_refspec("test/main").is_ok());
        assert!(validate_refspec("origin:test/main").is_ok());
        for good in [
            "a.",
            "a..b",
            "_a",
            "a_b",
            "1a",
            "A",
            "\u{e9}",
            "a/\u{e9}b",
            "\u{e9}:main",
        ] {
            assert!(validate_refspec(good).is_ok(), "should accept {good:?}");
        }
    }

    fn patterns(texts: &[&str]) -> Vec<RefPattern> {
        texts
            .iter()
            .map(|text| RefPattern::parse(text).unwrap())
            .collect()
    }

    /// A pattern below the literal parts of a `lit/**` pattern is dropped,
    /// and a duplicate stays one time. A pattern that is not below the
    /// literal parts, one with a wildcard before the `**`, and `a/**` against
    /// `a` stay.
    #[test]
    fn a_covered_pattern_is_dropped() {
        let kept = |texts: &[&str]| -> Vec<String> {
            let all = patterns(texts);
            uncovered_patterns(&all)
                .iter()
                .map(|p| p.as_str().to_owned())
                .collect()
        };
        assert_eq!(
            kept(&["a/b", "a/**", "a/*/c", "ab", "a"]),
            ["a/**", "ab", "a"]
        );
        assert_eq!(kept(&["a/b", "a/b", "a/**", "a/**"]), ["a/**"]);
        assert_eq!(kept(&["x/y", "x/y"]), ["x/y"]);
        assert_eq!(kept(&["a/b/**", "a/**", "a/b/c"]), ["a/**"]);
        assert_eq!(kept(&["a/*/**", "a/b/c"]), ["a/*/**", "a/b/c"]);
        assert_eq!(kept(&["a/**/c", "a/**", "a/**/c"]), ["a/**"]);
        assert_eq!(kept(&["a/**/c", "b/**/c"]), ["a/**/c", "b/**/c"]);
        assert_eq!(kept(&["**", "a", "b/*"]), ["**"]);
        assert_eq!(kept(&["*", "a/b"]), ["*", "a/b"]);
    }

    /// A negative pattern covers a directory when it is `lead/**` and the
    /// directory path starts with the lead parts, where `*` stands for any
    /// part.
    #[test]
    fn a_negative_pattern_covers_a_directory() {
        let covers: Vec<Vec<&str>> = ["a/c/**", "*/x/**", "**/q", "a/**/**", "k/**"]
            .iter()
            .filter_map(|text| covering_lead(text))
            .collect();
        assert_eq!(covers, [vec!["a", "c"], vec!["*", "x"], vec!["k"]]);
        for dir in ["a/c", "a/c/d", "z/x", "k", "k/j/i"] {
            assert!(dir_is_covered(&covers, dir), "{dir}");
        }
        for dir in ["a", "a/b", "b/c", "z", "kk", "z/y"] {
            assert!(!dir_is_covered(&covers, dir), "{dir}");
        }
        assert!(dir_is_covered(&[Vec::new()], "any"));
    }

    #[test]
    fn collection_ref_names_the_pair_it_rejects() {
        let err = collection_ref_to_relpath(&CollectionRef::new("org.example.Foo", "a/../b"))
            .unwrap_err();
        assert!(
            matches!(&err, Error::InvalidRefspec(name) if name == "org.example.Foo:a/../b"),
            "{err}"
        );
        let err = collection_ref_to_relpath(&CollectionRef::local("a/../b")).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidRefspec(name) if name == "a/../b"),
            "{err}"
        );
    }

    #[test]
    fn splits_the_ancestry_suffix() {
        assert_eq!(split_ancestry("test/main"), ("test/main", 0));
        assert_eq!(split_ancestry("test/main^"), ("test/main", 1));
        assert_eq!(split_ancestry("test/main^^^"), ("test/main", 3));
        assert_eq!(split_ancestry("^"), ("", 1));
    }

    #[test]
    fn builds_the_alias_link_body() {
        // A sibling alias names the target directly.
        assert_eq!(
            relative_link("refs/heads/alias", "refs/heads/test/main"),
            "test/main"
        );
        // A nested alias climbs out of its own directory first.
        assert_eq!(relative_link("refs/heads/p/q", "refs/heads/one"), "../one");
        // A target one level up from the directory of the alias.
        assert_eq!(relative_link("refs/heads/a/b", "refs/heads/a"), "../a");
        // Across the two ref roots.
        assert_eq!(
            relative_link("refs/heads/alias", "refs/remotes/origin/main"),
            "../remotes/origin/main"
        );
    }

    /// Every case the addressability predicate is checked against, as
    /// `(name, top, path, expected)`.
    const ADDRESSABILITY_CASES: &[(&str, &str, &str, bool)] = &[
        // A local name addresses its own file where the mapping accepts it.
        ("main", "refs/heads", "main", true),
        ("test/main", "refs/heads", "test/main", true),
        // A `:` reads as the separator of a remote name, so the mapping gives
        // a path under `refs/remotes`.
        ("foo:bar", "refs/heads", "foo:bar", false),
        ("a/b:c", "refs/heads", "a/b:c", false),
        // A local name the mapping accepts still has to match the path it was
        // listed at.
        ("main", "refs/heads", "other", false),
        // A name the mapping refuses answers false as well.
        ("a/../b", "refs/heads", "a/../b", false),
        ("", "refs/heads", "", false),
        // A remote name addresses its own file where the first `/` of the path
        // is the `:` of the name.
        ("origin:main", "refs/remotes", "origin/main", true),
        ("a:pool/x", "refs/remotes", "a:pool/x", false),
        ("a:pool/x", "refs/remotes", "a/pool/x", true),
        // A `:` in the name part is outside the ref-name rule, so neither of
        // the two files that list as this name is addressable.
        ("origin:foo:bar", "refs/remotes", "origin/foo:bar", false),
        ("a:b:main", "refs/remotes", "a:b/main", false),
        ("a:b:main", "refs/remotes", "a/b:main", false),
        // A name outside the rule is not addressable, wherever its file is.
        ("a b", "refs/heads", "a b", false),
        ("-a", "refs/heads", "-a", false),
        ("a/.b", "refs/heads", "a/.b", false),
        ("a*", "refs/heads", "a*", false),
        ("origin:a b", "refs/remotes", "origin/a b", false),
        ("o r:main", "refs/remotes", "o r/main", false),
        ("-o:main", "refs/remotes", "-o/main", false),
        (".o:main", "refs/remotes", ".o/main", false),
        ("o~:main", "refs/remotes", "o~/main", false),
        ("\u{e9}:main", "refs/remotes", "\u{e9}/main", true),
        // A file directly under `refs/remotes` names no remote, so its name
        // maps under `refs/heads`.
        ("stray", "refs/remotes", "stray", false),
        // An empty remote component is refused.
        (":x:main", "refs/remotes", ":x/main", false),
        // So is a traversal, in the remote component and in the name below it.
        ("..:main", "refs/remotes", "../main", false),
        ("origin:a/../b", "refs/remotes", "origin/a/../b", false),
        // No refspec maps below `refs/mirrors`.
        (
            "org.example.Coll/mm",
            "refs/mirrors",
            "org.example.Coll/mm",
            false,
        ),
        // A remote refspec at the path that it takes under another top gives
        // false, because the mapping names one top alone.
        ("origin:main", "refs/mirrors", "origin/main", false),
    ];

    #[test]
    fn a_listed_name_addresses_its_own_file_only_where_the_mapping_returns_it() {
        for (name, top, path, expected) in ADDRESSABILITY_CASES {
            assert_eq!(
                listed_name_addresses_it(name, top, path),
                *expected,
                "{name:?} under {top:?} at {path:?}"
            );
        }
    }

    #[test]
    fn the_addressability_predicate_agrees_with_the_refspec_mapping() {
        // The predicate reads the name in place, so this holds it to the
        // mapping it mirrors.
        for (name, top, path, _) in ADDRESSABILITY_CASES {
            assert_eq!(
                listed_name_addresses_it(name, top, path),
                refspec_to_relpath(name).ok() == Some(format!("{top}/{path}")),
                "{name:?} under {top:?} at {path:?}"
            );
        }
    }

    #[test]
    fn parses_ref_content_with_newline() {
        let hex = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";
        let checksum = parse_ref_content(format!("{hex}\n").as_bytes()).unwrap();
        assert_eq!(checksum.to_hex(), hex);
        assert!(parse_ref_content(b"not-a-checksum\n").is_err());
    }

    /// A scratch directory with `refs/heads` in it, removed when the value
    /// drops.
    struct Root {
        dir: std::path::PathBuf,
        fd: std::os::fd::OwnedFd,
    }

    impl Root {
        fn new(label: &str) -> Root {
            let dir = std::env::temp_dir().join(format!(
                "ostrya-refs-{label}-{}-{}",
                std::process::id(),
                crate::write::unique()
            ));
            std::fs::create_dir_all(dir.join("refs/heads")).unwrap();
            let fd = std::fs::File::open(&dir).unwrap().into();
            Root { dir, fd }
        }

        fn fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A ref-tree walk opens a subdirectory with no symlink followed: a
    /// symlink to a directory, a regular file, and an absent entry give no
    /// directory.
    #[test]
    fn a_ref_subdirectory_opens_with_no_symlink_followed() {
        let root = Root::new("subdir-nofollow");
        let heads = root.dir.join("refs/heads");
        std::fs::create_dir(heads.join("real")).unwrap();
        std::os::unix::fs::symlink("real", heads.join("link")).unwrap();
        std::fs::write(heads.join("file"), b"").unwrap();
        let dir = std::fs::File::open(&heads).unwrap();
        assert!(open_ref_subdir(dir.as_fd(), "real").unwrap().is_some());
        for name in ["link", "file", "absent"] {
            let sub = open_ref_subdir(dir.as_fd(), name).unwrap();
            assert!(sub.is_none(), "{name}");
        }
    }

    /// The listing opens an entry that the walk found as a ref file with no
    /// symlink followed. An entry that is an alias at the open takes the
    /// alias rule, so an alias to a ref that the client does not read gives
    /// no ref. The same entry gives the ref of its target to a client that
    /// reads the target.
    #[test]
    fn a_listed_ref_file_that_is_an_alias_at_the_open_takes_the_alias_rule() {
        let root = Root::new("listed-alias");
        ostrya_rt::block_on(async {
            let repo = Repo::create(
                &root.dir.join("repo"),
                crate::CreateOptions::new(RepoMode::Archive),
            )
            .await
            .unwrap();
            let commit = Checksum::from_bytes([7; 32]);
            let heads = root.dir.join("repo/refs/heads");
            std::fs::write(heads.join("secret"), format!("{}\n", commit.to_hex())).unwrap();
            std::fs::create_dir(heads.join("pub")).unwrap();
            std::os::unix::fs::symlink("../secret", heads.join("pub/a")).unwrap();
            let dir = std::fs::File::open(heads.join("pub")).unwrap();
            let entry = RefEntry {
                dir: dir.as_fd(),
                name: "a",
                path: "pub/a",
                file_type: FileType::RegularFile,
            };
            let reader = |allow: &str| {
                let text = format!(
                    "[core]\nrepo_version=1\nmode=archive-z2\n\
                     [ex-ostrya client \"c\"]\nauth=anonymous\nallow={allow}\n"
                );
                let config = crate::RepoConfig::parse(&text).unwrap();
                let access = crate::access::ClientAccess::from_config(&config, &root.dir).unwrap();
                ReadAccess::new(
                    std::sync::Arc::new(access),
                    crate::access::AuthItem::Anonymous,
                    None,
                )
            };
            let hidden = read_listed_ref(&repo, HEADS_DIR, &entry, &reader("r:pub/**")).unwrap();
            assert_eq!(hidden, None);
            let read = read_listed_ref(&repo, HEADS_DIR, &entry, &reader("r:**"))
                .unwrap()
                .unwrap();
            assert_eq!(parse_ref_content(&read).unwrap(), commit);
        });
    }

    #[test]
    fn sync_dirs_all_runs_each_sync_past_a_failure() {
        let root = Root::new("sync-all");
        // The deepest entry sorts first, and it is a file, so its sync fails.
        std::fs::create_dir_all(root.dir.join("refs/heads/a")).unwrap();
        std::fs::write(root.dir.join("refs/heads/a/file"), b"").unwrap();
        let dirs = vec![
            ".".to_owned(),
            "refs/heads".to_owned(),
            "refs/heads/a/file".to_owned(),
            "refs/heads/a".to_owned(),
        ];
        let before = test_syncs::count(&root.dir);
        let err = sync_dirs_all(root.fd(), dirs).unwrap_err();
        assert!(
            matches!(&err, Error::Io(e) if e.raw_os_error() == Some(Errno::NOTDIR.raw_os_error())),
            "{err:?}"
        );
        assert_eq!(test_syncs::count(&root.dir), before + 4);
    }

    /// A write that fails after it created parent directories still records
    /// the directories that hold them, and leaves no temp entry in `tmp/`.
    #[test]
    fn a_failed_write_records_the_parents_it_created() {
        let root = Root::new("created");
        // A ref name of 256 bytes is longer than a file name can be. The temp
        // file in `tmp/` is created, and the rename over the ref name fails.
        let long = "r".repeat(256);
        let mut dirs = Vec::new();
        let relpath = format!("refs/heads/new/deep/{long}");
        let checksum = Some(Checksum::from_bytes([7; 32]));
        put_ref_blocking(
            root.fd(),
            &relpath,
            checksum,
            true,
            RepoMode::BareUser,
            &mut dirs,
        )
        .unwrap_err();
        dirs.sort();
        assert_eq!(dirs, ["refs/heads", "refs/heads/new"]);
        let tmp = root.dir.join("tmp");
        assert!(tmp.is_dir());
        assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);

        // A link body longer than a path can be fails the `symlinkat`.
        let mut dirs = Vec::new();
        let link = "x".repeat(5000);
        let relpath = "refs/heads/other/deep/alias";
        put_alias_blocking(
            root.fd(),
            relpath,
            &link,
            true,
            RepoMode::BareUser,
            &mut dirs,
        )
        .unwrap_err();
        dirs.sort();
        assert_eq!(dirs, ["refs/heads", "refs/heads/other"]);
        assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);
    }
}
