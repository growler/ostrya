//! Ref resolution, listing, and writes.
//!
//! A ref is a file under `refs/` that names a commit by its checksum. The
//! entry points are:
//!
//! - [`Repo::resolve_rev`] resolves a revision string to a commit. Its doc
//!   gives the revision syntax.
//! - [`Repo::resolve_ref_tip`] reads one [`Ref`] from the ref store: a local
//!   ref, a remote ref, or a collection ref.
//! - [`Repo::list_refs`], [`Repo::list_remote_refs`],
//!   [`Repo::list_mirror_refs`], [`Repo::list_collection_refs`],
//!   [`Repo::list_collection_refs_in`], and [`Repo::list_ref_aliases`] list
//!   refs.
//! - [`Repo::set_ref_immediate`] writes one ref outside a transaction. Its doc
//!   gives the ref file format and the durability rules.
//! - [`Transaction::set_ref`] queues a ref write for the transaction commit.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
#[cfg(feature = "receive")]
use std::sync::Arc;

use ostrya_core::{Checksum, Ref, RefPattern, RefSelector};
use rustix::fs::FileType;
use rustix::io::Errno;

use crate::access::{AccessRules, Namespace, ReadAccess};
use crate::archive::resolve_alias;
use crate::config::valid_remote_name;
use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::repo_fs::{FsError, FsResultExt, Publish, Reason, RepoDir, RepoLayout, TempLink};
use crate::summary::SelectionFloor;
use crate::transaction::Transaction;

/// One collection-qualified ref of a repository.
///
/// [`Repo::list_collection_refs`] returns these entries. The refs of the
/// `[core] collection-id` of the repository are the local refs, under
/// `refs/heads`. The refs of another collection id are under `refs/mirrors`
/// or under `refs/remotes`.
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
    /// `refs/mirrors` or `refs/remotes`.
    ///
    /// The collection id of the repository qualifies a ref under `refs/heads`.
    pub local: bool,
    /// The remote whose `collection-id` qualifies a ref under
    /// `refs/remotes/R/`, or `None` for a ref under `refs/heads` or
    /// `refs/mirrors`.
    pub remote: Option<String>,
}

/// A ref stored as an alias: a relative symlink to the file of another ref.
///
/// [`Repo::list_ref_aliases`] gives the aliases under `refs/heads`,
/// `refs/remotes`, and `refs/mirrors`. It does not read the directory of the
/// `[core] collection-id` under `refs/mirrors`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefAlias {
    /// The alias itself.
    ///
    /// A link under `refs/heads` is a [`Ref::Local`], a link under
    /// `refs/remotes/R/` is a [`Ref::Remote`] of the remote `R`, and a link
    /// under `refs/mirrors/ID/` is a [`Ref::Collection`] of the id `ID`. The
    /// listing does not check the name, so it can be a ref that fails
    /// [`Ref::validate`]. The remove calls refuse such a ref.
    pub name: Ref,
    /// The ref that the body of the link names, or `None`.
    ///
    /// The body resolves against the directory of the link, and the path
    /// that it gives maps back to a ref, as the ref store maps a ref to a
    /// path. The value is `None` when the body leaves `refs/`, when the path
    /// names no ref, when the path is under the directory of the `[core]
    /// collection-id` under `refs/mirrors`, or when the ref fails
    /// [`Ref::validate`]. Thus `None` tells that the body names no ref path
    /// that the store addresses by a [`Ref`]. It does not tell that the
    /// alias resolves to no commit: the resolve of the alias follows a body
    /// into the directory of the `[core] collection-id` and reads the file
    /// there. The ref that a `Some` value names can be absent: a resolve of
    /// it then gives no commit.
    pub target: Option<Ref>,
    /// The body of the link, as stored.
    pub body: String,
}

/// The state of one ref path, as [`ref_file_state`] and [`lstat_ref_state`]
/// read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefFileState {
    /// No file stands at the path.
    Absent,
    /// A ref file, and the commit it names.
    Commit(Checksum),
    /// A symlink: an alias of another ref.
    Alias,
    /// Something a ref write cannot replace, and the reason: the path names
    /// a directory, passes through a file or an alias, or names a special
    /// file.
    NotARef(&'static str),
}

/// One queued ref write: a target and the checksum to point it at (`None`
/// removes the ref).
pub(crate) struct RefWrite {
    target: Ref,
    checksum: Option<Checksum>,
    /// The state that the ref must have before the write. `None` sets no
    /// expectation. `Some(None)` expects that no file stands at the path.
    /// `Some(Some(c))` expects a ref file that names `c`.
    expected: Option<Option<Checksum>>,
}

/// One queued ref write, with the path of its ref under the repository.
pub(crate) struct ResolvedRef {
    /// The ref that the transaction queued, in its canonical form: a ref of
    /// the own collection id is a local ref.
    name: Ref,
    /// The path of the ref under the repository.
    relpath: String,
    /// The commit to write, or `None` to remove the ref.
    checksum: Option<Checksum>,
    /// The state that the ref must have before the write, as
    /// [`RefWrite`] holds it.
    expected: Option<Option<Checksum>>,
}

/// Methods that queue ref writes for the transaction commit.
impl Transaction {
    /// Queues a ref write for the transaction commit.
    ///
    /// [`commit`](Transaction::commit) writes the ref after it publishes the
    /// objects. If `checksum` is `None`, the commit removes the ref.
    ///
    /// The ref gives the path, as
    /// [`set_ref_immediate`](Repo::set_ref_immediate) states. A collection
    /// ref of the `[core] collection-id` of the repository is at
    /// `refs/heads/<name>`, so the commit writes or removes that file, and it
    /// does not touch `refs/mirrors/<collection>/`.
    ///
    /// The call itself does not check the ref. If the ref fails
    /// [`Ref::validate`], the commit fails with [`Error::InvalidRefspec`],
    /// which holds the text of the ref. The commit then publishes no object
    /// and writes no ref.
    ///
    /// The commit checks the queued refs under the update lock, before the
    /// first write. It fails with [`Error::RefNotWritable`] and writes no ref
    /// in these cases:
    ///
    /// - The path of a queued write or removal names a directory, passes
    ///   through a file, or names a special file. A removal whose path passes
    ///   through a file passes the check when an earlier removal of the same
    ///   transaction removes a path above it at any level, for example `a`
    ///   for `a/b/c`. The unlink of `a` leaves `a/b/c` absent. A removal of
    ///   `a/b`, then a removal of `a`, fails. An entry of
    ///   [`set_ref_expecting`](Transaction::set_ref_expecting) does not take
    ///   this exception.
    /// - The path of a queued write or removal names an alias. To remove an
    ///   alias, use [`Repo::remove_ref_alias_immediate`] or
    ///   [`UpdateGuard::remove_ref_alias`](crate::UpdateGuard::remove_ref_alias).
    /// - The path of a queued write or removal passes through an alias: a
    ///   symlink at a component above the ref, from the repository root
    ///   down, also a dangling one. The reason is `passes through an alias`.
    /// - The path of one queued ref names a directory of the path of another
    ///   queued ref, and one of the two is a write. Examples are a write of
    ///   `a` and a write of `a/b`, or a removal of `a` and a write of `a/b`.
    ///
    /// The check opens each queued path with `openat2`, `RESOLVE_BENEATH`,
    /// and `RESOLVE_NO_SYMLINKS`. The open has no fallback. On a kernel
    /// without `openat2`, the commit fails with [`Error::Io`].
    ///
    /// The check reads the ref store as it is before the first write. The
    /// writes follow no symlink either: each write opens the directory of its
    /// ref with no symlink followed, and renames or unlinks relative to it. A
    /// writer that does not take the update lock can put a symlink above a
    /// queued path after the check. The write of that path then fails with
    /// [`Error::InvalidFormat`], and never goes through the symlink.
    ///
    /// If a directory of `refs/mirrors/` has a name that fails the rule, a
    /// ref under it cannot be written or removed through this call. Remove
    /// such a ref by hand.
    ///
    /// To write the ref only if it has a known state, use
    /// [`set_ref_expecting`](Transaction::set_ref_expecting).
    pub fn set_ref(&self, r: &Ref, checksum: Option<&Checksum>) {
        self.refs.lock().unwrap().push(RefWrite {
            target: r.clone(),
            checksum: checksum.copied(),
            expected: None,
        });
    }

    /// Queues a ref write for the transaction commit, on the condition that
    /// the ref has the state `expected`.
    ///
    /// The arguments are:
    ///
    /// - `r`: the ref to write or remove.
    /// - `expected`: the state of the ref before the write. `None` expects
    ///   that no file stands at the path of the ref. `Some(c)` expects a ref
    ///   file that names `c`. If the path of the ref names a directory or
    ///   passes through a file or an alias, the commit fails with
    ///   [`Error::RefNotWritable`], also for `None`.
    ///   [`Repo::resolve_ref_tip`] gives `None` for a path that passes
    ///   through a file, so a caller that gives back that `None` as
    ///   `expected` gets this error. For a path that names a directory,
    ///   [`Repo::resolve_ref_tip`] fails with [`Error::NotARef`], and for a
    ///   path below an alias with [`Error::InvalidFormat`].
    /// - `new`: the commit to write. If `new` is `None`, the commit removes
    ///   the ref.
    ///
    /// The path rules and the checks of [`set_ref`](Transaction::set_ref)
    /// apply. The commit compares each conditional entry in the same check,
    /// under the update lock, before it writes the detached metadata and the
    /// first ref. The compare reads the ref store as it is before the first
    /// write. This is also true when an earlier entry of the same transaction
    /// writes the same ref.
    ///
    /// The commit fails and writes no detached metadata and no ref in these
    /// cases:
    ///
    /// - The ref does not have the state `expected`:
    ///   [`Error::RefMismatch`].
    /// - The path of the ref names an alias, or passes through an alias:
    ///   [`Error::RefNotWritable`].
    /// - The ref file does not parse, or is larger than 4096 bytes:
    ///   [`Error::InvalidFormat`] or [`Error::Core`].
    pub fn set_ref_expecting(&self, r: &Ref, expected: Option<&Checksum>, new: Option<&Checksum>) {
        self.refs.lock().unwrap().push(RefWrite {
            target: r.clone(),
            checksum: new.copied(),
            expected: Some(expected.copied()),
        });
    }

    /// Takes the queued refs out of the queue and maps each one to its path
    /// under the repository. A malformed ref fails the call.
    /// [`commit`](Transaction::commit) calls it first, so a malformed ref
    /// fails before the commit publishes any object.
    pub(crate) fn resolve_ref_queue(&self) -> Result<Vec<ResolvedRef>> {
        let own = self.repo().config().collection_id();
        let queue = std::mem::take(&mut *self.refs.lock().unwrap());
        queue
            .into_iter()
            .map(|w| {
                let relpath = ref_relpath(own, &w.target)?;
                Ok(ResolvedRef {
                    name: w.target.canonical(own),
                    relpath,
                    checksum: w.checksum,
                    expected: w.expected,
                })
            })
            .collect()
    }
}

/// Checks the resolved refs of a transaction against the ref store, on the
/// blocking pool.
///
/// The caller holds the update lock and calls this before the first write.
/// The check reads each path with [`lstat_ref_state`], so it follows no
/// symlink above the ref. It reads the path of an entry with no expectation
/// with `lstat` alone, and does not read the content of a ref file. It reads
/// the path of a conditional entry with [`ref_file_state`], and parses the
/// ref file. It gives the first failure:
///
/// 1. In queue order, a write or a removal whose path names a directory,
///    passes through a file or an alias, names a special file, or names an
///    alias:
///    [`Error::RefNotWritable`]. For a conditional entry, a state other than
///    the expected state gives [`Error::RefMismatch`], and a ref file that
///    does not parse gives the error of the parse. A removal with no
///    expectation whose path passes through a file passes when an earlier
///    removal of the queue, with or without an expectation, removes a path
///    above it at any level, for example `a` for `a/b/c`.
/// 2. Two entries where the path of one names a directory of the path of the
///    other, and one of the two is a write: [`Error::RefNotWritable`]. The
///    error names the outer ref. Two removals pass, and so does one path
///    queued two times.
pub(crate) fn check_resolved_refs_blocking(root: &RepoDir, refs: &[ResolvedRef]) -> Result<()> {
    let not_writable = |r: &ResolvedRef, reason: String| Error::RefNotWritable {
        name: r.name.to_string(),
        reason,
    };
    // The paths of the removals queued so far.
    let mut removed: HashSet<&str> = HashSet::new();
    for r in refs {
        match r.expected {
            None => match lstat_ref_state(root, &r.relpath)? {
                Some(RefFileState::Alias) => {
                    return Err(not_writable(r, NAMES_AN_ALIAS.to_owned()));
                }
                Some(RefFileState::NotARef(reason))
                    if !(reason == PASSES_THROUGH_A_FILE
                        && r.checksum.is_none()
                        && parent_paths(&r.relpath).any(|p| removed.contains(p))) =>
                {
                    return Err(not_writable(r, reason.to_owned()));
                }
                _ => {}
            },
            Some(expected) => {
                let current = match ref_file_state(root, &r.relpath)? {
                    RefFileState::Absent => None,
                    RefFileState::Commit(c) => Some(c),
                    RefFileState::Alias => {
                        return Err(not_writable(r, NAMES_AN_ALIAS.to_owned()));
                    }
                    RefFileState::NotARef(reason) => {
                        return Err(not_writable(r, reason.to_owned()));
                    }
                };
                if current != expected {
                    return Err(Error::RefMismatch {
                        name: r.name.to_string(),
                        expected,
                        current,
                    });
                }
            }
        }
        if r.checksum.is_none() {
            removed.insert(&r.relpath);
        }
    }
    let entries: Vec<(&str, bool)> = refs
        .iter()
        .map(|r| (r.relpath.as_str(), r.checksum.is_some()))
        .collect();
    if let Some((outer, inner)) = nested_ref_paths(&entries) {
        return Err(not_writable(
            &refs[outer],
            format!(
                "names a directory of ref {} of the same transaction",
                refs[inner].name
            ),
        ));
    }
    Ok(())
}

/// Returns each ref that the resolved refs `refs` of a transaction change, on
/// the blocking pool.
///
/// The caller holds the update lock, and calls this after
/// [`check_resolved_refs_blocking`] and before the first write. The result
/// holds one entry for each ref path, at the place of its first entry in
/// `refs`, with the last commit that `refs` queues for it. A path whose last
/// entry is a removal gives no entry.
///
/// The old commit is the expected commit of a conditional entry at the path,
/// which the check confirmed. Else the call reads the path one time with
/// [`RepoDir::read_capped`] and the cap [`REF_READ_CAP`], and parses the
/// content with [`parse_ref_content`]. The check passed, so a path whose last
/// entry is a write is absent or a regular file, and the call does not
/// `lstat` it again. The read follows no symlink and does not wait on a
/// FIFO. Each error of the read or of the parse gives no old commit, so the
/// read never fails the commit. An entry whose old commit is its new commit
/// is not in the result.
pub(crate) fn ref_changes_blocking(
    root: &RepoDir,
    refs: &[ResolvedRef],
) -> Vec<crate::pull::RefChange> {
    // For each path: its first entry, its last queued commit, and the
    // expected commit of a conditional entry at it.
    let mut paths = Vec::with_capacity(refs.len());
    let mut index: HashMap<&str, usize> = HashMap::with_capacity(refs.len());
    for r in refs {
        let at = *index.entry(r.relpath.as_str()).or_insert_with(|| {
            paths.push((r, None, None));
            paths.len() - 1
        });
        let path = &mut paths[at];
        path.1 = r.checksum;
        path.2 = path.2.or(r.expected);
    }
    paths
        .into_iter()
        .filter_map(|(first, new, expected)| {
            let new = new?;
            let old = expected.unwrap_or_else(|| {
                root.read_capped(&first.relpath, REF_READ_CAP)
                    .ok()
                    .and_then(|bytes| parse_ref_content(&bytes).ok())
            });
            (old != Some(new)).then(|| crate::pull::RefChange {
                name: first.name.clone(),
                old,
                new,
            })
        })
        .collect()
}

/// Returns the parent directories of the ref path `path`, nearest first:
/// `a/b` and `a` for `a/b/c`.
fn parent_paths(path: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(path), |p| p.rsplit_once('/').map(|(parent, _)| parent)).skip(1)
}

/// Finds two entries where the path of one names a directory of the path of
/// the other, and one of the two is a write.
///
/// Each entry is a ref path and `true` for a write. The result is the index
/// of the outer entry and the index of the inner entry. The outer entry is
/// the first entry at its path, and a path writes if an entry at it writes.
/// The call tries the inner entries in order, and the parents of each one
/// nearest first. One path queued two times is no pair.
pub(crate) fn nested_ref_paths(entries: &[(&str, bool)]) -> Option<(usize, usize)> {
    // For each path: the first entry at it, and `true` if an entry at it
    // writes.
    let mut paths: HashMap<&str, (usize, bool)> = HashMap::new();
    for (i, &(path, writes)) in entries.iter().enumerate() {
        paths.entry(path).or_insert((i, false)).1 |= writes;
    }
    entries
        .iter()
        .enumerate()
        .find_map(|(inner, &(path, inner_writes))| {
            parent_paths(path).find_map(|parent| match paths.get(parent) {
                Some(&(outer, outer_writes)) if outer_writes || inner_writes => {
                    Some((outer, inner))
                }
                _ => None,
            })
        })
}

/// Writes the resolved refs of a transaction, each one atomically, on the
/// blocking pool.
///
/// The call uses the fsync policy that the transaction resolved, so the
/// object writes, the publication step, and the ref writes read one value.
///
/// The durability invariant: with fsync on, each ref file is `fsync`-ed
/// before its rename. Each directory that a write makes is synced into its
/// parent when the write makes it. After the last rename, each directory
/// that gained or lost a ref name is `fsync`-ed once, deepest first, before
/// the call returns.
///
/// Before the call, the caller made durable the objects and the detached
/// metadata that the refs name. So no ref is durable before what it names. A
/// write that fails still syncs the directories of the refs written before
/// it.
///
/// `root` is the handle of the repository root.
pub(crate) fn write_resolved_refs_blocking(
    root: &RepoDir,
    refs: &[ResolvedRef],
    fsync: bool,
) -> Result<()> {
    let mut dirs = Vec::new();
    let written = refs.iter().try_for_each(|r| match r.checksum {
        Some(checksum) => put_ref_file_blocking(root, &r.relpath, checksum, fsync, &mut dirs),
        None => remove_ref_blocking(root, &r.relpath, fsync, &mut dirs),
    });
    if !fsync {
        return written;
    }
    let synced = sync_ref_dirs(root, dirs);
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
    /// 3. A ref in a text form of [`Ref`]: `NAME`, `REMOTE:NAME`, or
    ///    `@ID:NAME`. It resolves to the commit that the ref names, read at
    ///    the path that [`resolve_ref_tip`](Repo::resolve_ref_tip) reads.
    ///    `@ID:NAME` reads `refs/mirrors/ID/NAME`, or `refs/heads/NAME` when
    ///    `ID` is the `[core] collection-id` of the repository. The read
    ///    rules of [`resolve_ref_tip`](Repo::resolve_ref_tip) apply: a ref
    ///    path that passes through a ref file names no ref, and a ref path
    ///    that names a directory, a FIFO, a socket, or a device file fails
    ///    with [`Error::NotARef`]. An alias resolves by the alias rule.
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
    ///   valid ref.
    /// - [`Error::AmbiguousRefspec`] if more than one commit checksum starts
    ///   with the abbreviated checksum.
    /// - [`Error::NoParentCommit`] if a `^` steps back from a commit with no
    ///   parent.
    /// - [`Error::ObjectNotFound`] if a `^` step reads a commit that is not in
    ///   the repository.
    /// - [`Error::NotARef`] if the ref path of the base names an entry that
    ///   is not a ref, as [`resolve_ref_tip`](Repo::resolve_ref_tip) states.
    ///   The error holds the base as text.
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8 or is larger
    ///   than 4096 bytes, or if the ref path passes through a symlink.
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
            match ostrya_rt::unblock(move || match_abbreviated(repo.objects(), &prefix)).await? {
                AbbrevMatch::One(checksum) => return Ok(Some((checksum, RevKind::Checksum))),
                AbbrevMatch::Ambiguous => return Err(Error::AmbiguousRefspec(rev.to_owned())),
                AbbrevMatch::None => {}
            }
        }

        let r: Ref = rev.parse()?;
        let relpath = ref_relpath(self.config().collection_id(), &r)?;
        match self.resolve_named_tip(rev.to_owned(), relpath).await? {
            Some(checksum) => Ok(Some((checksum, RevKind::Ref))),
            None if allow_noent => Ok(None),
            None => Err(Error::RefNotFound(rev.to_owned())),
        }
    }

    /// Returns the commit that a ref names, read from the ref store only.
    ///
    /// The ref selects the path, as
    /// [`set_ref_immediate`](Repo::set_ref_immediate) states. A collection
    /// ref of the `[core] collection-id` of the repository reads
    /// `refs/heads/NAME`, and the call does not read `refs/mirrors/ID/`. The
    /// call reads `[core] collection-id` from the config that the handle read
    /// at the open.
    ///
    /// The call does not read the name as a checksum, as an abbreviated
    /// checksum, or with a `^` suffix. The result is `None` if no entry is at
    /// the path, or if the path passes through a ref file. A caller that
    /// needs an error for an absent ref gives [`Error::RefNotFound`] with the
    /// text of the ref.
    ///
    /// The read follows no symlink at a component of the path, from the
    /// repository root down. It opens the ref file with `O_NONBLOCK`, and
    /// then checks its type, so the open of a FIFO does not wait for a
    /// writer. An open that the permissions refuse fails with [`Error::Io`],
    /// also at a FIFO.
    ///
    /// If the ref is an alias, the call reads the ref that the alias names by
    /// the alias rule:
    ///
    /// - The body of the alias is a relative path. It resolves against the
    ///   directory of the alias to a path below `refs/`.
    /// - The target is a ref file: a regular file. The call reads the type of
    ///   the target before it opens it.
    /// - No component of the target path is a symlink, and the target itself
    ///   is not an alias.
    ///
    /// An alias whose target is absent, or whose target path passes through
    /// a ref file, names no ref, and the result is `None`. An alias that
    /// breaks the rule fails with [`Error::NotARef`]. So an alias to an
    /// absolute path, to a path outside `refs/`, to another alias, or to
    /// itself names no commit. The ref listings apply the same rule, and give
    /// no ref for such an alias.
    ///
    /// Callers that hold a ref name and not a revision use this call. These
    /// are a media export and a media import for their refs, a summary for
    /// the metadata ref that it chains, and the CLI for its alias-target
    /// check. An alias records a name, so the CLI uses this call.
    ///
    /// The call takes no lock. It does not wait for an
    /// [`UpdateGuard`](crate::UpdateGuard) or for a transaction. A ref write
    /// renames a complete file over the ref, so the read gives the old commit
    /// or the new commit.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if the ref fails [`Ref::validate`]. The
    ///   error holds the text of the ref, and the call reads no file.
    /// - [`Error::NotARef`] if the path names a directory, a FIFO, a socket,
    ///   or a device file (reason `is not a regular file`), or an alias that
    ///   breaks the alias rule. The error holds the text of the ref.
    /// - [`Error::InvalidFormat`] if the ref file is not UTF-8 or is larger
    ///   than 4096 bytes, or if a component of the path, for example
    ///   `refs/heads`, is a symlink.
    /// - [`Error::Core`] if the ref file holds no checksum.
    /// - [`Error::Io`] if the read fails, for example on a ref file that the
    ///   process cannot read.
    pub async fn resolve_ref_tip(&self, r: &Ref) -> Result<Option<Checksum>> {
        let relpath = ref_relpath(self.config().collection_id(), r)?;
        self.resolve_named_tip(r.to_string(), relpath).await
    }

    /// Returns the commit that the ref file at `relpath` names, by the read
    /// rules of [`resolve_ref_tip`](Repo::resolve_ref_tip). An error that
    /// names the ref names it as `relpath`.
    ///
    /// The read and the parse run in one call on the blocking pool.
    pub(crate) async fn resolve_relpath_tip(&self, relpath: String) -> Result<Option<Checksum>> {
        self.resolve_named_tip(relpath.clone(), relpath).await
    }

    /// Returns the commit that the ref file at `relpath` names, by the read
    /// rules of [`resolve_ref_tip`](Repo::resolve_ref_tip). An error that
    /// names the ref names it as `name`.
    async fn resolve_named_tip(&self, name: String, relpath: String) -> Result<Option<Checksum>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || read_ref_tip(repo.root_dir(), &name, &relpath)).await
    }

    /// Runs [`resolve_relpath_tip`](Repo::resolve_relpath_tip) on the calling
    /// thread.
    pub(crate) fn resolve_relpath_tip_blocking(&self, relpath: &str) -> Result<Option<Checksum>> {
        read_ref_tip(self.root_dir(), relpath, relpath)
    }

    /// Returns the commits of the ref files at several paths under `refs/`,
    /// in one pass on the blocking pool. The result holds one entry for each
    /// path, in order.
    ///
    /// The call first reads the type of the entry at each path, and follows
    /// no symlink. These paths read as absent: an absent entry, a directory,
    /// a FIFO, a socket, a device, a path that passes through a file, and a
    /// path with a symlink at a component before the last one. A regular
    /// file and a symlink at the last component, an alias, are then read as
    /// [`resolve_ref_tip`](Repo::resolve_ref_tip) reads a refspec. An alias
    /// that gives [`Error::NotARef`] reads as absent. Each other error fails
    /// the call. The check under the update lock refuses a write or a delete
    /// at each path that reads as absent, except at an absent entry.
    #[cfg(feature = "receive")]
    pub(crate) async fn resolve_relpath_tips(
        &self,
        relpaths: Arc<[String]>,
    ) -> Result<Vec<Option<Checksum>>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            let root = repo.root_dir();
            relpaths
                .iter()
                .map(|p| {
                    if let Some(RefFileState::Absent | RefFileState::NotARef(_)) =
                        lstat_ref_state(root, p)?
                    {
                        return Ok(None);
                    }
                    match read_ref_tip(root, p, p) {
                        Err(Error::NotARef { .. }) => Ok(None),
                        other => other,
                    }
                })
                .collect()
        })
        .await
    }

    /// Returns the state of the ref file at each of several paths under
    /// `refs/`, and the commit of the refspec `tip`, in one pass on the
    /// blocking pool. The result holds one state for each path, in order.
    ///
    /// The call reads each ref path with [`ref_file_state`]: the type of the
    /// entry first, and then the content of a regular file, which it parses.
    /// A ref that does not parse fails the call.
    ///
    /// If `tip` is given, the call reads it at the path where
    /// [`resolve_ref_tip`](Repo::resolve_ref_tip) reads it, by the same
    /// rules. The result holds the failure of `tip` separately, so the caller
    /// decides if it needs the value.
    #[cfg(feature = "receive")]
    #[allow(clippy::type_complexity)]
    pub(crate) async fn read_ref_states(
        &self,
        relpaths: Arc<[String]>,
        tip: Option<&str>,
    ) -> Result<(Vec<RefFileState>, Option<Result<Option<Checksum>>>)> {
        let tip = tip.map(|refspec| refspec_to_relpath(refspec).map(|p| (refspec.to_owned(), p)));
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            let root = repo.root_dir();
            let states = relpaths
                .iter()
                .map(|p| ref_file_state(root, p))
                .collect::<Result<Vec<_>>>()?;
            let tip = tip.map(|named| {
                let (name, relpath) = named?;
                read_ref_tip(root, &name, &relpath)
            });
            Ok((states, tip))
        })
        .await
    }

    /// Returns the local refs as `(name, commit)` pairs, sorted by name.
    ///
    /// The local refs are under `refs/heads`. If `prefix` is given, the result
    /// holds only the ref named `prefix` and the refs below `prefix/`.
    ///
    /// The call opens `refs/` and `refs/heads/` with no symlink followed, and
    /// below them it opens each directory and each ref file with no symlink
    /// followed. A symlink entry is an alias, and the walk never goes into
    /// it. An alias resolves by the alias rule of
    /// [`resolve_ref_tip`](Repo::resolve_ref_tip), and the call reads the
    /// type of its target before it opens the target. An alias that breaks
    /// the rule, and an alias whose target names no ref, are not in the
    /// result.
    ///
    /// A ref entry that is a FIFO, a socket, or a device file is not in the
    /// result. The call does not open such an entry, so its permissions have
    /// no effect on the call. The call checks the type of each file that it
    /// opens, and an open does not wait for a writer. An open that the
    /// permissions refuse fails the call, also at the target of an alias.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8 or is larger
    ///   than 4096 bytes, or if `refs` or `refs/heads` is a symlink.
    /// - [`Error::Core`] if a ref file holds no checksum.
    /// - [`Error::Io`] if a read from the file system fails.
    ///
    /// [`list_refs_where`](Repo::list_refs_where) lists the local refs and the
    /// collection refs that a predicate selects, and it reads no ref file
    /// that the predicate drops.
    pub async fn list_refs(&self, prefix: Option<&str>) -> Result<Vec<(String, Checksum)>> {
        let repo = self.clone();
        let mut refs =
            ostrya_rt::unblock(move || collect_heads(&repo, open_refs(&repo)?.as_ref(), &|_| true))
                .await?;
        if let Some(prefix) = prefix {
            refs.retain(|(name, _)| ref_prefixes(name).any(|part| part == prefix));
        }
        refs.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(refs)
    }

    /// Returns the local refs and the collection refs that `keep` selects,
    /// each with its commit.
    ///
    /// The call lists these refs:
    ///
    /// - Each ref under `refs/heads`, as a [`Ref::Local`].
    /// - Each ref under `refs/mirrors/ID/` of a valid collection id other
    ///   than the `[core] collection-id` of the repository, as a
    ///   [`Ref::Collection`] of `ID`.
    ///
    /// The call applies `keep` to each ref before it reads the ref file, so
    /// it never reads a ref file that `keep` drops. It does not read
    /// `refs/mirrors/ID/` of the `[core] collection-id` of the repository,
    /// a directory under `refs/mirrors` whose name fails
    /// [`is_valid_collection_id`](crate::is_valid_collection_id), or a file
    /// directly under `refs/mirrors`, and it does not call `keep` for them.
    /// The result holds no remote ref.
    ///
    /// The call reads each ref and each alias that `keep` selects by the rules
    /// of [`list_refs`](Repo::list_refs), and opens `refs/mirrors/` with no
    /// symlink followed. An alias that breaks the alias rule, an alias whose
    /// target names no ref, and a ref entry that is a FIFO, a socket, or a
    /// device file are not in the result.
    ///
    /// The local refs come first, sorted by name. The collection refs come
    /// after them, sorted by collection id and then by name. The sort is the
    /// byte order of the strings.
    ///
    /// The call runs on the blocking pool.
    ///
    /// # Errors
    ///
    /// For a ref that `keep` selects:
    ///
    /// - [`Error::InvalidFormat`] if the ref file is not UTF-8 or is larger
    ///   than 4096 bytes.
    /// - [`Error::Core`] if the ref file holds no checksum.
    /// - [`Error::Io`] if a read from the file system fails.
    ///
    /// Also [`Error::InvalidFormat`] if `refs`, `refs/heads`, `refs/mirrors`,
    /// or an entry directly under `refs/mirrors` is a symlink, whatever
    /// `keep` selects, and [`Error::Io`] if the read of a directory under
    /// `refs/heads` or `refs/mirrors` fails.
    pub async fn list_refs_where(
        &self,
        keep: impl Fn(&Ref) -> bool + Send + 'static,
    ) -> Result<Vec<(Ref, Checksum)>> {
        let repo = self.clone();
        let own = self.config().collection_id().map(str::to_owned);
        ostrya_rt::unblock(move || {
            let refs = open_refs(&repo)?;
            let mut heads = collect_heads(&repo, refs.as_ref(), &|name| keep(&Ref::local(name)))?;
            heads.sort_by(|a, b| a.0.cmp(&b.0));
            // A directory directly under `refs/mirrors` is a collection. The
            // walk skips the own id and an id that is not valid.
            let skip = |path: &str| {
                !path.contains('/')
                    && (Some(path) == own.as_deref() || !ostrya_core::is_valid_collection_id(path))
            };
            // An entry directly under `refs/mirrors` has no collection id.
            let keep_mirror = |path: &str| {
                path.split_once('/')
                    .is_some_and(|(id, name)| keep(&Ref::collection(id, name)))
            };
            let mut mirrors = collect_mirrors(&repo, refs.as_ref(), &skip, &keep_mirror)?;
            mirrors.sort_unstable_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
            let mut out = Vec::with_capacity(heads.len() + mirrors.len());
            out.extend(heads.into_iter().map(|(name, c)| (Ref::local(name), c)));
            out.extend(
                mirrors
                    .into_iter()
                    .map(|(id, name, c)| (Ref::collection(id, name), c)),
            );
            Ok(out)
        })
        .await
    }

    /// Returns the refs that `refs` and `collections` select and `access`
    /// reads, for a ref listing.
    ///
    /// # Local refs
    ///
    /// The local refs are the refs of `refs/heads`. The call does not read
    /// `refs/mirrors/ID/` of the `[core] collection-id` of the config.
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
    /// With no positive pattern, the patterns of the allow items that give
    /// `r` in the group of the namespace take the place of the positive
    /// patterns in the walk, and the walk does not read a directory that a
    /// deny item of the group covers. The walk enumerates a name that the
    /// ref-name rule refuses, and a wildcard selects it.
    ///
    /// The result holds a ref only when `access` reads its name. The call
    /// checks the name before it reads the ref file, so a ref file that
    /// `access` does not read is never read. When `access` reads no local
    /// ref, or when a negative pattern of `refs` is `**`, the call does not
    /// open `refs/heads/`. The call opens `refs/`, `refs/heads/`, and
    /// `refs/mirrors/` with no symlink followed. Below these directories, it
    /// opens each ref file and each directory with no symlink followed. An
    /// alias resolves by the alias rule of
    /// [`resolve_ref_tip`](Repo::resolve_ref_tip), and only when `access`
    /// reads the target path. The call reads the type of the target before
    /// it opens the target. An alias that breaks the rule, and an alias
    /// whose target names no regular file, are not in the result. The call
    /// does not open a ref entry that is a FIFO, a socket, or a device file,
    /// and such an entry is not in the result. An entry that changes into
    /// such a file before its open is not in the result, and its open does
    /// not wait for a writer.
    ///
    /// # Collection refs
    ///
    /// With `collections`, the call reads the top level of `refs/mirrors/`
    /// one time. `collections` selects the refs of each other collection by
    /// `ID/NAME`, with the rules above, and `access` reads them with the
    /// group of the item in the namespace of `ID`. The call skips a
    /// collection whose group gives no `r` before it reads the directory. It
    /// also skips a name that is not UTF-8, and an entry that is no
    /// directory. A symlink at the top level fails the call with
    /// [`Error::InvalidFormat`]. A directory whose name fails the
    /// collection-id rule goes to
    /// `invalid_dirs`, and the call reads no entry in it. The call skips the
    /// directory of an id that no positive pattern can reach, or that a
    /// negative pattern covers, before it reads the rights of the id. The
    /// own collection id is not a collection of the result. With `None`, the
    /// call does not open `refs/mirrors/`.
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
            let mut selection = RefSelection::default();
            let reads_local = !selects_no_name(&refs) && access.reads_local_refs();
            let refs_dir = if reads_local || collections.is_some() {
                open_refs(&repo)?
            } else {
                None
            };
            collect_local_selected(
                &repo,
                refs_dir.as_ref(),
                &refs,
                &access,
                &mut floor,
                &mut selection,
            )?;
            if let Some(collections) = &collections
                && let Some(mirrors) = open_top_in(refs_dir.as_ref(), MIRRORS_DIR)?
            {
                collect_collections_selected(
                    &repo,
                    &mirrors,
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
    /// and the result does not hold it. The call reads the refs
    /// and the aliases by the rules of [`list_refs`](Repo::list_refs). An
    /// alias that breaks the alias rule, an alias whose target names no ref,
    /// and a ref entry that is a FIFO, a socket, or a device file are not in
    /// the result.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8 or is larger
    ///   than 4096 bytes, or if `refs`, `refs/remotes`, or an entry directly
    ///   under `refs/remotes` is a symlink.
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
    /// The call reads the refs and the aliases by the rules of
    /// [`list_refs`](Repo::list_refs). An alias that breaks the alias rule,
    /// an alias whose target names no ref, and a ref entry that is a FIFO, a
    /// socket, or a device file are not in the result.
    ///
    /// The result holds the refs of `refs/mirrors/ID/` of the
    /// `[core] collection-id` of the repository. The ref resolve, the
    /// collection ref listings, and the summary ignore that directory.
    ///
    /// The result is not sorted. A caller that needs a stable order sorts it.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8 or is larger
    ///   than 4096 bytes, or if `refs`, `refs/mirrors`, or an entry directly
    ///   under `refs/mirrors` is a symlink.
    /// - [`Error::Core`] if a ref file holds no checksum.
    /// - [`Error::Io`] if a read from the file system fails.
    pub async fn list_mirror_refs(&self) -> Result<Vec<(String, String, Checksum)>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            collect_mirrors(&repo, open_refs(&repo)?.as_ref(), &|_| false, &|_| true)
        })
        .await
    }

    /// Returns the collection-qualified refs, sorted by collection id and ref
    /// name.
    ///
    /// The result holds:
    ///
    /// - The local refs, qualified by the `[core] collection-id` of the
    ///   repository, if the config sets one.
    /// - Each ref under `refs/mirrors`, which holds its collection id in its
    ///   path, except the refs of `refs/mirrors/ID/` of the
    ///   `[core] collection-id` of the repository. The call does not read
    ///   that directory.
    /// - Each ref under `refs/remotes/R/` of a remote R whose config sets a
    ///   `collection-id`, qualified by that id. The call skips a remote
    ///   whose `collection-id` holds a malformed escape sequence, fails
    ///   [`is_valid_collection_id`](crate::is_valid_collection_id), or is the
    ///   `[core] collection-id` of the repository, and a remote name that
    ///   [`valid_remote_name`] refuses. A directory under `refs/remotes` with
    ///   no remote group in the config gives no ref. If no remote qualifies,
    ///   the call does not read `refs/remotes`.
    ///
    /// The result holds each pair of a collection id and a ref name one
    /// time. A ref under `refs/mirrors` wins over a ref of a remote with the
    /// same pair. Among remotes with the same pair, the first remote in the
    /// byte order of the names wins.
    ///
    /// The call reads the refs and the aliases by the rules of
    /// [`list_refs`](Repo::list_refs). An alias that breaks the alias rule,
    /// an alias whose target names no ref, and a ref entry that is a FIFO, a
    /// socket, or a device file are not in the result.
    ///
    /// [`list_collection_refs_in`](Repo::list_collection_refs_in) lists the
    /// refs of one collection that a selector selects. It does not read
    /// `refs/remotes`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if a ref file is not UTF-8 or is larger
    ///   than 4096 bytes, or if `refs`, `refs/heads`, `refs/remotes`,
    ///   `refs/mirrors`, an entry directly under `refs/mirrors`, or the
    ///   directory `refs/remotes/R` of a remote of the result is a symlink.
    /// - [`Error::Core`] if a ref file holds no checksum.
    /// - [`Error::Io`] if a read from the file system fails.
    pub async fn list_collection_refs(&self) -> Result<Vec<CollectionRefEntry>> {
        let config = self.config();
        let own = config.collection_id();
        // The remotes whose refs the listing holds, each with its collection
        // id, sorted by name.
        let mut remotes = BTreeMap::new();
        for name in config.remotes() {
            if !valid_remote_name(name) {
                continue;
            }
            let Some(remote) = config.remote(name) else {
                continue;
            };
            // A value with a malformed escape sequence gives no row.
            if let Ok(Some(id)) = remote.collection_id()
                && ostrya_core::is_valid_collection_id(&id)
                && Some(id.as_str()) != own
            {
                remotes.insert(name.to_owned(), id);
            }
        }
        let heads = match own {
            Some(_) => self.list_refs(None).await?,
            None => Vec::new(),
        };
        let mut all = self.collection_refs_over(&heads, own).await?;
        if remotes.is_empty() {
            return Ok(all);
        }
        let repo = self.clone();
        let refs = ostrya_rt::unblock(move || collect_remote_collections(&repo, &remotes)).await?;
        // The refs of the remotes come after the mirror refs, in the byte
        // order of the remote names. The sort is stable, and `dedup_by` keeps
        // the first entry of each pair, so a mirror ref wins over a ref of a
        // remote, and the first remote by name wins over the others.
        all.extend(
            refs.into_iter()
                .map(|(remote, collection, name, commit)| CollectionRefEntry {
                    collection,
                    name,
                    commit,
                    local: false,
                    remote: Some(remote),
                }),
        );
        all.sort_by(|a, b| (&a.collection, &a.name).cmp(&(&b.collection, &b.name)));
        all.dedup_by(|a, b| a.collection == b.collection && a.name == b.name);
        Ok(all)
    }

    /// Returns the refs of the collection `collection_id` that `refs`
    /// selects, as `(name, commit)` pairs, sorted byte-wise by name, each
    /// name one time.
    ///
    /// `refs` selects a ref by its name in the collection, with the rules of
    /// [`RefSelector`]. An empty selector selects each ref of the collection.
    ///
    /// The collection id selects the directories that the call lists:
    ///
    /// - The `[core] collection-id` of the repository lists the refs of
    ///   `refs/heads/`. The call does not read `refs/mirrors/ID/`. The
    ///   summary and the ref listing apply the same rule.
    /// - Each other collection id lists the refs of `refs/mirrors/ID/` alone.
    ///   With no directory `refs/mirrors/ID/`, the result is an empty vector.
    ///
    /// The call opens `refs/`, `refs/mirrors`, and `refs/mirrors/ID` with no
    /// symlink followed. An entry `ID` that is absent or a regular file is no
    /// directory `refs/mirrors/ID/`, and so is each entry `ID` when
    /// `refs/mirrors` is absent. A symlink at `ID` fails the call. When the
    /// call opens `refs/mirrors`, a `refs/mirrors` that is a regular file
    /// gives an error. The call reads `[core] collection-id` from the config
    /// that the handle read at the open.
    ///
    /// An alias resolves by the alias rule of
    /// [`resolve_ref_tip`](Repo::resolve_ref_tip), and it names a regular
    /// file under `refs/heads/` or under `refs/mirrors/ID/` of a valid
    /// collection id other than `[core] collection-id`. The result holds the
    /// alias by its own name, with the commit of the target. An alias whose
    /// target is absent, is outside these directories, or is an alias is not
    /// in the result. The call does not open a ref entry that is a FIFO, a
    /// socket, or a device file, and such an entry is not in the result.
    ///
    /// The call does not check a name that it finds against the ref-name
    /// rule. A wildcard of `refs` selects a name that the rule refuses.
    ///
    /// # Reads
    ///
    /// The call reads only the directories that the literal leading parts of
    /// a positive pattern name, and below them only the directories that the
    /// pattern can match. It does not read a directory that a negative
    /// pattern covers: a negative pattern of literal or `*` parts and a
    /// final `**` matches each name below a directory whose path starts with
    /// these parts. It applies the negative patterns to a name before it
    /// reads the ref file. A negative pattern `**` selects no ref, and the
    /// call then opens no directory. The call opens each directory that
    /// literal leading parts name one time, also when more than one pattern
    /// starts with these parts.
    ///
    /// For each other collection id, the call opens `refs/mirrors/` and
    /// `refs/mirrors/ID/`, and below `refs/mirrors/ID/` the directories that
    /// the rules above give. It does not read the names at the top level of
    /// `refs/mirrors/`. Except to read the target of an alias, it does not
    /// open the directory of another collection, and it does not open
    /// `refs/heads/`.
    ///
    /// The call takes no lock. It does not wait for an
    /// [`UpdateGuard`](crate::UpdateGuard) or for a transaction. A ref write
    /// renames a complete file over the ref, so each ref in the result has
    /// the old commit or the new commit. Writes during the call can give a
    /// result that the store did not hold at one time.
    ///
    /// No client group applies: the `[ex-ostrya client]` groups of the
    /// config do not limit the result. The result has no size limit.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if the collection id does not pass
    ///   [`is_collection_id`](crate::is_collection_id) or is longer than 255
    ///   bytes. The error holds the collection id. The call reads no file.
    /// - [`Error::InvalidFormat`] if a selected ref file is not UTF-8 or is
    ///   larger than 4096 bytes, if `refs`, `refs/mirrors`, or
    ///   `refs/mirrors/ID` that the call opens is a symlink, or if
    ///   `refs/mirrors` is a regular file.
    /// - [`Error::Core`] if a selected ref file holds no checksum.
    /// - [`Error::Io`] if a read fails, for example if a directory that the
    ///   call reads gives no read permission.
    pub async fn list_collection_refs_in(
        &self,
        collection_id: &str,
        refs: &RefSelector,
    ) -> Result<Vec<(String, Checksum)>> {
        if !ostrya_core::is_valid_collection_id(collection_id) {
            return Err(Error::InvalidRefspec(collection_id.to_owned()));
        }
        if selects_no_name(refs) {
            return Ok(Vec::new());
        }
        let own = self.config().collection_id();
        if own == Some(collection_id) {
            let selection = self
                .select_refs(refs, None, self.implicit_reads(), None)
                .await?;
            return Ok(selection.local);
        }
        // The selector of `ID/NAME` paths. With no positive pattern, `ID/**`
        // keeps the walk inside the directory of the collection.
        let mut entries: Vec<String> = refs
            .positive()
            .iter()
            .map(|pattern| format!("{collection_id}/{}", pattern.as_str()))
            .collect();
        if entries.is_empty() {
            entries.push(format!("{collection_id}/**"));
        }
        entries.extend(
            refs.negative()
                .iter()
                .map(|pattern| format!("!{collection_id}/{}", pattern.as_str())),
        );
        let collections = RefSelector::parse(entries.iter().map(String::as_str))?;
        let repo = self.clone();
        let id = collection_id.to_owned();
        ostrya_rt::unblock(move || {
            let everyone = repo.implicit_reads();
            let Some(rules) = everyone.collection_rules(&id) else {
                return Ok(Vec::new());
            };
            // The walk opens `refs/mirrors/ID` by its name, so the call does
            // not read the names of `refs/mirrors`.
            let Some(mirrors) = open_ref_top(&repo, MIRRORS_DIR)? else {
                return Ok(Vec::new());
            };
            let mut floor = SelectionFloor::new(None);
            let mut selection = RefSelection::default();
            collect_collection_selected(
                &repo,
                &mirrors,
                &CollectionWalk::new(&collections),
                &id,
                rules,
                everyone,
                &mut floor,
                &mut selection,
            )?;
            Ok(selection.collections.remove(&id).unwrap_or_default())
        })
        .await
    }

    /// Returns the collection-qualified refs, made over a `refs/heads` listing
    /// that the caller read before, sorted by collection id and ref name. A
    /// repository with no `[core] collection-id` qualifies no local ref, and
    /// the call then ignores `heads`. The result holds each ref under
    /// `refs/mirrors`, except the refs of `refs/mirrors/skip/`. The call does
    /// not read that directory.
    pub(crate) async fn collection_refs_over(
        &self,
        heads: &[(String, Checksum)],
        skip: Option<&str>,
    ) -> Result<Vec<CollectionRefEntry>> {
        let mut all = Vec::new();
        if let Some(collection) = self.config().collection_id().map(str::to_owned) {
            for (name, commit) in heads {
                all.push(CollectionRefEntry {
                    collection: collection.clone(),
                    name: name.clone(),
                    commit: *commit,
                    local: true,
                    remote: None,
                });
            }
        }
        let repo = self.clone();
        let skip = skip.map(str::to_owned);
        let mirrors = ostrya_rt::unblock(move || {
            let refs = open_refs(&repo)?;
            collect_mirrors(
                &repo,
                refs.as_ref(),
                &|path| Some(path) == skip.as_deref(),
                &|_| true,
            )
        })
        .await?;
        for (collection, name, commit) in mirrors {
            all.push(CollectionRefEntry {
                collection,
                name,
                commit,
                local: false,
                remote: None,
            });
        }
        all.sort_by(|a, b| (&a.collection, &a.name).cmp(&(&b.collection, &b.name)));
        Ok(all)
    }

    /// Returns the refs that are aliases, sorted by the text of their name.
    ///
    /// The call reads the symlinks under `refs/heads`, `refs/remotes`, and
    /// `refs/mirrors`. [`RefAlias`] states the name and the target of each
    /// link. The text of the name is the text of [`Ref`], and the list is
    /// sorted by that text in byte order. The call does not read the
    /// directory of the `[core] collection-id` that the open of the handle
    /// read, because the ref store reads `refs/heads` for that id.
    ///
    /// The result holds an alias whose target names no ref, because the call
    /// reads the link and not the ref behind it. [`RefAlias::target`] states
    /// what its value tells about the ref behind the link. An alias whose
    /// body is not UTF-8 is not in the result.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if `refs`, `refs/heads`, `refs/remotes`,
    ///   `refs/mirrors`, or an entry directly under `refs/remotes` or
    ///   `refs/mirrors` is a symlink, or if the body of a link is larger than
    ///   the cap of a ref read.
    /// - [`Error::Io`] if a read from the file system fails, for example if
    ///   a directory under `refs/` cannot be read.
    pub async fn list_ref_aliases(&self) -> Result<Vec<RefAlias>> {
        let repo = self.clone();
        let mut aliases = ostrya_rt::unblock(move || collect_aliases(&repo)).await?;
        aliases.sort_by_cached_key(|alias| alias.name.to_string());
        Ok(aliases)
    }

    /// Checks a path below `refs/` for a component that is not a directory.
    ///
    /// `relpath` is relative to `refs/`, as a listing prefix names it. The
    /// call fails for two conditions: a component before the last one is not
    /// a directory (`ENOTDIR`), or is a symlink. Each condition ends a
    /// listing.
    ///
    /// If the path names nothing, the call returns `Ok(())`, because a prefix
    /// that matches no ref lists nothing. Each other failure of the check also
    /// returns `Ok(())`, and the prefix then filters the listing. The check
    /// follows no symlink, and does not follow the last component, so a path
    /// that names an alias is the link itself, and the call returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] with `ENOTDIR` if a component before the last one is
    ///   not a directory.
    /// - [`Error::InvalidFormat`] with the text `passes through a symlink` if
    ///   `refs` or a component before the last one is a symlink.
    pub async fn check_refs_path(&self, relpath: &str) -> Result<()> {
        let path = format!("refs/{relpath}");
        let repo = self.clone();
        ostrya_rt::unblock(move || match repo.root_dir().exists(&path) {
            Err(FsError::Invalid {
                reason: Reason::NotDirectory,
                ..
            }) => Err(Error::Io(Errno::NOTDIR.into())),
            Err(
                e @ FsError::Invalid {
                    reason: Reason::Symlink,
                    ..
                },
            ) => Err(e.into()),
            _ => Ok(()),
        })
        .await
    }

    /// Returns `true` if an entry stands at the ref path of `r`, or above it.
    ///
    /// The path is the path where [`resolve_ref_tip`](Repo::resolve_ref_tip)
    /// reads the ref. The call reads the type of the entry with one `lstat`
    /// relative to the repository root, and follows no symlink at any
    /// component of the path. It reads no content, and does not check the
    /// alias rule.
    ///
    /// The result is `true` for a ref file, an alias (also a dangling one), a
    /// directory, or a special file at the path. It is also `true` for a file,
    /// a special file, or a symlink at a component above the path, for
    /// example a symlink at `refs/heads`. The result is `false` if a
    /// component of the path is absent.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if the ref fails [`Ref::validate`]. The
    ///   call reads no file.
    /// - [`Error::Io`] if the `lstat` fails for a reason other than an absent
    ///   entry, for example on a directory that the process cannot search.
    pub async fn ref_path_has_entry(&self, r: &Ref) -> Result<bool> {
        let relpath = ref_relpath(self.config().collection_id(), r)?;
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            Ok(!matches!(
                lstat_ref_state(repo.root_dir(), &relpath)?,
                Some(RefFileState::Absent)
            ))
        })
        .await
    }

    /// Writes one ref outside a transaction.
    ///
    /// If `checksum` is `None`, the call removes the ref file. The removal of
    /// an absent ref file is not an error. The call reads `[core] fsync` from
    /// the config. A transaction writes its queued refs in the same way, under
    /// its own fsync policy (see [`Transaction::commit`]). To remove a set of
    /// refs under one check, use
    /// [`remove_refs_immediate`](Repo::remove_refs_immediate).
    ///
    /// # Ref files
    ///
    /// A ref is a file under `refs/`. It holds a 64-character hex checksum and
    /// a newline, 65 bytes in all. The file mode is `0644`, independent of the
    /// umask. The [`Ref`] gives the path:
    ///
    /// - The local ref `name` is at `refs/heads/name`.
    /// - The remote ref `remote:name` is at `refs/remotes/remote/name`.
    /// - The collection ref `@collection:name` is at
    ///   `refs/mirrors/collection/name`. A collection ref of the `[core]
    ///   collection-id` of the repository is at `refs/heads/name`, so
    ///   `@collection:name` and `name` name the same file there. The call
    ///   reads `[core] collection-id` from the config that the handle read at
    ///   the open.
    ///
    /// A ref can also be an alias: a relative symlink to the file of another
    /// ref. A read resolves the link by the alias rule of
    /// [`resolve_ref_tip`](Repo::resolve_ref_tip), and reads the checksum of
    /// the target ref. The call does not write or remove an alias. To remove
    /// an alias, use
    /// [`remove_ref_alias_immediate`](Repo::remove_ref_alias_immediate).
    /// [`Ref::validate`] checks each component of the ref against the
    /// ref-name rule, so a ref path stays inside `refs/`. If a directory of
    /// `refs/mirrors/` has a name that fails the rule, a ref under it cannot
    /// be written or removed through this call. Remove such a ref by hand.
    ///
    /// A read, a write, and a removal follow no symlink above the ref, from
    /// the repository root down. Each open of a path in the repository is one
    /// `openat2` with `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`. The open has
    /// no fallback. On a kernel without `openat2`, the call fails with
    /// [`Error::Io`]. Under the update lock, before the write, the call reads
    /// the type of the entry at the path of the ref. The write itself opens
    /// the directory of the ref with no symlink followed, and the rename of
    /// the temp file is relative to that directory. So a symlink that a
    /// writer puts above the ref after the check fails the write, and the
    /// write never goes through it.
    ///
    /// The call creates the missing parent directories of a name with `/` in
    /// it. It requests mode `0777` for them, which the umask reduces. In a
    /// `bare-user-shared` repository, each directory that the call creates
    /// gets mode `02770`. A file or a symlink at a component of the path
    /// fails the write. If `refs/` is absent, the call makes it with the
    /// directories `heads`, `remotes`, and `mirrors`, as the create of a
    /// repository makes them.
    ///
    /// # Durability
    ///
    /// The write is atomic. The call writes the content to a new temp file
    /// `.ostrya-tmp-<pid>-XXXXXX` in the `tmp/` directory of the repository.
    /// Then it renames the temp file over the ref file. No temp entry is under
    /// `refs/`, so a listing never reads one.
    ///
    /// If `tmp/` is on a different file system, the rename fails with
    /// `EXDEV`, and the call removes the temp file.
    ///
    /// If `[core] fsync` is on:
    ///
    /// - The call sets the mode of the temp file, and then runs `fsync` on it
    ///   before the rename.
    /// - When the call creates a parent directory, it runs `fsync` at once on
    ///   the directory that holds the new directory. It creates the
    ///   directories from the top down, so the full path of the name is
    ///   durable, and not only the last entry.
    /// - After the rename, the call runs `fsync` on the directory that holds
    ///   the ref, so the name is durable together with the content.
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
    /// - [`Error::InvalidRefspec`] if the ref fails [`Ref::validate`]. The
    ///   error holds the text of the ref, and the call writes nothing.
    /// - [`Error::RefNotWritable`] if the path of the ref names an alias. The
    ///   call writes nothing, and the alias stays. The call gives the same
    ///   error, with the reason `passes through an alias`, if `refs` or a
    ///   component above the ref is a symlink, also a dangling one. It then
    ///   writes nothing through the symlink.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or `[core]
    ///   lock-timeout-secs` does not parse.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is below `-1`,
    ///   if a file is at a directory component of the path, if a symlink is
    ///   at `tmp`, or if a writer puts a symlink at a component of the path
    ///   after the check of the path. The call then writes nothing through
    ///   the symlink.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn set_ref_immediate(&self, r: &Ref, checksum: Option<&Checksum>) -> Result<()> {
        let own = self.config().collection_id();
        let relpath = ref_relpath(own, r)?;
        let name = r.clone().canonical(own).to_string();
        self.write_ref_relpath(name, relpath, checksum).await
    }

    /// Removes a set of refs, outside a transaction.
    ///
    /// The ref gives the path, as
    /// [`set_ref_immediate`](Repo::set_ref_immediate) states. The removal of
    /// an absent ref is not an error, and a ref given more than one time is
    /// removed one time. The parent directories of a ref stay.
    ///
    /// The call checks all refs before it removes the first ref. The check is
    /// the check that [`Transaction::commit`] applies to the refs of
    /// [`Transaction::set_ref`]. Then the call removes the refs in the given
    /// order. The call uses no staging directory and does not use `tmp/`. If
    /// an unlink fails, the refs removed before it stay removed.
    ///
    /// If `[core] fsync` is on, the call runs `fsync` one time on each
    /// directory that lost a name, after the last removal, deepest first. A
    /// removal that fails still syncs the directories that the removals
    /// before it changed.
    ///
    /// The locks are those of [`set_ref_immediate`](Repo::set_ref_immediate).
    /// The call holds the update lock from the check to the last sync.
    ///
    /// If `refs` is empty, the call does no I/O. It reads no config key,
    /// takes no lock, and returns `Ok`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if a ref fails [`Ref::validate`]. The
    ///   error holds the text of the first ref that fails, and the call
    ///   removes nothing.
    /// - [`Error::RefNotWritable`] if the path of a ref names an alias, names
    ///   a directory, passes through a file or an alias, or names a special
    ///   file. The error names the first such ref, and the call removes
    ///   nothing.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or `[core]
    ///   lock-timeout-secs` does not parse.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is below `-1`.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn remove_refs_immediate(&self, refs: &[Ref]) -> Result<()> {
        if refs.is_empty() {
            return Ok(());
        }
        let own = self.config().collection_id();
        let resolved = refs
            .iter()
            .map(|r| {
                Ok(ResolvedRef {
                    relpath: ref_relpath(own, r)?,
                    name: r.clone().canonical(own),
                    checksum: None,
                    expected: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let fsync = self.config().fsync()?;
        self.write_locked(move |repo| {
            let root = repo.root_dir();
            check_resolved_refs_blocking(root, &resolved)?;
            let mut dirs = Vec::new();
            let removed = resolved
                .iter()
                .try_for_each(|r| remove_ref_blocking(root, &r.relpath, fsync, &mut dirs));
            removed.and(sync_ref_dirs(root, dirs))
        })
        .await
    }

    async fn write_ref_relpath(
        &self,
        name: String,
        relpath: String,
        checksum: Option<&Checksum>,
    ) -> Result<()> {
        let fsync = self.config().fsync()?;
        let checksum = checksum.copied();
        self.write_locked(move |repo| {
            write_ref_blocking(repo.root_dir(), &name, &relpath, checksum, fsync)
        })
        .await
    }

    /// Writes one ref as an alias of another ref, outside a transaction.
    ///
    /// The alias is a relative symlink from the file of `alias` to the file
    /// of `target`. It replaces the ref or the alias that `alias` named
    /// before. The call checks both refs. The call does not require either
    /// ref to exist, because the link records a name and not a checksum.
    ///
    /// Each ref gives its path as
    /// [`set_ref_immediate`](Repo::set_ref_immediate) states: a local ref is
    /// under `refs/heads`, a remote ref under `refs/remotes/REMOTE/`, and a
    /// collection ref under `refs/mirrors/ID/`. A collection ref of the
    /// `[core] collection-id` is the local ref of the same name, under
    /// `refs/heads`. The id is the one that the open of the handle read. The
    /// alias and its target can be in different directories, for example a
    /// collection alias of a local ref. An error names a ref by the text of
    /// its canonical form, as [`Ref::canonical`] gives it: `@OWN:NAME` is
    /// named `NAME`.
    ///
    /// An alias names a ref file. Under the update lock, the call reads the
    /// type of the entry at the path of `target` with no symlink followed,
    /// and refuses an alias whose target is an alias. An absent target, and a
    /// target whose path passes through a ref file, are allowed. The call
    /// checks the new alias alone: an alias write over a ref file that other
    /// aliases name makes these aliases name an alias, and they then name no
    /// ref.
    ///
    /// The write is atomic: the call creates the link under a temp name
    /// `.ostrya-tmp-<pid>-XXXXXX` in `tmp/` and renames it over the ref path.
    /// The rules of the path and of the parent directories are those of
    /// [`set_ref_immediate`](Repo::set_ref_immediate). If `[core] fsync` is
    /// on, the call runs `fsync` on the directory that holds each parent
    /// directory that it creates, at once, and on the directory that holds the
    /// link. The locks are those of
    /// [`set_ref_immediate`](Repo::set_ref_immediate).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if `alias` or `target` fails
    ///   [`Ref::validate`]. The call checks `alias` first, and the error
    ///   holds the text of the ref that fails.
    /// - [`Error::RefNotWritable`] if `refs` or a component above the path
    ///   of `alias` is a symlink, also a dangling one. The reason is
    ///   `passes through an alias`, and the call writes nothing.
    /// - [`Error::RefNotWritable`] for `alias` if `target` names an alias,
    ///   or names the path of `alias` itself. The reason is `targets an
    ///   alias`, and the call writes nothing. If `refs` or a component above
    ///   the path of `target` is a symlink, the reason is `passes through an
    ///   alias`.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or `[core]
    ///   lock-timeout-secs` does not parse.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is below `-1`,
    ///   if a file is at a directory component of the path, if a symlink is
    ///   at `tmp`, or if a writer puts a symlink at a component of the path
    ///   after the check of the path. The call then writes nothing through
    ///   the symlink.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn set_ref_alias_immediate(&self, alias: &Ref, target: &Ref) -> Result<()> {
        let fsync = self.config().fsync()?;
        let own = self.config().collection_id();
        let relpath = ref_relpath(own, alias)?;
        let target = ref_relpath(own, target)?;
        let name = alias.clone().canonical(own).to_string();
        self.write_locked(move |repo| {
            write_alias_blocking(repo.root_dir(), &name, &relpath, &target, fsync)
        })
        .await
    }

    /// Removes the alias `alias`, outside a transaction.
    ///
    /// The call unlinks the symlink at the path of `alias`. The ref gives the
    /// path as [`set_ref_alias_immediate`](Repo::set_ref_alias_immediate)
    /// states, so the call removes an alias under `refs/heads`,
    /// `refs/remotes/REMOTE/`, or `refs/mirrors/ID/`. The ref that the alias
    /// names stays. The removal of an absent path is not an error. If `[core]
    /// fsync` is on, the call runs `fsync` on the directory that held the
    /// link. The locks are those of
    /// [`set_ref_immediate`](Repo::set_ref_immediate).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] if `alias` fails [`Ref::validate`]. The
    ///   error holds the text of the ref. So an alias that
    ///   [`list_ref_aliases`](Repo::list_ref_aliases) gives with a name that
    ///   fails the check cannot be removed through this call. Remove such an
    ///   alias by hand.
    /// - [`Error::RefNotWritable`] if the path of `alias` names a ref file,
    ///   names a directory, passes through a file or an alias, or names a
    ///   special file. The error names the ref by the text of its canonical
    ///   form, and the call removes nothing.
    /// - [`Error::Core`] if `[core] fsync`, `[core] locking`, or `[core]
    ///   lock-timeout-secs` does not parse.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is below `-1`.
    /// - [`Error::LockTimeout`] if the wait for a lock passes `[core]
    ///   lock-timeout-secs`.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn remove_ref_alias_immediate(&self, alias: &Ref) -> Result<()> {
        let fsync = self.config().fsync()?;
        let own = self.config().collection_id();
        let relpath = ref_relpath(own, alias)?;
        let name = alias.clone().canonical(own).to_string();
        self.write_locked(move |repo| {
            let root = repo.root_dir();
            let mut dirs = Vec::new();
            let removed = remove_alias_blocking(root, &name, &relpath, fsync, &mut dirs);
            removed.and(sync_ref_dirs(root, dirs))
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
///
/// A fanout directory that the scan reads and that is a symlink or is not a
/// directory fails the scan.
fn match_abbreviated(objects: &RepoDir, prefix: &str) -> Result<AbbrevMatch> {
    let mut found: Option<Checksum> = None;
    if prefix.len() >= 2 {
        let (fanout, within) = prefix.split_at(2);
        if scan_fanout(objects, fanout, within, &mut found)? {
            return Ok(AbbrevMatch::Ambiguous);
        }
    } else {
        for entry in objects.list()? {
            // The name of an object fanout directory is two hex characters.
            // Each other entry under `objects/` is not a loose-object fanout.
            let Ok(fanout) = std::str::from_utf8(&entry.name) else {
                continue;
            };
            if fanout.len() != 2 || !fanout.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            if !fanout.starts_with(prefix) {
                continue;
            }
            if scan_fanout(objects, fanout, "", &mut found)? {
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
    objects: &RepoDir,
    fanout: &str,
    within: &str,
    found: &mut Option<Checksum>,
) -> Result<bool> {
    let Some(dir) = objects.open_dir(fanout).optional()? else {
        return Ok(false);
    };
    for entry in dir.list()? {
        let Some(checksum) = std::str::from_utf8(&entry.name)
            .ok()
            .and_then(|entry| matching_commit(fanout, entry, within))
        else {
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

/// Collects each ref under `refs/heads` and its subdirectories whose name
/// `keep` selects. `refs` is the handle of `refs/` that [`open_refs`] gives.
/// The walk applies `keep` to the name before it reads the ref file.
fn collect_heads(
    repo: &Repo,
    refs: Option<&RepoDir>,
    keep: &dyn Fn(&str) -> bool,
) -> Result<Vec<(String, Checksum)>> {
    let Some(heads) = open_top_in(refs, HEADS_DIR)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    walk_ref_dir(&heads, "", &mut |entry| {
        if !keep(entry.path) {
            return Ok(());
        }
        if let Some((bytes, _)) = read_listed_ref(repo.root_dir(), HEADS_DIR, &entry, None)? {
            out.push((entry.path.to_owned(), parse_ref_content(&bytes)?));
        }
        Ok(())
    })?;
    Ok(out)
}

/// The directory of the local refs.
pub(crate) const HEADS_DIR: &str = "refs/heads";

/// The directory of the mirror refs, one subdirectory for each collection id.
pub(crate) const MIRRORS_DIR: &str = "refs/mirrors";

/// The directory of the remote refs, one subdirectory for each remote.
pub(crate) const REMOTES_DIR: &str = "refs/remotes";

/// The refs of one ref listing, which [`Repo::select_refs`] returns.
#[derive(Default)]
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
    /// The target path of each alias of `local`, by name.
    pub(crate) local_aliases: HashMap<String, String>,
    /// The target path of each alias of `collections`, by collection id and
    /// name.
    pub(crate) collection_aliases: BTreeMap<String, HashMap<String, String>>,
}

impl RefSelection {
    /// Returns the refs of the selection that `access` reads.
    ///
    /// The selection comes from [`Repo::select_refs`] with an access that
    /// reads each ref that `access` reads. The result holds the refs that
    /// `select_refs` with the same selectors and `access` gives for the same
    /// state of the repository. A ref is in the result when `access` reads
    /// its name, and, for an alias, its target path. The result holds no
    /// alias target and no invalid directory.
    pub(crate) fn readable(&self, access: &ReadAccess) -> RefSelection {
        let mut out = RefSelection::default();
        if access.reads_local_refs() {
            for (name, commit) in &self.local {
                if !access.can_read(&Namespace::Local, name) {
                    continue;
                }
                if let Some(target) = self.local_aliases.get(name)
                    && !access.can_read_path(target)
                {
                    continue;
                }
                out.local.push((name.clone(), *commit));
            }
        }
        for (id, refs) in &self.collections {
            let Some(rules) = access.collection_rules(id) else {
                continue;
            };
            if !rules.gives_read() {
                continue;
            }
            let aliases = self.collection_aliases.get(id);
            let names: Vec<(String, Checksum)> = refs
                .iter()
                .filter(|(name, _)| {
                    crate::access::reads(rules, name)
                        && aliases
                            .and_then(|aliases| aliases.get(name))
                            .is_none_or(|target| access.can_read_path(target))
                })
                .cloned()
                .collect();
            if !names.is_empty() {
                out.collections.insert(id.clone(), names);
            }
        }
        out
    }
}

/// Returns the local refs that `selector` selects and `access` reads, sorted
/// by name, each one time: the refs of `refs/heads`. `refs` is the handle of
/// `refs/` that [`open_refs`] gives. When `access` reads no local ref, or
/// when `selector` selects no name, the call does not open `refs/heads`. The call adds each ref to `floor`, and the refs and their
/// alias targets to `selection`.
fn collect_local_selected(
    repo: &Repo,
    refs: Option<&RepoDir>,
    selector: &RefSelector,
    access: &ReadAccess,
    floor: &mut SelectionFloor,
    selection: &mut RefSelection,
) -> Result<()> {
    if selects_no_name(selector) || !access.reads_local_refs() {
        return Ok(());
    }
    let mut local = BTreeMap::new();
    if let Some(heads) = open_top_in(refs, HEADS_DIR)? {
        collect_dir_selected(
            repo, HEADS_DIR, &heads, selector, access, floor, &mut local, selection,
        )?;
    }
    selection.local = local.into_iter().collect();
    Ok(())
}

/// Adds to `out` each ref of `dir`, the directory `root` under `refs/`, that
/// `selector` selects and `access` reads in the local namespace, each one
/// time, and adds it to `floor`. A ref that no entry selects, that `access`
/// does not read, or that is in `out` already is not read, and a directory
/// that a negative pattern covers is not read. With no positive pattern, the
/// walk reads only the directories that an allow item of the local rules of
/// `access` that gives `r` can match, and no directory that a deny item of
/// these rules covers. The target path of each alias goes to
/// `selection.local_aliases`.
#[allow(clippy::too_many_arguments)]
fn collect_dir_selected(
    repo: &Repo,
    root: &str,
    dir: &RepoDir,
    selector: &RefSelector,
    access: &ReadAccess,
    floor: &mut SelectionFloor,
    out: &mut BTreeMap<String, Checksum>,
    selection: &mut RefSelection,
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
        if let Some((bytes, target)) = read_listed_ref(repo.root_dir(), root, &entry, Some(access))?
        {
            let commit = parse_ref_content(&bytes)?;
            floor.add_ref(entry.path)?;
            out.insert(entry.path.to_owned(), commit);
            if let Some(target) = target {
                selection
                    .local_aliases
                    .insert(entry.path.to_owned(), target);
            }
        }
        Ok(())
    };
    match access.local_rules() {
        Some(rules) if selector.positive().is_empty() => {
            let covers = negative_covers(selector);
            walk_readable(dir, rules, &|dir| dir_is_covered(&covers, dir), &mut take)
        }
        _ => walk_selected(dir, selector, &mut take),
    }
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
/// level that is not a directory or a symlink are skipped. A symlink at the
/// top level fails the call with [`Error::InvalidFormat`] and the text
/// `passes through a symlink`.
fn collect_collections_selected(
    repo: &Repo,
    mirrors: &RepoDir,
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
    for entry in mirrors.list()? {
        let Ok(name) = String::from_utf8(entry.name) else {
            continue;
        };
        refuse_top_symlink(MIRRORS_DIR, &name, entry.file_type)?;
        if Some(name.as_str()) == own || entry.file_type != FileType::Directory {
            continue;
        }
        if !ostrya_core::is_valid_collection_id(&name) {
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
    for (id, rules) in &readable {
        collect_collection_selected(repo, mirrors, &walk, id, rules, access, floor, selection)?;
    }
    Ok(())
}

/// Adds to `selection` the refs of the collection `id` that `walk` selects by
/// `ID/NAME` and that `rules`, the rules of the collection, read, with the
/// target paths of their aliases. The call walks the directory `id` of
/// `mirrors`, the open `refs/mirrors`, with [`CollectionWalk::walk`]. Except
/// to read the target of an alias, it opens no other directory of `mirrors`.
/// A symlink at `id` fails the call.
/// It applies the negative patterns of the walk and `rules` to a name before
/// it reads the ref file. An alias resolves only when `access` reads its
/// target path. The call adds each ref to `floor`, and the collection when it
/// gives its first ref. A collection with no ref is not in `selection`.
#[allow(clippy::too_many_arguments)]
fn collect_collection_selected(
    repo: &Repo,
    mirrors: &RepoDir,
    walk: &CollectionWalk<'_>,
    id: &str,
    rules: &AccessRules,
    access: &ReadAccess,
    floor: &mut SelectionFloor,
    selection: &mut RefSelection,
) -> Result<()> {
    let mut names: BTreeMap<String, Checksum> = BTreeMap::new();
    let mut aliases = HashMap::new();
    let mut take = |entry: RefEntry<'_>| -> Result<()> {
        // The walk gives each entry of the directory of `id` as `id/NAME`.
        let Some((_, name)) = entry.path.split_once('/') else {
            return Ok(());
        };
        if names.contains_key(name)
            || walk
                .selector
                .negative()
                .iter()
                .any(|p| p.matches(entry.path))
            || !crate::access::reads(rules, name)
        {
            return Ok(());
        }
        if let Some((bytes, target)) =
            read_listed_ref(repo.root_dir(), MIRRORS_DIR, &entry, Some(access))?
        {
            let commit = parse_ref_content(&bytes)?;
            if names.is_empty() {
                floor.add_collection(id)?;
            }
            floor.add_ref(name)?;
            names.insert(name.to_owned(), commit);
            if let Some(target) = target {
                aliases.insert(name.to_owned(), target);
            }
        }
        Ok(())
    };
    walk.walk(mirrors, id, rules, &mut take)?;
    if !aliases.is_empty() {
        selection.collection_aliases.insert(id.to_owned(), aliases);
    }
    if !names.is_empty() {
        selection
            .collections
            .insert(id.to_owned(), names.into_iter().collect());
    }
    Ok(())
}

/// Walks the ref tree of `dir` for `selector`, and gives `take` each entry
/// whose path a positive pattern can match. With no positive pattern, `take`
/// gets each entry. The walk does not read a directory that a negative
/// pattern covers. `take` applies the negative patterns.
fn walk_selected(
    dir: &RepoDir,
    selector: &RefSelector,
    take: &mut dyn FnMut(RefEntry<'_>) -> Result<()>,
) -> Result<()> {
    let covers = negative_covers(selector);
    let skip = |dir: &str| dir_is_covered(&covers, dir);
    if selector.positive().is_empty() {
        walk_ref_dir_skipping(dir, "", &skip, &mut &mut *take)?;
    } else {
        let split: Vec<(&RefPattern, Vec<&str>)> = uncovered_patterns(selector.positive())
            .into_iter()
            .map(|pattern| (pattern, pattern.as_str().split('/').collect()))
            .collect();
        let patterns: Vec<(&RefPattern, &[&str])> = split
            .iter()
            .map(|(pattern, parts)| (*pattern, parts.as_slice()))
            .collect();
        walk_ref_patterns(dir, "", &patterns, &skip, take)?;
    }
    Ok(())
}

/// Walks the ref tree of `dir` for the allow items of `rules` that give `r`,
/// as [`walk_selected`] walks for positive patterns, and gives `take` each
/// entry whose path such an item can match. The walk does not read a
/// directory that a deny item of `rules` covers, or for whose path `skip`
/// returns `true`. `take` applies the rules.
fn walk_readable(
    dir: &RepoDir,
    rules: &AccessRules,
    skip: &dyn Fn(&str) -> bool,
    take: &mut dyn FnMut(RefEntry<'_>) -> Result<()>,
) -> Result<()> {
    let positive: Vec<RefPattern> = rules
        .allow
        .iter()
        .filter(|item| item.gives_read())
        .map(|item| item.pattern.clone())
        .collect();
    let covers: Vec<Vec<&str>> = rules
        .deny
        .iter()
        .filter_map(|pattern| covering_lead(pattern.as_str()))
        .collect();
    let skip = |dir: &str| skip(dir) || dir_is_covered(&covers, dir);
    for pattern in uncovered_patterns(&positive) {
        let parts: Vec<&str> = pattern.as_str().split('/').collect();
        walk_ref_pattern(dir, "", &parts, pattern, &skip, take)?;
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
    /// `id/NAME`. The walk does not read the top level of `mirrors`. With no
    /// positive pattern, it walks as [`walk_readable`] walks for `rules`, the
    /// rules of the collection. An absent `id` and a file at `id` give no
    /// entry, and a symlink at `id` fails the walk.
    fn walk(
        &self,
        mirrors: &RepoDir,
        id: &str,
        rules: &AccessRules,
        take: &mut dyn FnMut(RefEntry<'_>) -> Result<()>,
    ) -> Result<()> {
        let skip = |dir: &str| dir_is_covered(&self.covers, dir);
        let Some(sub) = mirrors.open_dir(id).optional_dir()? else {
            return Ok(());
        };
        if self.selector.positive().is_empty() {
            let skip = |dir: &str| skip(&format!("{id}/{dir}"));
            return walk_readable(&sub, rules, &skip, &mut |entry| {
                let path = format!("{id}/{}", entry.path);
                take(RefEntry {
                    path: &path,
                    ..entry
                })
            });
        }
        // The patterns whose first part names `id`, with the parts below it.
        let mut below: Vec<(&RefPattern, &[&str])> = Vec::new();
        for (pattern, parts) in &self.patterns {
            if !first_part_reaches(parts, id) {
                continue;
            }
            match parts.split_first() {
                Some((&"**", _)) => {
                    walk_ref_dir_skipping(&sub, id, &skip, &mut |entry| {
                        if pattern.matches(entry.path) {
                            take(entry)
                        } else {
                            Ok(())
                        }
                    })?;
                }
                Some((_, rest)) => below.push((*pattern, rest)),
                None => {}
            }
        }
        walk_ref_patterns(&sub, id, &below, &skip, take)
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

/// Returns `true` if a negative pattern of `selector` is `**`. That pattern
/// matches each name, so `selector` selects no name.
fn selects_no_name(selector: &RefSelector) -> bool {
    selector.negative().iter().any(|p| p.as_str() == "**")
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

/// Reads the ref of the entry `entry` of a ref-tree walk of the directory
/// `top` under `refs/`, or returns `None`. `root` is the handle of the
/// repository root.
///
/// The result holds the bytes of the ref file, and the target path of an
/// alias. The call does not open an entry that is not a regular file or a
/// symlink, so its open never waits on a FIFO. It reads a regular file with
/// [`read_ref_entry`], which follows no symlink. An entry that is removed,
/// or that is no regular file at the open, gives `None`.
///
/// A symlink entry is an alias. Its body resolves against the directory of
/// the entry under `top`, with [`resolve_alias`], and the call reads the
/// target with [`read_alias_target`]. With `access`, the alias resolves
/// only when `access` reads the target path. An alias that breaks the alias
/// rule, and an alias whose target names no ref, give `None`.
///
/// A ref file or an alias target larger than [`REF_READ_CAP`] fails the call
/// with [`Error::InvalidFormat`].
pub(crate) fn read_listed_ref(
    root: &RepoDir,
    top: &str,
    entry: &RefEntry<'_>,
    access: Option<&ReadAccess>,
) -> Result<Option<(Vec<u8>, Option<String>)>> {
    if !entry.can_hold_ref() {
        return Ok(None);
    }
    let symlink = entry.file_type == FileType::Symlink;
    let body = match read_ref_entry(entry.dir, entry.name, symlink) {
        Ok(RefEntryRead::File(bytes)) => return Ok(Some((bytes, None))),
        Ok(RefEntryRead::Alias(body)) => body,
        // The entry is gone, or it changed into an entry that holds no ref.
        Err(
            FsError::Absent { .. }
            | FsError::Invalid {
                reason: Reason::NotRegular(_) | Reason::NotDirectory,
                ..
            },
        ) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let link_dir = match entry.path.rsplit_once('/') {
        Some((dir, _)) => format!("{top}/{dir}"),
        None => top.to_owned(),
    };
    let Some(target) = resolve_alias(&link_dir, &body) else {
        return Ok(None);
    };
    if access.is_some_and(|access| !access.can_read_path(&target)) {
        return Ok(None);
    }
    match read_alias_target(root, &target)? {
        AliasTarget::Ref(bytes) => Ok(Some((bytes, Some(target)))),
        AliasTarget::Absent | AliasTarget::Broken(_) => Ok(None),
    }
}

/// Collects each ref under `refs/remotes`, named by its `remote:name`
/// refspec. The first path component is the remote, and the rest is the ref
/// name. A symlink directly under `refs/remotes` fails the walk, as
/// [`refuse_top_symlink`] states.
fn collect_remotes(repo: &Repo) -> Result<Vec<(String, Checksum)>> {
    let Some(remotes) = open_ref_top(repo, REMOTES_DIR)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    walk_ref_dir(&remotes, "", &mut |entry| {
        refuse_top_symlink(REMOTES_DIR, entry.path, entry.file_type)?;
        let Some((bytes, _)) = read_listed_ref(repo.root_dir(), REMOTES_DIR, &entry, None)? else {
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

/// Collects each ref under `refs/remotes/R/` of each remote R of `remotes`,
/// as `(remote, collection_id, ref_name, commit)` tuples. `remotes` maps a
/// remote name to its collection id. The refs come in the order of the remotes in
/// the map. A directory `R` that is absent or a regular file gives no ref.
/// A symlink at `R` fails the call.
fn collect_remote_collections(
    repo: &Repo,
    remotes: &BTreeMap<String, String>,
) -> Result<Vec<(String, String, String, Checksum)>> {
    let Some(dir) = open_ref_top(repo, REMOTES_DIR)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (remote, collection) in remotes {
        let Some(sub) = dir.open_dir(remote).optional_dir()? else {
            continue;
        };
        let top = format!("{REMOTES_DIR}/{remote}");
        walk_ref_dir(&sub, "", &mut |entry| {
            if let Some((bytes, _)) = read_listed_ref(repo.root_dir(), &top, &entry, None)? {
                let checksum = parse_ref_content(&bytes)?;
                out.push((
                    remote.clone(),
                    collection.clone(),
                    entry.path.to_owned(),
                    checksum,
                ));
            }
            Ok(())
        })?;
    }
    Ok(out)
}

/// Collects the aliases under `refs/heads`, `refs/remotes`, and
/// `refs/mirrors`. Each alias gets the name that the listing of its
/// directory gives a ref, and the target that [`listed_alias_target`] reads
/// from its body. The walk of `refs/mirrors` does not read the directory of
/// the `[core] collection-id`. A symlink directly under `refs/remotes` or
/// `refs/mirrors` fails the call, as [`refuse_top_symlink`] states.
fn collect_aliases(repo: &Repo) -> Result<Vec<RefAlias>> {
    let own = repo.config().collection_id();
    let mut out = Vec::new();
    let refs = open_refs(repo)?;
    // Gives the alias of one entry under `top`, or `None` for an entry that
    // is not an alias.
    let alias = |top: &str, entry: &RefEntry<'_>, name: Ref| -> Result<Option<RefAlias>> {
        let Some(body) = read_alias_body(entry)? else {
            return Ok(None);
        };
        let link_dir = match entry.path.rsplit_once('/') {
            Some((dir, _)) => format!("{top}/{dir}"),
            None => top.to_owned(),
        };
        let target = resolve_alias(&link_dir, body.as_bytes())
            .and_then(|path| listed_alias_target(own, &path));
        Ok(Some(RefAlias { name, target, body }))
    };
    if let Some(heads) = open_top_in(refs.as_ref(), HEADS_DIR)? {
        walk_ref_dir(&heads, "", &mut |entry| {
            if entry.file_type != FileType::Symlink {
                return Ok(());
            }
            let name = Ref::local(entry.path);
            out.extend(alias(HEADS_DIR, &entry, name)?);
            Ok(())
        })?;
    }
    if let Some(remotes) = open_top_in(refs.as_ref(), REMOTES_DIR)? {
        walk_ref_dir(&remotes, "", &mut |entry| {
            refuse_top_symlink(REMOTES_DIR, entry.path, entry.file_type)?;
            if entry.file_type != FileType::Symlink {
                return Ok(());
            }
            if let Some((remote, ref_name)) = entry.path.split_once('/') {
                let name = Ref::remote(remote, ref_name);
                out.extend(alias(REMOTES_DIR, &entry, name)?);
            }
            Ok(())
        })?;
    }
    if let Some(mirrors) = open_top_in(refs.as_ref(), MIRRORS_DIR)? {
        let skip = |path: &str| !path.contains('/') && Some(path) == own;
        walk_ref_dir_skipping(&mirrors, "", &skip, &mut |entry| {
            refuse_top_symlink(MIRRORS_DIR, entry.path, entry.file_type)?;
            if entry.file_type != FileType::Symlink {
                return Ok(());
            }
            // An entry directly under refs/mirrors names no collection, as
            // in collect_mirrors.
            if let Some((id, ref_name)) = entry.path.split_once('/') {
                let name = Ref::collection(id, ref_name);
                out.extend(alias(MIRRORS_DIR, &entry, name)?);
            }
            Ok(())
        })?;
    }
    Ok(out)
}

/// Maps the path `path` below the repository root, which [`resolve_alias`]
/// gives for the body of an alias, to the ref that the ref store keeps at
/// it, in a repository whose `[core] collection-id` is `own`.
///
/// `refs/heads/NAME` gives a local ref, `refs/remotes/R/NAME` a remote ref,
/// and `refs/mirrors/ID/NAME` a collection ref. Each other path, a path
/// under the directory of `own` under `refs/mirrors`, and a ref that fails
/// [`Ref::validate`] give `None`.
fn listed_alias_target(own: Option<&str>, path: &str) -> Option<Ref> {
    let below = path.strip_prefix("refs/")?;
    let r = if let Some(name) = below.strip_prefix("heads/") {
        Ref::local(name)
    } else if let Some(rest) = below.strip_prefix("remotes/") {
        let (remote, name) = rest.split_once('/')?;
        Ref::remote(remote, name)
    } else {
        let rest = below.strip_prefix("mirrors/")?;
        let (id, name) = rest.split_once('/')?;
        if Some(id) == own {
            return None;
        }
        Ref::collection(id, name)
    };
    r.validate().is_ok().then_some(r)
}

/// Opens the directory `top` under the repository root, for example
/// `refs/heads`, with no symlink followed. `top` is a directory directly
/// under `refs/`. Returns `None` if `refs/` or `top` is absent.
///
/// A symlink at `refs` or at `top` fails with [`Error::InvalidFormat`] and
/// the text `passes through a symlink`. A file there fails with
/// [`Error::InvalidFormat`] and the text `is not a directory`.
pub(crate) fn open_ref_top(repo: &Repo, top: &str) -> Result<Option<RepoDir>> {
    open_top_in(open_refs(repo)?.as_ref(), top)
}

/// Opens `refs/` under the repository root with no symlink followed, for a
/// listing that reads more than one directory under it. Returns `None` if
/// `refs/` is absent. The errors are those of [`open_ref_top`].
pub(crate) fn open_refs(repo: &Repo) -> Result<Option<RepoDir>> {
    Ok(repo.root_dir().open_layout(RepoLayout::Refs).optional()?)
}

/// Opens the directory `top`, for example `refs/heads`, in `refs`, the
/// handle that [`open_refs`] gives, as [`open_ref_top`] opens it. Returns
/// `None` if `refs` is `None` or `top` is absent.
pub(crate) fn open_top_in(refs: Option<&RepoDir>, top: &str) -> Result<Option<RepoDir>> {
    let Some(refs) = refs else {
        return Ok(None);
    };
    let name = top.strip_prefix("refs/").unwrap_or(top);
    Ok(refs.open_dir(name).optional()?)
}

/// Fails with [`Error::InvalidFormat`] and the text `passes through a
/// symlink` if the entry at `path`, relative to the directory `top`, is a
/// symlink directly under `top`. `file_type` is the type of the entry, read
/// with no symlink followed. `top` is `refs/remotes` or `refs/mirrors`, where
/// such an entry is a symlinked `refs/remotes/R` or `refs/mirrors/ID`. The
/// walks and the listings of these directories call it for each entry before
/// they read the entry, so a listing below such a symlink fails.
pub(crate) fn refuse_top_symlink(top: &str, path: &str, file_type: FileType) -> Result<()> {
    if file_type == FileType::Symlink && !path.contains('/') {
        return Err(FsError::Invalid {
            path: format!("{top}/{path}"),
            reason: Reason::Symlink,
        }
        .into());
    }
    Ok(())
}

/// Collects each ref under `refs/mirrors`, split into its collection id (the
/// first path component) and its ref name (the rest of the path). `refs` is
/// the handle of `refs/` that [`open_refs`] gives. The walk does not read a
/// directory whose path below `refs/mirrors` `skip` selects, and it does not
/// read an entry whose path `keep` drops. A symlink directly under
/// `refs/mirrors` fails the walk, as [`refuse_top_symlink`] states.
fn collect_mirrors(
    repo: &Repo,
    refs: Option<&RepoDir>,
    skip: &dyn Fn(&str) -> bool,
    keep: &dyn Fn(&str) -> bool,
) -> Result<Vec<(String, String, Checksum)>> {
    let Some(mirrors) = open_top_in(refs, MIRRORS_DIR)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    walk_ref_dir_skipping(&mirrors, "", skip, &mut |entry| {
        refuse_top_symlink(MIRRORS_DIR, entry.path, entry.file_type)?;
        if !keep(entry.path) {
            return Ok(());
        }
        let Some((bytes, _)) = read_listed_ref(repo.root_dir(), MIRRORS_DIR, &entry, None)? else {
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
    pub(crate) dir: &'a RepoDir,
    /// The name of the entry in that directory.
    pub(crate) name: &'a str,
    /// The path from the root of the walk to the entry.
    pub(crate) path: &'a str,
    /// The type of the entry, read with no symlink followed.
    pub(crate) file_type: FileType,
}

impl RefEntry<'_> {
    /// Returns `true` if the entry is a regular file or a symlink. Only such
    /// an entry can hold a ref. A listing does not open a FIFO, a socket, or
    /// a device file.
    pub(crate) fn can_hold_ref(&self) -> bool {
        matches!(self.file_type, FileType::RegularFile | FileType::Symlink)
    }
}

/// Walks a directory under `refs/`. The walk descends into each subdirectory
/// and reports each other entry to `visit`.
///
/// The type of each entry comes from the listing of its directory, read with
/// no symlink followed, so the walk descends only into a real directory, and
/// an alias has [`FileType::Symlink`] whatever it names. The walk reports a
/// link that names a directory and does not descend into it. A caller reads
/// it as an alias. The walk skips a name that is not UTF-8, and a name
/// removed before the listing read its type.
///
/// The walk opens a subdirectory with no symlink followed. When the entry is
/// no directory at the open, the walk reads its type again and reports it
/// with that type. When the entry is removed, or is a directory again, the
/// walk skips it.
pub(crate) fn walk_ref_dir(
    dir: &RepoDir,
    prefix: &str,
    visit: &mut impl FnMut(RefEntry<'_>) -> Result<()>,
) -> Result<()> {
    walk_ref_dir_skipping(dir, prefix, &|_| false, visit)
}

/// Walks a directory as [`walk_ref_dir`] does, and does not read a
/// subdirectory when `skip` returns `true` for its path below the top.
fn walk_ref_dir_skipping(
    dir: &RepoDir,
    prefix: &str,
    skip: &dyn Fn(&str) -> bool,
    visit: &mut impl FnMut(RefEntry<'_>) -> Result<()>,
) -> Result<()> {
    for entry in dir.list()? {
        let Ok(name) = String::from_utf8(entry.name) else {
            continue;
        };
        let mut file_type = entry.file_type;
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if file_type == FileType::Directory {
            if skip(&path) {
                continue;
            }
            if let Some(sub) = dir.open_dir(&name).optional_walked_dir()? {
                walk_ref_dir_skipping(&sub, &path, skip, visit)?;
                continue;
            }
            // The entry changed after the listing. It takes the type that it
            // has now.
            match entry_type(dir, &name)? {
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

/// Walks the parts of a ref tree that the patterns `patterns` can match, as
/// [`walk_ref_pattern`] walks for each pattern. Each item holds a pattern and
/// its parts that remain below `dir`, and `prefix` is the path of `dir` below
/// the top, or empty for the top.
///
/// The patterns whose first part is the same literal share the read of the
/// type of that entry and the open of that directory. So the walk opens each
/// directory of the literal leading parts one time, whatever the number of
/// patterns below it. Each pattern whose first part is `*` or `**` goes to
/// `walk_ref_pattern`.
fn walk_ref_patterns(
    dir: &RepoDir,
    prefix: &str,
    patterns: &[(&RefPattern, &[&str])],
    skip: &dyn Fn(&str) -> bool,
    visit: &mut dyn FnMut(RefEntry<'_>) -> Result<()>,
) -> Result<()> {
    // The patterns of each literal first part, with the parts after it.
    let mut literal: BTreeMap<&str, Vec<(&RefPattern, &[&str])>> = BTreeMap::new();
    for &(pattern, parts) in patterns {
        match parts.split_first() {
            Some((first, rest)) if *first != "*" && *first != "**" => {
                literal.entry(first).or_default().push((pattern, rest));
            }
            Some(_) => walk_ref_pattern(dir, prefix, parts, pattern, skip, visit)?,
            None => {}
        }
    }
    for (name, group) in literal {
        // A missing entry, or a name longer than a file name can be, has no
        // type.
        let Some(file_type) = entry_type(dir, name)? else {
            continue;
        };
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        if file_type == FileType::Directory {
            let below: Vec<(&RefPattern, &[&str])> = group
                .into_iter()
                .filter(|(_, rest)| !rest.is_empty())
                .collect();
            // An entry that is no directory at the open matches no pattern
            // with more parts.
            if !below.is_empty()
                && !skip(&path)
                && let Some(sub) = dir.open_dir(name).optional_walked_dir()?
            {
                walk_ref_patterns(&sub, &path, &below, skip, visit)?;
            }
        } else if group.iter().any(|(_, rest)| rest.is_empty()) {
            visit(RefEntry {
                dir,
                name,
                path: &path,
                file_type,
            })?;
        }
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
/// The call reads the type of each entry with no symlink followed, and opens
/// a subdirectory with no symlink followed, as `walk_ref_dir` does, so it
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
/// - `*` reads `dir` and takes each entry with its type from the listing, as
///   a literal part does.
/// - `**` walks `dir` with `walk_ref_dir`. If no part follows it, each entry
///   goes to `visit`. Otherwise `visit` gets each entry whose whole path the
///   pattern matches.
fn walk_ref_pattern(
    dir: &RepoDir,
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
    let entries: Vec<(String, FileType)> = if *first == "*" {
        dir.list()?
            .into_iter()
            .filter_map(|entry| Some((String::from_utf8(entry.name).ok()?, entry.file_type)))
            .collect()
    } else {
        entry_type(dir, first)?
            .map(|file_type| ((*first).to_owned(), file_type))
            .into_iter()
            .collect()
    };
    for (name, file_type) in entries {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        match (file_type == FileType::Directory, rest.is_empty()) {
            (true, false) if !skip(&path) => {
                // An entry that is no directory at the open matches no
                // pattern with more parts.
                if let Some(sub) = dir.open_dir(&name).optional_walked_dir()? {
                    walk_ref_pattern(&sub, &path, rest, pattern, skip, visit)?;
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
    // The texts of the patterns before the current one.
    let mut seen: HashSet<&str> = HashSet::new();
    patterns
        .iter()
        .filter(|p| {
            let text = p.as_str();
            let repeat = !seen.insert(text);
            !repeat
                && !leads.iter().any(|(j, lead)| {
                    patterns[*j].as_str() != text
                        && text.len() > lead.len()
                        && text.starts_with(lead)
                })
        })
        .collect()
}

/// Returns the type of the entry `name` of `dir`, read with no symlink
/// followed, or `None` if the entry does not exist.
///
/// A name longer than the file system permits (`ENAMETOOLONG`) names no
/// entry, so it also gives `None`.
fn entry_type(dir: &RepoDir, name: &str) -> Result<Option<FileType>> {
    match dir.lstat(name) {
        Ok(stat) => Ok(Some(stat.file_type)),
        Err(FsError::Absent { .. }) => Ok(None),
        Err(FsError::Io(e)) if e.raw_os_error() == Some(Errno::NAMETOOLONG.raw_os_error()) => {
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// Returns the symlink target of an alias entry, as stored. Returns `None`
/// for an entry that is not a symlink and for a target that is not UTF-8.
///
/// The call reads the entry with [`read_ref_entry`]. An entry that is
/// removed after the walk, or that is no symlink at the read, gives `None`,
/// as in [`read_listed_ref`].
fn read_alias_body(entry: &RefEntry<'_>) -> Result<Option<String>> {
    if entry.file_type != FileType::Symlink {
        return Ok(None);
    }
    let body = match read_ref_entry(entry.dir, entry.name, true) {
        Ok(RefEntryRead::Alias(body)) => body,
        Ok(RefEntryRead::File(_)) => return Ok(None),
        // The entry is gone, or it changed into an entry that holds no ref.
        Err(
            FsError::Absent { .. }
            | FsError::Invalid {
                reason: Reason::NotRegular(_) | Reason::NotDirectory,
                ..
            },
        ) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(String::from_utf8(body).ok())
}

/// The content of a ref entry that [`read_ref_entry`] read.
enum RefEntryRead {
    /// The bytes of a ref file.
    File(Vec<u8>),
    /// The body of an alias.
    Alias(Vec<u8>),
}

/// Reads the entry at `path` below `dir`: the bytes of a ref file, or the
/// body of an alias. `symlink` is `true` when the caller read the type of
/// the entry as a symlink.
///
/// The read of a ref file is [`RepoDir::read_capped`] with the cap
/// [`REF_READ_CAP`], so it follows no symlink, and its open does not wait on
/// a FIFO. When it finds a symlink, the call reads the body of the symlink
/// with [`RepoDir::read_link`]. A symlink at a component before the last one
/// fails that read too, with [`Reason::Symlink`]. When the read of a body
/// finds no symlink (`EINVAL`), a writer replaced the alias with a file, and
/// the call starts again one time. The errors are those of the two reads.
fn read_ref_entry(
    dir: &RepoDir,
    path: &str,
    symlink: bool,
) -> std::result::Result<RefEntryRead, FsError> {
    let mut symlink = symlink;
    let mut restarted = false;
    loop {
        if !symlink {
            match dir.read_capped(path, REF_READ_CAP) {
                Err(FsError::Invalid {
                    reason: Reason::Symlink,
                    ..
                }) => {}
                other => return other.map(RefEntryRead::File),
            }
        }
        match dir.read_link(path, REF_READ_CAP) {
            Err(FsError::Io(e))
                if !restarted && e.raw_os_error() == Some(Errno::INVAL.raw_os_error()) =>
            {
                restarted = true;
                symlink = false;
            }
            other => return other.map(RefEntryRead::Alias),
        }
    }
}

/// The target of an alias that [`read_alias_target`] read.
enum AliasTarget {
    /// The bytes of the ref file at the target.
    Ref(Vec<u8>),
    /// No entry is at the target, or the target path passes through a file.
    Absent,
    /// The alias breaks the alias rule. The payload is the reason that an
    /// [`Error::NotARef`] of the alias gives.
    Broken(&'static str),
}

/// Reads the ref file that an alias names, by the alias rule. `target` is
/// the path of the target below the repository root `root`, as
/// [`resolve_alias`] gives it, so it is a relative path inside `refs/`.
///
/// The rule: the target is a regular file, it is not an alias, and no
/// component of its path is a symlink. One `lstat` with no symlink followed
/// reads the type of the target before its open, so the call never opens a
/// FIFO, a socket, or a device through an alias. The call then reads a
/// regular file with [`RepoDir::read_capped`], which follows no symlink.
///
/// An absent target, and a target path that passes through a file, give
/// [`AliasTarget::Absent`]. A target that breaks the rule gives
/// [`AliasTarget::Broken`]. A target larger than [`REF_READ_CAP`] fails
/// with [`Error::InvalidFormat`].
fn read_alias_target(root: &RepoDir, target: &str) -> Result<AliasTarget> {
    let stat = match root.lstat(target) {
        Ok(stat) => stat,
        Err(e) => return alias_target_error(e),
    };
    match stat.file_type {
        FileType::RegularFile => {}
        FileType::Symlink => return Ok(AliasTarget::Broken(ALIAS_TO_AN_ALIAS)),
        _ => return Ok(AliasTarget::Broken(ALIAS_TO_NO_FILE)),
    }
    match root.read_capped(target, REF_READ_CAP) {
        Ok(bytes) => Ok(AliasTarget::Ref(bytes)),
        // The entry changed after the `lstat`.
        Err(FsError::Invalid {
            reason: Reason::NotRegular(_),
            ..
        }) => Ok(AliasTarget::Broken(ALIAS_TO_NO_FILE)),
        Err(e) => alias_target_error(e),
    }
}

/// Returns the result of an error `e` of the read of the target of an alias,
/// as [`read_alias_target`] states it.
fn alias_target_error(e: FsError) -> Result<AliasTarget> {
    match e {
        FsError::Absent { .. }
        | FsError::Invalid {
            reason: Reason::NotDirectory,
            ..
        } => Ok(AliasTarget::Absent),
        FsError::Invalid {
            reason: Reason::Symlink,
            ..
        } => Ok(AliasTarget::Broken(ALIAS_THROUGH_A_SYMLINK)),
        e => Err(e.into()),
    }
}

/// Reads the ref `name` at the path `relpath` below the repository root
/// `root` for a direct read, and parses it. The rules are those of
/// [`read_ref`].
fn read_ref_tip(root: &RepoDir, name: &str, relpath: &str) -> Result<Option<Checksum>> {
    match read_ref(root, name, relpath)? {
        Some(bytes) => Ok(Some(parse_ref_content(&bytes)?)),
        None => Ok(None),
    }
}

/// Reads the bytes of the ref `name` at the path `relpath` below the
/// repository root `root`, for a direct read of a ref name.
///
/// The call reads the entry with [`read_ref_entry`]. It opens the path first,
/// and checks the type of the entry after the open. The result is `None`
/// for an absent entry and for a path that passes through a file. An entry
/// that is not a regular file and not a symlink fails with
/// [`Error::NotARef`] and the reason `is not a regular file`. A symlink at a
/// component of the path fails with [`Error::InvalidFormat`].
///
/// An alias resolves by the alias rule: its body resolves with
/// [`resolve_alias`] against the directory of the alias, and
/// [`read_alias_target`] reads the target. An alias whose target is absent
/// gives `None`. An alias that breaks the rule fails with
/// [`Error::NotARef`] and the reason of the rule.
fn read_ref(root: &RepoDir, name: &str, relpath: &str) -> Result<Option<Vec<u8>>> {
    let body = match read_ref_entry(root, relpath, false).optional_ref(name)? {
        None => return Ok(None),
        Some(RefEntryRead::File(bytes)) => return Ok(Some(bytes)),
        Some(RefEntryRead::Alias(body)) => body,
    };
    let broken = |reason: &str| Error::NotARef {
        name: name.to_owned(),
        reason: reason.to_owned(),
    };
    let Some(target) = resolve_alias(ref_parent(relpath), &body) else {
        return Err(broken(ALIAS_OUTSIDE_REFS));
    };
    match read_alias_target(root, &target)? {
        AliasTarget::Ref(bytes) => Ok(Some(bytes)),
        AliasTarget::Absent => Ok(None),
        AliasTarget::Broken(reason) => Err(broken(reason)),
    }
}

/// The reason of [`RefFileState::NotARef`] for a path that passes through a
/// file.
const PASSES_THROUGH_A_FILE: &str = "passes through a file";

/// The reason of [`RefFileState::NotARef`] for a path that passes through a
/// symlink: an alias above the ref, dangling or not.
const PASSES_THROUGH_AN_ALIAS: &str = "passes through an alias";

/// The reason of [`RefFileState::NotARef`] for a path that names a
/// directory.
const NAMES_A_DIRECTORY: &str = "names a directory";

/// The reason of [`RefFileState::NotARef`] for a path that names a FIFO, a
/// socket, or a device file.
const NAMES_A_SPECIAL_FILE: &str = "names a special file";

/// The reason of [`Error::RefNotWritable`] for a ref write or a ref removal
/// whose path names an alias.
const NAMES_AN_ALIAS: &str = "names an alias";

/// The reason of [`Error::RefNotWritable`] for an alias write whose target
/// is an alias, or is the alias itself.
const TARGETS_AN_ALIAS: &str = "targets an alias";

/// The reason of [`Error::NotARef`] for an alias whose body is absolute, is
/// not UTF-8, or resolves outside `refs/`.
const ALIAS_OUTSIDE_REFS: &str = "is an alias whose target is not a relative path inside refs/";

/// The reason of [`Error::NotARef`] for an alias whose target is an alias,
/// or is the alias itself.
const ALIAS_TO_AN_ALIAS: &str = "is an alias to an alias";

/// The reason of [`Error::NotARef`] for an alias whose target path passes
/// through a symlink.
const ALIAS_THROUGH_A_SYMLINK: &str = "is an alias whose target passes through a symlink";

/// The reason of [`Error::NotARef`] for an alias whose target is a
/// directory, a FIFO, a socket, or a device file.
const ALIAS_TO_NO_FILE: &str = "is an alias to an entry that is not a regular file";

/// Returns the state of the ref path `relpath`, read with `lstat` alone.
///
/// The `lstat` is relative to the repository root `root`, and follows no
/// symlink at any component of the path, from the repository root down, so
/// `refs`, `refs/heads`, and `refs/remotes/R` are components too. The open
/// of the path has no fallback. On a kernel without `openat2`, the call
/// fails.
///
/// `None` is a regular file, whose content the caller reads. The call never
/// returns [`RefFileState::Commit`]. A path that the `lstat` cannot reach
/// has the state that [`unreached_state`] gives. Each other error, for
/// example `EACCES`, fails the call.
fn lstat_ref_state(root: &RepoDir, relpath: &str) -> Result<Option<RefFileState>> {
    let stat = match root.lstat(relpath) {
        Ok(stat) => stat,
        Err(e) => return unreached_state(e).map(Some),
    };
    Ok(match stat.file_type {
        FileType::RegularFile => None,
        FileType::Symlink => Some(RefFileState::Alias),
        FileType::Directory => Some(RefFileState::NotARef(NAMES_A_DIRECTORY)),
        _ => Some(RefFileState::NotARef(NAMES_A_SPECIAL_FILE)),
    })
}

/// Returns the state of a ref path that an operation could not reach, from
/// its error `e`:
///
/// - A symlink above the ref, dangling or not, is
///   [`RefFileState::NotARef`] with the reason [`PASSES_THROUGH_AN_ALIAS`].
///   The open stops at the first component that is not a directory, so a
///   symlink there gives this state before a file below it can give the
///   next one.
/// - A file or a special file above the ref is [`RefFileState::NotARef`]
///   with the reason [`PASSES_THROUGH_A_FILE`].
/// - A missing entry is [`RefFileState::Absent`].
///
/// Each other error fails the call.
fn unreached_state(e: FsError) -> Result<RefFileState> {
    match e {
        FsError::Absent { .. } => Ok(RefFileState::Absent),
        FsError::Invalid {
            reason: Reason::Symlink,
            ..
        } => Ok(RefFileState::NotARef(PASSES_THROUGH_AN_ALIAS)),
        FsError::Invalid {
            reason: Reason::NotDirectory,
            ..
        } => Ok(RefFileState::NotARef(PASSES_THROUGH_A_FILE)),
        e => Err(e.into()),
    }
}

/// Returns the state of the ref path `relpath`, read with [`lstat_ref_state`]
/// and then a read of a regular file with no symlink followed.
///
/// The read does not wait on a FIFO. A directory, a FIFO, a socket, or a
/// device file at the read gives the [`RefFileState::NotARef`] that
/// [`lstat_ref_state`] gives for it, and a symlink there gives
/// [`RefFileState::Alias`]. A ref file larger than [`REF_READ_CAP`] fails
/// with [`Error::InvalidFormat`].
fn ref_file_state(root: &RepoDir, relpath: &str) -> Result<RefFileState> {
    if let Some(state) = lstat_ref_state(root, relpath)? {
        return Ok(state);
    }
    match root.read_capped(relpath, REF_READ_CAP) {
        Ok(bytes) => Ok(RefFileState::Commit(parse_ref_content(&bytes)?)),
        // The entry changed after the `lstat`.
        Err(FsError::Invalid {
            reason: Reason::NotRegular(FileType::Directory),
            ..
        }) => Ok(RefFileState::NotARef(NAMES_A_DIRECTORY)),
        Err(FsError::Invalid {
            reason: Reason::NotRegular(_),
            ..
        }) => Ok(RefFileState::NotARef(NAMES_A_SPECIAL_FILE)),
        Err(FsError::Invalid {
            reason: Reason::Symlink,
            ..
        }) => Ok(RefFileState::Alias),
        Err(e) => unreached_state(e),
    }
}

/// Parses the content of a ref file: a hex checksum with trailing white
/// space.
pub(crate) fn parse_ref_content(bytes: &[u8]) -> Result<Checksum> {
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
#[cfg_attr(not(feature = "receive"), allow(dead_code))]
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
/// Prune classifies a ref below `refs/heads` or `refs/remotes` only where
/// this returns `true`. So each such ref that the classifier sees reads and
/// deletes through the file that the listing read. A name that the mapping
/// refuses gives `false`.
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
/// gives `false`. Prune classifies a mirror ref by its own rule: the path
/// must split into a valid collection id and a valid ref name, which
/// [`ref_relpath`] with no own id maps back to the same file.
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
// `.`, `_`, and alphanumeric characters that are not ASCII. `is_component` is
// the wider one-component rule that the remote part of a receive pattern uses
// (`pattern.rs`): not empty, not `.` or `..`, no slash, no NUL.
// `ostrya-core` holds the rules, and a collection id takes
// `ostrya_core::is_valid_collection_id`.
pub(crate) use ostrya_core::is_ref_component as is_component;
pub(crate) use ostrya_core::is_ref_name as is_ref_path;

/// Maps a ref to the path under the repository that the ref store reads and
/// writes, in a repository whose `[core] collection-id` is `own`.
///
/// A local ref gives `refs/heads/<name>`, and a remote ref gives
/// `refs/remotes/<remote>/<name>`. A collection ref gives
/// `refs/mirrors/<id>/<name>`, or `refs/heads/<name>` when `id` is `own`. A
/// caller that needs the mirror path of each id passes `None`. The ref must
/// pass [`Ref::validate`]. A failure gives [`Error::InvalidRefspec`] with the
/// text of the ref, and the caller writes nothing.
pub(crate) fn ref_relpath(own: Option<&str>, r: &Ref) -> Result<String> {
    r.validate()?;
    Ok(match r {
        Ref::Local { name } => format!("{HEADS_DIR}/{name}"),
        Ref::Remote { remote, name } => format!("refs/remotes/{remote}/{name}"),
        Ref::Collection { id, name } if Some(id.as_str()) == own => {
            format!("{HEADS_DIR}/{name}")
        }
        Ref::Collection { id, name } => format!("{MIRRORS_DIR}/{id}/{name}"),
    })
}

/// Reads a refspec as a [`Ref`] with no check: `REMOTE:NAME`, split at the
/// first `:`, is a remote ref, and other text is a local ref.
///
/// The ref store checks the result where it maps it to a path, so a refspec
/// that fails the rule fails there with [`Error::InvalidRefspec`].
pub(crate) fn refspec_ref(refspec: &str) -> Ref {
    match refspec.split_once(':') {
        Some((remote, name)) => Ref::remote(remote, name),
        None => Ref::local(refspec),
    }
}

/// Writes or removes one ref file below the repository root `root`,
/// atomically.
///
/// For `Some(checksum)`, the call:
///
/// 1. Opens `refs/`, and makes it with its directories `heads`, `remotes`,
///    and `mirrors` if it is absent.
/// 2. Writes the 65-byte `<hex>\n` content to a new temp file in `tmp/`,
///    sets its mode `0644`, and runs `fsync` on it if `fsync` is set.
/// 3. Makes the missing parent directories of the target.
/// 4. Renames the temp file over the target, relative to the parent
///    directory of the target.
///
/// If `tmp/` is on a different file system, the rename fails with `EXDEV`,
/// and the call removes the temp file. `None` unlinks the ref and does not
/// use `tmp/`. An absent file is success. A path that names an alias fails,
/// as [`put_ref_blocking`] states.
///
/// Under `fsync`, step 3 syncs the parent of each directory that it makes at
/// once, from the top down. The call runs `fsync` on the directory that
/// holds the ref after the rename or the unlink. So the name that the
/// operation created or removed is durable, and not only the content of the
/// file. A write that fails still syncs the directories that it changed
/// before the failure.
fn write_ref_blocking(
    root: &RepoDir,
    name: &str,
    relpath: &str,
    checksum: Option<Checksum>,
    fsync: bool,
) -> Result<()> {
    let mut dirs = Vec::new();
    let written = put_ref_blocking(root, name, relpath, checksum, fsync, &mut dirs);
    written.and(sync_ref_dirs(root, dirs))
}

/// Runs the body of [`write_ref_blocking`], and leaves the sync of the
/// directory of the ref to the caller.
///
/// Under `fsync`, the call adds the directory that holds the ref to `dirs`,
/// for [`sync_ref_dirs`], after the rename or the unlink. The directories
/// that the write makes are synced at once, and are not in `dirs`.
///
/// If `relpath` names an alias, or passes through an alias, the call fails
/// with [`Error::RefNotWritable`] for the ref `name`, and changes nothing.
pub(crate) fn put_ref_blocking(
    root: &RepoDir,
    name: &str,
    relpath: &str,
    checksum: Option<Checksum>,
    fsync: bool,
    dirs: &mut Vec<String>,
) -> Result<()> {
    let reason = match lstat_ref_state(root, relpath)? {
        Some(RefFileState::Alias) => Some(NAMES_AN_ALIAS),
        Some(RefFileState::NotARef(PASSES_THROUGH_AN_ALIAS)) => Some(PASSES_THROUGH_AN_ALIAS),
        _ => None,
    };
    if let Some(reason) = reason {
        return Err(Error::RefNotWritable {
            name: name.to_owned(),
            reason: reason.to_owned(),
        });
    }
    match checksum {
        Some(checksum) => put_ref_file_blocking(root, relpath, checksum, fsync, dirs),
        None => remove_ref_blocking(root, relpath, fsync, dirs),
    }
}

/// Unlinks the ref file `relpath` below the repository root `root`. An
/// absent file is success. The unlink is relative to the directory of the
/// ref, which opens with no symlink followed. Under `fsync`, the call adds
/// the directory that holds the ref to `dirs`.
fn remove_ref_blocking(
    root: &RepoDir,
    relpath: &str,
    fsync: bool,
    dirs: &mut Vec<String>,
) -> Result<()> {
    if root.remove_file(relpath, false)? && fsync {
        dirs.push(ref_parent(relpath).to_owned());
    }
    Ok(())
}

/// Opens `refs/` below the repository root `root` for a write. If `refs/` is
/// absent, the call makes it with its directories `heads`, `remotes`, and
/// `mirrors`.
fn open_refs_for_write(root: &RepoDir, fsync: bool) -> Result<RepoDir> {
    match root.open_layout(RepoLayout::Refs) {
        Err(FsError::Absent { .. }) => Ok(root.ensure_layout(RepoLayout::Refs, fsync)?),
        opened => Ok(opened?),
    }
}

/// Opens the directory that holds the ref `relpath` below the `refs/`
/// handle `refs` for a write, and makes each missing directory on the way.
/// Returns the handle of the directory and the name of the ref in it.
///
/// The call makes the directories below `refs/` with
/// [`RepoDir::ensure_dir`], with the mode of the kind below `refs/`. With
/// `fsync`, each make syncs the parent of the new directory at once. A
/// symlink or a file at a component fails with [`Error::InvalidFormat`].
fn ensure_ref_parent<'p>(
    refs: &RepoDir,
    relpath: &'p str,
    fsync: bool,
) -> Result<(RepoDir, &'p str)> {
    let Some((parent, leaf)) = relpath
        .strip_prefix("refs/")
        .and_then(|rel| rel.rsplit_once('/'))
    else {
        return Err(Error::InvalidInput(format!("not a ref path: {relpath}")));
    };
    Ok((refs.ensure_dir(parent, fsync)?, leaf))
}

/// Writes the ref file `relpath` through a temp file, as
/// [`put_ref_blocking`] writes a `Some` checksum.
///
/// The call opens `refs/` with [`open_refs_for_write`], and then makes the
/// temp file with [`RepoDir::stage_atomic`] on the `refs/` handle: a named
/// file `.ostrya-tmp-<pid>-XXXXXX` in the `tmp/` of the context of `root`.
/// The temp file holds the content, has the file mode of a ref file, and is
/// synced under `fsync`. The call makes the temp file before each directory
/// below `refs/` that [`RepoDir::ensure_dir`] makes, so a temp file that it
/// cannot make adds no such directory. If `refs/` is absent,
/// [`open_refs_for_write`] makes `refs/` and its directories `heads`,
/// `remotes`, and `mirrors` before the temp file.
fn put_ref_file_blocking(
    root: &RepoDir,
    relpath: &str,
    checksum: Checksum,
    fsync: bool,
    dirs: &mut Vec<String>,
) -> Result<()> {
    let refs = open_refs_for_write(root, fsync)?;
    let temp = refs.stage_atomic(format!("{}\n", checksum.to_hex()).as_bytes(), fsync)?;
    let (parent, leaf) = ensure_ref_parent(&refs, relpath, fsync)?;
    temp.publish(&parent, leaf, Publish::Replace, false)?;
    if fsync {
        dirs.push(ref_parent(relpath).to_owned());
    }
    Ok(())
}

/// Sorts `dirs` deepest first, then by name, and drops the repeats.
fn sort_dirs_deepest_first(dirs: &mut Vec<String>) {
    let depth = |dir: &str| {
        if dir == ROOT_DIR {
            0
        } else {
            dir.split('/').count()
        }
    };
    dirs.sort_by(|a, b| depth(b).cmp(&depth(a)).then_with(|| a.cmp(b)));
    dirs.dedup();
}

/// The name that a list of directories to sync gives the repository root.
const ROOT_DIR: &str = ".";

/// Runs `fsync` on the directory `dir` below the repository root `root`, or
/// on the root itself for [`ROOT_DIR`]. The open of `dir` follows no
/// symlink.
fn sync_recorded_dir(root: &RepoDir, dir: &str) -> Result<()> {
    if dir == ROOT_DIR {
        root.sync()?;
    } else {
        root.sync_dir(dir)?;
    }
    Ok(())
}

/// Runs `fsync` once on each distinct directory of `dirs`, deepest first. The
/// names are relative to the repository root `root`.
///
/// The call syncs a deeper directory before the directory above it. The
/// first sync records the name of the ref file. The next records the name of
/// the directory that holds it, and the next the name of the directory above
/// that. The object fanout uses the same order.
///
/// So a crash part way through leaves a prefix of each path recorded. It
/// never leaves a directory entry that names a directory with unrecorded
/// contents.
fn sync_ref_dirs(root: &RepoDir, mut dirs: Vec<String>) -> Result<()> {
    sort_dirs_deepest_first(&mut dirs);
    for dir in &dirs {
        sync_recorded_dir(root, dir)?;
    }
    Ok(())
}

/// Runs `fsync` once on each distinct directory of `dirs`, in the order of
/// [`sync_ref_dirs`], and returns the first error. A failed sync does not stop
/// the syncs after it. `.` names the repository root, which the call syncs
/// through its handle.
pub(crate) fn sync_dirs_all(root: &RepoDir, mut dirs: Vec<String>) -> Result<()> {
    sort_dirs_deepest_first(&mut dirs);
    let mut first = Ok(());
    for dir in &dirs {
        let synced = sync_recorded_dir(root, dir);
        #[cfg(test)]
        test_syncs::record(std::os::fd::AsFd::as_fd(root));
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

/// Writes one alias symlink below the repository root `root`, atomically.
/// `target` is the path of the ref that the alias names.
///
/// The call:
///
/// 1. Checks the path of the alias and the target, as [`put_alias_blocking`]
///    states.
/// 2. Creates the link under a new temp name in `tmp/`.
/// 3. Makes the missing parent directories of the alias, as
///    [`write_ref_blocking`] does.
/// 4. Renames the link over the path of the alias, relative to its parent
///    directory.
///
/// So the call replaces an existing ref file or an existing alias in one
/// step. A symlink has no content of its own to sync. So `fsync` reaches the
/// directory that holds each directory that the call makes, at once, and the
/// directory that holds the link.
///
/// A write that fails still syncs the directories that it changed before the
/// failure.
fn write_alias_blocking(
    root: &RepoDir,
    name: &str,
    relpath: &str,
    target: &str,
    fsync: bool,
) -> Result<()> {
    let mut dirs = Vec::new();
    let written = put_alias_blocking(root, name, relpath, target, fsync, &mut dirs);
    written.and(sync_ref_dirs(root, dirs))
}

/// Runs the body of [`write_alias_blocking`], and leaves the sync of the
/// directory of the link to the caller. Under `fsync`, the call adds to
/// `dirs` the directory that holds the link.
///
/// The call fails with [`Error::RefNotWritable`] for the alias `name`, and
/// changes nothing, in these cases:
///
/// - `relpath` passes through an alias. The reason is `passes through an
///   alias`.
/// - `target` is `relpath`, or names an alias. The reason is `targets an
///   alias`. One `lstat` with no symlink followed reads the type of the
///   target.
/// - `target` passes through an alias. The reason is `passes through an
///   alias`.
///
/// An absent target, and a target that passes through a file, are allowed.
pub(crate) fn put_alias_blocking(
    root: &RepoDir,
    name: &str,
    relpath: &str,
    target: &str,
    fsync: bool,
    dirs: &mut Vec<String>,
) -> Result<()> {
    let refuse = |reason: &str| {
        Err(Error::RefNotWritable {
            name: name.to_owned(),
            reason: reason.to_owned(),
        })
    };
    if passes_through_an_alias(root, relpath)? {
        return refuse(PASSES_THROUGH_AN_ALIAS);
    }
    if target == relpath {
        return refuse(TARGETS_AN_ALIAS);
    }
    match lstat_ref_state(root, target)? {
        Some(RefFileState::Alias) => return refuse(TARGETS_AN_ALIAS),
        Some(RefFileState::NotARef(PASSES_THROUGH_AN_ALIAS)) => {
            return refuse(PASSES_THROUGH_AN_ALIAS);
        }
        _ => {}
    }
    let link = TempLink::create(root, &relative_link(relpath, target))?;
    let (parent, leaf) = ensure_ref_parent(&open_refs_for_write(root, fsync)?, relpath, fsync)?;
    link.publish(&parent, leaf, Publish::Replace, false)?;
    if fsync {
        dirs.push(ref_parent(relpath).to_owned());
    }
    Ok(())
}

/// Returns `true` if a symlink, dangling or not, is at a component of the
/// ref path `relpath` before its last one, below the repository root `root`.
///
/// The check is one [`RepoDir::exists`], which follows no symlink. A symlink
/// at the last component, an absent entry, and a path that passes through a
/// file give `false`. Each other error fails the call.
fn passes_through_an_alias(root: &RepoDir, relpath: &str) -> Result<bool> {
    match root.exists(relpath) {
        Ok(_)
        | Err(FsError::Invalid {
            reason: Reason::NotDirectory,
            ..
        }) => Ok(false),
        Err(FsError::Invalid {
            reason: Reason::Symlink,
            ..
        }) => Ok(true),
        Err(e) => Err(e.into()),
    }
}

/// Unlinks the alias `relpath`, and leaves the directory syncs to the caller.
/// Under `fsync`, the call adds the directory that held the link to `dirs`.
///
/// An absent path is success. A ref file, a directory, a special file, or a
/// path that passes through a file or an alias fails with
/// [`Error::RefNotWritable`] for the ref `name`.
pub(crate) fn remove_alias_blocking(
    root: &RepoDir,
    name: &str,
    relpath: &str,
    fsync: bool,
    dirs: &mut Vec<String>,
) -> Result<()> {
    let reason = match lstat_ref_state(root, relpath)? {
        Some(RefFileState::Absent) => return Ok(()),
        Some(RefFileState::Alias) => return remove_ref_blocking(root, relpath, fsync, dirs),
        Some(RefFileState::NotARef(reason)) => reason,
        None | Some(RefFileState::Commit(_)) => "names a ref file",
    };
    Err(Error::RefNotWritable {
        name: name.to_owned(),
        reason: reason.to_owned(),
    })
}

/// Checks that no ref to delete passes through an alias, below the
/// repository root `root`, and removes nothing.
///
/// The call maps each key to its path with `relpath`, as
/// [`delete_matching_refs_blocking`] does. It checks each path one time with
/// [`passes_through_an_alias`]. If a path passes through an alias, the call
/// fails with [`Error::RefNotWritable`] for that key, reason `passes through
/// an alias`. Each other path passes the check.
pub(crate) fn check_refs_to_delete_blocking<K: std::fmt::Display>(
    root: &RepoDir,
    refs: &[(K, Checksum)],
    relpath: impl Fn(&K) -> Result<String>,
) -> Result<()> {
    for (key, _) in refs {
        if passes_through_an_alias(root, &relpath(key)?)? {
            return Err(Error::RefNotWritable {
                name: key.to_string(),
                reason: PASSES_THROUGH_AN_ALIAS.to_owned(),
            });
        }
    }
    Ok(())
}

/// Removes each ref that still names the checksum that the caller recorded
/// for it, below the repository root `root`, in one blocking pass.
///
/// The call maps each key to its path with `relpath`. The caller passes the
/// path rule of the asynchronous writes, for example [`refspec_to_relpath`]
/// for a refspec or [`ref_relpath`] for a [`Ref`]. So
/// the read and the unlink address the same file as the rest of the library.
/// One pass can hold keys of more than one space under `refs/`.
///
/// Before the first unlink, the call runs [`check_refs_to_delete_blocking`]
/// on the whole batch. If a path passes through an alias, the call fails
/// with its error and removes no ref. Each unlink opens the directory of the
/// ref with no symlink followed, so no unlink goes through a symlink above a
/// ref.
///
/// Each read comes immediately before its own unlink. The read is the direct
/// read of [`Repo::resolve_ref_tip`]. The call leaves a ref that now names a
/// different commit where it is. This covers a repository whose `[core]
/// locking` is false, and a caller that moved the ref after it recorded the
/// checksum.
///
/// A read that finds no ref unlinks all the same. The name that the caller
/// recorded is gone or dangles. The unlink removes a symlink and not the file
/// that it names, and an absent name is success. A FIFO, a socket, or a
/// device file at the path is no ref, and so is an alias that breaks the
/// alias rule, so the call unlinks it. The read checks the type of the file
/// after the open, and the open does not wait for a writer. An open that the
/// permissions refuse fails the call.
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
/// Returns the keys that it removed, in the order that it got them.
pub(crate) fn delete_matching_refs_blocking<K: std::fmt::Display>(
    root: &RepoDir,
    refs: Vec<(K, Checksum)>,
    relpath: impl Fn(&K) -> Result<String>,
    fsync: bool,
) -> Result<Vec<K>> {
    check_refs_to_delete_blocking(root, &refs, &relpath)?;
    let mut removed = Vec::with_capacity(refs.len());
    let mut parents: Vec<String> = Vec::new();
    let mut held: HashSet<String> = HashSet::new();
    for (key, target) in refs {
        let relpath = relpath(&key)?;
        let current = match read_ref(root, &relpath, &relpath) {
            Err(Error::NotARef { .. }) => None,
            read => read?,
        };
        if let Some(bytes) = current
            && parse_ref_content(&bytes)? != target
        {
            continue;
        }
        if root.remove_file(&relpath, false)? && fsync {
            let parent = ref_parent(&relpath);
            if !held.contains(parent) {
                held.insert(parent.to_owned());
                parents.push(parent.to_owned());
            }
        }
        removed.push(key);
    }
    for parent in &parents {
        root.sync_dir(parent).optional()?;
    }
    Ok(removed)
}

/// Returns the directory that holds the ref at `relpath`. A refspec and a
/// collection ref always map below `refs/`, so the path has a parent. For a
/// bare name, the result is the repository root.
fn ref_parent(relpath: &str) -> &str {
    relpath.rsplit_once('/').map_or(ROOT_DIR, |(dir, _)| dir)
}

#[cfg(test)]
mod tests {
    use ostrya_core::RepoMode;
    use rustix::fs::{Mode, OFlags};

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
    fn ref_relpath_names_the_ref_it_rejects() {
        for (r, label) in [
            (
                Ref::collection("org.example.Foo", "a/../b"),
                "@org.example.Foo:a/../b",
            ),
            (Ref::collection("a", "main"), "@a:main"),
            (Ref::local("a/../b"), "a/../b"),
            (Ref::local("origin:main"), "origin:main"),
            (Ref::remote("o/r", "main"), "o/r:main"),
            (
                Ref::collection("org.example.B", "-bad"),
                "@org.example.B:-bad",
            ),
        ] {
            let err = ref_relpath(None, &r).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidRefspec(name) if name == label),
                "{err}"
            );
        }
        let longest = format!("org.{}", "a".repeat(251));
        assert_eq!(longest.len(), ostrya_core::MAX_COLLECTION_ID_LEN);
        assert!(ref_relpath(None, &Ref::collection(longest.as_str(), "main")).is_ok());
        let too_long = format!("org.{}", "a".repeat(252));
        let err = ref_relpath(None, &Ref::collection(too_long.as_str(), "main")).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidRefspec(name) if *name == format!("@{too_long}:main")),
            "{err}"
        );
    }

    #[test]
    fn a_refspec_reads_as_a_ref_with_no_check() {
        assert_eq!(refspec_ref("a/b"), Ref::local("a/b"));
        assert_eq!(refspec_ref("origin:a/b"), Ref::remote("origin", "a/b"));
        assert_eq!(refspec_ref("o:a:b"), Ref::remote("o", "a:b"));
        let at = refspec_ref("@org.example.A:x");
        assert_eq!(at, Ref::remote("@org.example.A", "x"));
        assert!(at.validate().is_err());
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
    }

    impl Root {
        fn new(label: &str) -> Root {
            let dir = std::env::temp_dir().join(format!(
                "ostrya-refs-{label}-{}-{}",
                std::process::id(),
                crate::write::unique()
            ));
            std::fs::create_dir_all(dir.join("refs/heads")).unwrap();
            Root { dir }
        }

        /// Opens a handle of the scratch directory as a repository root.
        fn handle(&self) -> RepoDir {
            RepoDir::open_root(rustix::fs::CWD, &self.dir).unwrap()
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Returns the content of a ref file that names `commit`.
    fn ref_text(commit: &Checksum) -> String {
        format!("{}\n", commit.to_hex())
    }

    /// Makes a FIFO at `path`.
    fn mkfifo(path: &std::path::Path) {
        rustix::fs::mknodat(
            rustix::fs::CWD,
            path,
            FileType::Fifo,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
    }

    /// Asserts that `result` is [`Error::NotARef`] with the reason `reason`.
    fn assert_not_a_ref<T: std::fmt::Debug>(result: Result<T>, reason: &str, what: &str) {
        match result {
            Err(Error::NotARef { reason: r, .. }) => assert_eq!(r, reason, "{what}"),
            other => panic!("{what}: {other:?}"),
        }
    }

    /// Asserts that `result` is [`Error::InvalidFormat`] whose text holds
    /// `text`.
    fn assert_invalid<T: std::fmt::Debug>(result: Result<T>, text: &str, what: &str) {
        match result {
            Err(Error::InvalidFormat(message)) => {
                assert!(message.contains(text), "{what}: {message}");
            }
            other => panic!("{what}: {other:?}"),
        }
    }

    /// The listing reads an entry that the walk found as a ref file with no
    /// symlink followed. An entry that is an alias at the read takes the
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
            std::fs::write(heads.join("secret"), ref_text(&commit)).unwrap();
            std::fs::create_dir(heads.join("pub")).unwrap();
            std::os::unix::fs::symlink("../secret", heads.join("pub/a")).unwrap();
            let dir = open_ref_top(&repo, HEADS_DIR)
                .unwrap()
                .unwrap()
                .open_dir("pub")
                .unwrap();
            let entry = RefEntry {
                dir: &dir,
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
                let access = crate::access::ClientAccess::from_config(&config).unwrap();
                ReadAccess::new(
                    std::sync::Arc::new(access),
                    crate::access::AuthItem::Anonymous,
                    None,
                )
            };
            let root_dir = repo.root_dir();
            let hidden =
                read_listed_ref(root_dir, HEADS_DIR, &entry, Some(&reader("r:pub/**"))).unwrap();
            assert_eq!(hidden, None);
            let (read, target) =
                read_listed_ref(root_dir, HEADS_DIR, &entry, Some(&reader("r:**")))
                    .unwrap()
                    .unwrap();
            assert_eq!(parse_ref_content(&read).unwrap(), commit);
            assert_eq!(target.as_deref(), Some("refs/heads/secret"));
        });
    }

    /// The listing gives no ref for an entry that is a FIFO or a socket, and
    /// does not wait on the FIFO. An entry that the walk typed as a FIFO or a
    /// socket is never opened. An entry that the walk read as a regular file
    /// and that a FIFO replaced opens with no wait.
    #[test]
    fn a_listed_ref_entry_that_is_a_fifo_or_a_socket_gives_no_ref() {
        let root = Root::new("listed-fifo");
        let (fifo, _socket) = special_ref_entries(&root);
        for (name, file_type) in [
            ("fifo", FileType::Fifo),
            ("fifo", FileType::RegularFile),
            ("sock", FileType::Socket),
            ("sock", FileType::RegularFile),
        ] {
            let result = read_without_wait(&root.dir, &fifo, name, move |root| {
                let dir = root
                    .open_layout(RepoLayout::Refs)
                    .unwrap()
                    .open_dir("heads")
                    .unwrap();
                let entry = RefEntry {
                    dir: &dir,
                    name,
                    path: name,
                    file_type,
                };
                read_listed_ref(root, HEADS_DIR, &entry, None).map(|r| r.is_none())
            });
            assert!(result.unwrap(), "{name} as {file_type:?}");
        }
    }

    /// The alias listing gives no alias for an entry that the walk found as
    /// a symlink and that is removed, or that is no symlink, at the read of
    /// its body. A concurrent writer removes or replaces an alias so.
    #[test]
    fn a_listed_alias_that_is_gone_or_no_symlink_at_the_read_gives_no_alias() {
        let root = Root::new("listed-alias-gone");
        let heads = root.dir.join("refs/heads");
        let commit = Checksum::from_bytes([7; 32]);
        std::fs::write(heads.join("file"), ref_text(&commit)).unwrap();
        std::fs::create_dir(heads.join("dir")).unwrap();
        let handle = root.handle();
        let dir = handle
            .open_layout(RepoLayout::Refs)
            .unwrap()
            .open_dir("heads")
            .unwrap();
        for name in ["gone", "file", "dir"] {
            let entry = RefEntry {
                dir: &dir,
                name,
                path: name,
                file_type: FileType::Symlink,
            };
            assert_eq!(read_alias_body(&entry).unwrap(), None, "{name}");
        }
    }

    /// Runs `read` on a thread with a new handle of the repository root
    /// `dir`, and returns its result. If the call does not end in 10 seconds,
    /// a writer opens `fifo`, so that a blocked open ends, and the test
    /// fails.
    fn read_without_wait<T: Send + 'static>(
        dir: &std::path::Path,
        fifo: &std::path::Path,
        what: &str,
        read: impl FnOnce(&RepoDir) -> T + Send + 'static,
    ) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        let dir = dir.to_owned();
        std::thread::spawn(move || {
            let root = RepoDir::open_root(rustix::fs::CWD, &dir).unwrap();
            let _ = tx.send(read(&root));
        });
        let timeout = std::time::Duration::from_secs(10);
        let Ok(result) = rx.recv_timeout(timeout) else {
            // A writer releases the blocked open, so the thread ends.
            let _ = rustix::fs::open(
                fifo,
                OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            );
            let _ = rx.recv_timeout(timeout);
            panic!("{what}: the open waits on the FIFO");
        };
        result
    }

    /// Makes in `refs/heads` of `root` a FIFO `fifo`, an alias `to-fifo` to
    /// it, a socket `sock`, an alias `to-sock` to it, an absolute alias `null`
    /// to `/dev/null`, a directory `dir`, and an alias `to-dir` to it.
    /// Returns the path of the FIFO and the socket, which lives while the
    /// caller holds it.
    fn special_ref_entries(root: &Root) -> (std::path::PathBuf, std::os::unix::net::UnixListener) {
        let heads = root.dir.join("refs/heads");
        let fifo = heads.join("fifo");
        mkfifo(&fifo);
        std::os::unix::fs::symlink("fifo", heads.join("to-fifo")).unwrap();
        // The path of a socket has a short length limit, so the bind uses a
        // short path and a rename moves the socket into place.
        let short = root.dir.join("s");
        let socket = std::os::unix::net::UnixListener::bind(&short).unwrap();
        std::fs::rename(&short, heads.join("sock")).unwrap();
        std::os::unix::fs::symlink("sock", heads.join("to-sock")).unwrap();
        std::os::unix::fs::symlink("/dev/null", heads.join("null")).unwrap();
        std::fs::create_dir(heads.join("dir")).unwrap();
        std::os::unix::fs::symlink("dir", heads.join("to-dir")).unwrap();
        (fifo, socket)
    }

    /// A direct read of a ref path that names a FIFO, a socket, or a
    /// directory fails with "not a ref", and its open does not wait for a
    /// writer. An alias to such an entry, and an absolute alias, fail with
    /// the reason of the alias rule. A ref file reads.
    #[test]
    fn a_direct_read_of_a_fifo_a_socket_or_a_directory_is_not_a_ref() {
        let root = Root::new("special");
        let (fifo, _socket) = special_ref_entries(&root);
        for (name, reason) in [
            ("fifo", "is not a regular file"),
            ("sock", "is not a regular file"),
            ("dir", "is not a regular file"),
            ("to-fifo", ALIAS_TO_NO_FILE),
            ("to-sock", ALIAS_TO_NO_FILE),
            ("to-dir", ALIAS_TO_NO_FILE),
            ("null", ALIAS_OUTSIDE_REFS),
        ] {
            let relpath = format!("refs/heads/{name}");
            let result = read_without_wait(&root.dir, &fifo, name, move |root| {
                read_ref(root, name, &relpath)
            });
            assert_not_a_ref(result, reason, name);
        }
        let commit = Checksum::from_bytes([1; 32]);
        std::fs::write(root.dir.join("refs/heads/main"), ref_text(&commit)).unwrap();
        let read = read_ref_tip(&root.handle(), "main", "refs/heads/main").unwrap();
        assert_eq!(read, Some(commit));
    }

    /// The state of a ref path that names a FIFO or a socket is a special
    /// file, and the state of a directory is a directory. This holds for
    /// the `lstat` and for the read of the write-path check, and the read
    /// does not wait for a writer.
    #[test]
    fn the_ref_state_of_a_fifo_a_socket_or_a_directory_is_no_ref() {
        let root = Root::new("special-state");
        let (fifo, _socket) = special_ref_entries(&root);
        for (name, reason) in [
            ("fifo", "names a special file"),
            ("sock", "names a special file"),
            ("dir", "names a directory"),
        ] {
            let relpath = format!("refs/heads/{name}");
            let (lstat, checked) = read_without_wait(&root.dir, &fifo, name, move |root| {
                (
                    lstat_ref_state(root, &relpath),
                    ref_file_state(root, &relpath),
                )
            });
            let state = RefFileState::NotARef(reason);
            assert_eq!(lstat.unwrap(), Some(state), "{name}");
            assert_eq!(checked.unwrap(), state, "{name}");
        }
    }

    /// A symlink above a ref path, dangling or not, gives the state "passes
    /// through an alias", also at `refs` and at `refs/heads`. A ref file or a
    /// FIFO above the path gives "passes through a file", and the read does
    /// not wait on the FIFO. A symlink at the last component is an alias.
    #[test]
    fn the_ref_state_of_a_path_below_an_alias_is_no_ref() {
        use std::os::unix::fs::symlink;

        let root = Root::new("below-alias");
        let heads = root.dir.join("refs/heads");
        let content = ref_text(&Checksum::from_bytes([1; 32]));
        std::fs::create_dir(heads.join("d0")).unwrap();
        std::fs::write(heads.join("d0/x"), &content).unwrap();
        std::fs::write(heads.join("file"), &content).unwrap();
        symlink("nosuch", heads.join("dangling")).unwrap();
        symlink("d0", heads.join("to-dir")).unwrap();
        symlink("file", heads.join("to-file")).unwrap();
        let fifo = heads.join("fifo");
        mkfifo(&fifo);
        let alias = RefFileState::NotARef(PASSES_THROUGH_AN_ALIAS);
        let file = RefFileState::NotARef(PASSES_THROUGH_A_FILE);
        for (relpath, state) in [
            ("refs/heads/dangling/x", alias),
            ("refs/heads/to-dir/x", alias),
            ("refs/heads/to-dir/deeper/x", alias),
            ("refs/heads/to-file/x", alias),
            ("refs/heads/file/x", file),
            ("refs/heads/fifo/x", file),
            ("refs/heads/dangling", RefFileState::Alias),
            ("refs/heads/to-dir", RefFileState::Alias),
            ("refs/heads/nosuch/x", RefFileState::Absent),
        ] {
            let (lstat, checked) = read_without_wait(&root.dir, &fifo, relpath, move |root| {
                (
                    lstat_ref_state(root, relpath),
                    ref_file_state(root, relpath),
                )
            });
            assert_eq!(lstat.unwrap(), Some(state), "{relpath}");
            assert_eq!(checked.unwrap(), state, "{relpath}");
        }

        for top in ["refs/heads", "refs"] {
            let root = Root::new("below-alias-top");
            let real = root.dir.join("real");
            std::fs::rename(root.dir.join(top), &real).unwrap();
            let link = if top == "refs" { "real" } else { "../real" };
            symlink(link, root.dir.join(top)).unwrap();
            let main = if top == "refs" {
                "real/heads/main"
            } else {
                "real/main"
            };
            std::fs::write(root.dir.join(main), &content).unwrap();
            let handle = root.handle();
            for relpath in ["refs/heads/main", "refs/heads/sub/x"] {
                assert_eq!(
                    lstat_ref_state(&handle, relpath).unwrap(),
                    Some(alias),
                    "{top}: {relpath}"
                );
                assert_eq!(
                    ref_file_state(&handle, relpath).unwrap(),
                    alias,
                    "{top}: {relpath}"
                );
            }
        }
    }

    /// Creates an archive repository at `path`.
    async fn archive_repo(path: &std::path::Path) -> Repo {
        Repo::create(path, crate::CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap()
    }

    /// An alias that breaks the alias rule names no ref. A direct read of it
    /// fails with "not a ref" and the reason of the rule, and each listing
    /// and the prune roots leave it out. The aliases are in `refs/heads`, in
    /// `refs/remotes/o`, and in `refs/mirrors/ID`, and each names a ref file
    /// that holds the commit: an absolute alias into `refs/`, an absolute
    /// alias out of the repository, an alias to a file at the repository
    /// root, an alias that leaves the repository, an alias through a
    /// symlinked directory, an alias to an alias, and an alias to itself.
    #[test]
    fn an_alias_that_breaks_the_alias_rule_names_no_ref() {
        use std::os::unix::fs::symlink;

        let root = Root::new("alias-rule");
        let path = root.dir.join("repo");
        let repo = ostrya_rt::block_on(archive_repo(&path));
        let commit = Checksum::from_bytes([3; 32]);
        let outside = root.dir.join("outside-ref");
        std::fs::write(&outside, ref_text(&commit)).unwrap();
        std::fs::write(path.join("inrepo-ref"), ref_text(&commit)).unwrap();
        let mirror = format!("{MIRRORS_DIR}/org.example.Other");
        let dirs = [HEADS_DIR, "refs/remotes/o", mirror.as_str()];
        for dir in dirs {
            let dir = path.join(dir);
            std::fs::create_dir_all(dir.join("real")).unwrap();
            std::fs::write(dir.join("real/main"), ref_text(&commit)).unwrap();
            symlink("real", dir.join("linked")).unwrap();
            symlink("real/main", dir.join("good")).unwrap();
            symlink(dir.join("real/main"), dir.join("absin")).unwrap();
            symlink(&outside, dir.join("absout")).unwrap();
            symlink("../../../inrepo-ref", dir.join("relroot")).unwrap();
            symlink("../../../../outside-ref", dir.join("relout")).unwrap();
            symlink("linked/main", dir.join("through")).unwrap();
            symlink("good", dir.join("chain")).unwrap();
            symlink("self", dir.join("self")).unwrap();
        }
        // The remote and the mirror directories are one level deeper, so a
        // body that leaves `refs/` from there has one `..` more.
        for dir in [&dirs[1], &dirs[2]] {
            let dir = path.join(dir);
            for name in ["relroot", "relout"] {
                std::fs::remove_file(dir.join(name)).unwrap();
            }
            symlink("../../../../inrepo-ref", dir.join("relroot")).unwrap();
            symlink("../../../../../outside-ref", dir.join("relout")).unwrap();
        }
        let broken = [
            ("absin", ALIAS_OUTSIDE_REFS),
            ("absout", ALIAS_OUTSIDE_REFS),
            ("relroot", ALIAS_OUTSIDE_REFS),
            ("relout", ALIAS_OUTSIDE_REFS),
            ("through", ALIAS_THROUGH_A_SYMLINK),
            ("chain", ALIAS_TO_AN_ALIAS),
            ("self", ALIAS_TO_AN_ALIAS),
        ];
        ostrya_rt::block_on(async {
            for (name, reason) in broken {
                let result = repo.resolve_ref_tip(&Ref::local(name)).await;
                assert_not_a_ref(result, reason, name);
                let result = repo.resolve_rev(name, true).await;
                assert_not_a_ref(result, reason, name);
                let result = repo.resolve_ref_tip(&Ref::remote("o", name)).await;
                assert_not_a_ref(result, reason, name);
            }
            assert_eq!(
                repo.resolve_ref_tip(&Ref::local("good")).await.unwrap(),
                Some(commit)
            );
            let names = |refs: Vec<(String, Checksum)>| -> Vec<String> {
                refs.into_iter().map(|(name, _)| name).collect()
            };
            assert_eq!(
                names(repo.list_refs(None).await.unwrap()),
                ["good", "real/main"]
            );
            assert_eq!(
                names(repo.list_remote_refs().await.unwrap()),
                ["o:good", "o:real/main"]
            );
            let mut mirrors: Vec<String> = repo
                .list_mirror_refs()
                .await
                .unwrap()
                .into_iter()
                .map(|(_, name, _)| name)
                .collect();
            mirrors.sort();
            assert_eq!(mirrors, ["good", "real/main"]);
            let selector = RefSelector::parse(["**"]).unwrap();
            let selection = repo
                .select_refs(&selector, Some(&selector), repo.implicit_reads(), None)
                .await
                .unwrap();
            assert_eq!(names(selection.local), ["good", "real/main"]);
            assert_eq!(
                names(selection.collections["org.example.Other"].clone()),
                ["good", "real/main"]
            );
            let mut all: Vec<String> = repo
                .list_all_refs()
                .await
                .unwrap()
                .into_iter()
                .map(|listed| listed.name)
                .collect();
            all.sort();
            assert_eq!(
                all,
                [
                    "good",
                    "o:good",
                    "o:real/main",
                    "org.example.Other/good",
                    "org.example.Other/real/main",
                    "real/main",
                ]
            );
        });
    }

    /// An alias whose target is absent, or whose target path passes through
    /// a ref file, names no ref: a direct read gives `None`, and a listing
    /// leaves it out.
    #[test]
    fn an_alias_to_an_absent_target_reads_as_absent() {
        use std::os::unix::fs::symlink;

        let root = Root::new("alias-absent");
        let path = root.dir.join("repo");
        let repo = ostrya_rt::block_on(archive_repo(&path));
        let heads = path.join("refs/heads");
        std::fs::write(heads.join("file"), ref_text(&Checksum::from_bytes([4; 32]))).unwrap();
        symlink("nosuch", heads.join("gone")).unwrap();
        symlink("file/below", heads.join("below")).unwrap();
        ostrya_rt::block_on(async {
            for name in ["gone", "below"] {
                assert_eq!(
                    repo.resolve_ref_tip(&Ref::local(name)).await.unwrap(),
                    None,
                    "{name}"
                );
                assert_eq!(repo.resolve_rev(name, true).await.unwrap(), None);
                assert!(matches!(
                    repo.resolve_rev(name, false).await,
                    Err(Error::RefNotFound(_))
                ));
            }
            assert_eq!(repo.list_refs(None).await.unwrap().len(), 1);
        });
    }

    /// A ref file of 4096 bytes reads, in a direct read and in a listing. A
    /// ref file of 4097 bytes fails each read with its cap, also as the
    /// target of an alias.
    #[test]
    fn a_ref_file_over_its_cap_fails_the_read() {
        let root = Root::new("ref-cap");
        let path = root.dir.join("repo");
        let repo = ostrya_rt::block_on(archive_repo(&path));
        let commit = Checksum::from_bytes([5; 32]);
        let heads = path.join("refs/heads");
        let padded = |len: usize| {
            let mut text = ref_text(&commit);
            text.push_str(&" ".repeat(len - text.len()));
            text
        };
        std::fs::write(heads.join("x"), padded(4096)).unwrap();
        ostrya_rt::block_on(async {
            assert_eq!(
                repo.resolve_ref_tip(&Ref::local("x")).await.unwrap(),
                Some(commit)
            );
            assert_eq!(
                repo.list_refs(None).await.unwrap(),
                [("x".to_owned(), commit)]
            );
            std::fs::write(heads.join("x"), padded(4097)).unwrap();
            let cap = "refs/heads/x is larger than its cap of 4096 bytes";
            assert_invalid(repo.resolve_ref_tip(&Ref::local("x")).await, cap, "tip");
            assert_invalid(repo.resolve_rev("x", false).await, cap, "rev");
            assert_invalid(repo.list_refs(None).await, cap, "list");
            assert_invalid(repo.list_all_refs().await, cap, "all");
            std::os::unix::fs::symlink("x", heads.join("al")).unwrap();
            assert_invalid(repo.resolve_ref_tip(&Ref::local("al")).await, cap, "alias");
        });
    }

    /// A symlink at `refs`, at `refs/heads`, at `refs/remotes/R`, or at
    /// `refs/mirrors/ID` fails a resolve and each listing that reads the
    /// directory with "passes through a symlink": the listings of the local,
    /// remote, mirror, collection, and alias refs, the selection of the
    /// summary, and the prune and fsck roots. A write below it gives
    /// "passes through an alias".
    #[test]
    fn a_symlink_at_a_ref_directory_fails_the_read_and_the_write() {
        use std::os::unix::fs::symlink;

        let commit = Checksum::from_bytes([6; 32]);
        let id = "org.example.Other";
        for (dir, r) in [
            ("refs", Ref::local("main")),
            (HEADS_DIR, Ref::local("main")),
            ("refs/remotes/o", Ref::remote("o", "main")),
            (
                "refs/mirrors/org.example.Other",
                Ref::collection(id, "main"),
            ),
        ] {
            let root = Root::new("ref-dir-link");
            let path = root.dir.join("repo");
            let repo = ostrya_rt::block_on(archive_repo(&path));
            std::fs::create_dir_all(path.join(dir)).unwrap();
            let rel = ref_relpath(None, &r).unwrap();
            std::fs::create_dir_all(path.join(&rel).parent().unwrap()).unwrap();
            std::fs::write(path.join(&rel), ref_text(&commit)).unwrap();
            let real = root.dir.join("real");
            std::fs::rename(path.join(dir), &real).unwrap();
            symlink(&real, path.join(dir)).unwrap();
            let symlinked = "passes through a symlink";
            ostrya_rt::block_on(async {
                assert_invalid(repo.resolve_ref_tip(&r).await, symlinked, dir);
                assert_invalid(repo.list_all_refs().await, symlinked, dir);
                let all = RefSelector::parse(["**"]).unwrap();
                match dir {
                    "refs" | HEADS_DIR => {
                        assert_invalid(repo.list_refs(None).await, symlinked, dir);
                        assert_invalid(repo.list_refs_where(|_| true).await, symlinked, dir);
                        assert_invalid(repo.list_ref_aliases().await, symlinked, dir);
                    }
                    "refs/remotes/o" => {
                        let remotes =
                            BTreeMap::from([("o".to_owned(), "org.example.O".to_owned())]);
                        assert_invalid(collect_remote_collections(&repo, &remotes), symlinked, dir);
                        assert_invalid(repo.list_remote_refs().await, symlinked, dir);
                        assert_invalid(repo.list_ref_aliases().await, symlinked, dir);
                    }
                    _ => {
                        let listed = repo.list_collection_refs_in(id, &all).await;
                        assert_invalid(listed, symlinked, dir);
                        assert_invalid(repo.list_mirror_refs().await, symlinked, dir);
                        assert_invalid(repo.list_collection_refs().await, symlinked, dir);
                        assert_invalid(repo.list_refs_where(|_| true).await, symlinked, dir);
                        // A `keep` that drops each ref does not hide the
                        // symlink.
                        assert_invalid(repo.list_refs_where(|_| false).await, symlinked, dir);
                        let selected = repo
                            .select_refs(&all, Some(&all), repo.implicit_reads(), None)
                            .await;
                        assert_invalid(selected.map(|_| ()), symlinked, dir);
                        assert_invalid(repo.list_ref_aliases().await, symlinked, dir);
                    }
                }
                let written = repo.set_ref_immediate(&r, Some(&commit)).await;
                match written {
                    Err(Error::RefNotWritable { reason, .. }) => {
                        assert_eq!(reason, PASSES_THROUGH_AN_ALIAS, "{dir}");
                    }
                    other => panic!("{dir}: {other:?}"),
                }
            });
        }
    }

    /// An alias write refuses a target that is an alias, a target below an
    /// alias, and a target that is the alias itself, and writes nothing. An
    /// absent target is allowed.
    #[test]
    fn an_alias_write_refuses_a_target_that_is_an_alias() {
        let root = Root::new("alias-write");
        let path = root.dir.join("repo");
        let repo = ostrya_rt::block_on(archive_repo(&path));
        let heads = path.join("refs/heads");
        ostrya_rt::block_on(async {
            let commit = Checksum::from_bytes([8; 32]);
            repo.set_ref_immediate(&Ref::local("main"), Some(&commit))
                .await
                .unwrap();
            repo.set_ref_alias_immediate(&Ref::local("al1"), &Ref::local("main"))
                .await
                .unwrap();
            std::fs::create_dir(heads.join("d")).unwrap();
            std::os::unix::fs::symlink("d", heads.join("dl")).unwrap();
            for (target, reason) in [
                ("al1", TARGETS_AN_ALIAS),
                ("al2", TARGETS_AN_ALIAS),
                ("dl/x", PASSES_THROUGH_AN_ALIAS),
            ] {
                match repo
                    .set_ref_alias_immediate(&Ref::local("al2"), &Ref::local(target))
                    .await
                {
                    Err(Error::RefNotWritable { name, reason: r }) => {
                        assert_eq!((name.as_str(), r.as_str()), ("al2", reason), "{target}");
                    }
                    other => panic!("{target}: {other:?}"),
                }
                assert!(
                    std::fs::symlink_metadata(heads.join("al2")).is_err(),
                    "{target}"
                );
            }
            repo.set_ref_alias_immediate(&Ref::local("al3"), &Ref::local("nosuch"))
                .await
                .unwrap();
            assert_eq!(
                std::fs::read_link(heads.join("al3")).unwrap(),
                std::path::Path::new("nosuch")
            );
        });
    }

    /// Returns the number of temp entries in `tmp/` of the repository at
    /// `root`.
    fn temp_entries(root: &std::path::Path) -> usize {
        std::fs::read_dir(root.join("tmp"))
            .unwrap()
            .filter(|entry| {
                let name = entry.as_ref().unwrap().file_name();
                name.to_string_lossy().starts_with(".ostrya-tmp-")
            })
            .count()
    }

    /// A ref write puts its temp file in `tmp/`, syncs the directories that
    /// it makes at once, and records the directory of the ref for the batch
    /// sync. A failed publish leaves no temp entry and records nothing.
    #[test]
    fn a_ref_write_puts_its_temp_file_in_tmp() {
        let root = Root::new("temp-file");
        let handle = root.handle();
        let checksum = Some(Checksum::from_bytes([7; 32]));
        let mut dirs = Vec::new();
        put_ref_blocking(&handle, "a/x", "refs/heads/a/x", checksum, true, &mut dirs).unwrap();
        assert_eq!(dirs, ["refs/heads/a"]);
        assert_eq!(temp_entries(&root.dir), 0);

        // A ref name of 256 bytes is longer than a file name can be. The temp
        // file in `tmp/` is created, and the rename over the ref name fails.
        let long = "r".repeat(256);
        let name = format!("new/deep/{long}");
        let mut dirs = Vec::new();
        let relpath = format!("refs/heads/{name}");
        put_ref_blocking(&handle, &name, &relpath, checksum, true, &mut dirs).unwrap_err();
        assert!(dirs.is_empty(), "{dirs:?}");
        assert!(root.dir.join("refs/heads/new/deep").is_dir());
        assert_eq!(temp_entries(&root.dir), 0);
    }

    /// The ref listings leave out a FIFO entry that the walk found, and do
    /// not open it. During the listings, a writer waits in a blocking open of
    /// each FIFO. An open of the FIFO by a reader ends the wait of its writer,
    /// so a writer that stops its wait shows an open by a listing.
    #[test]
    fn the_ref_listings_do_not_open_a_fifo_entry() {
        let root = Root::new("listing-fifo");
        let repo = ostrya_rt::block_on(Repo::create(
            &root.dir.join("repo"),
            crate::CreateOptions::new(RepoMode::Archive),
        ))
        .unwrap();
        let fifos: Vec<std::path::PathBuf> = [
            "refs/heads/fifo",
            "refs/remotes/o/fifo",
            "refs/mirrors/org.example.Other/fifo",
        ]
        .iter()
        .map(|rel| {
            let fifo = root.dir.join("repo").join(rel);
            std::fs::create_dir_all(fifo.parent().unwrap()).unwrap();
            rustix::fs::mknodat(
                rustix::fs::CWD,
                &fifo,
                FileType::Fifo,
                Mode::from_raw_mode(0o644),
                0,
            )
            .unwrap();
            fifo
        })
        .collect();
        let (task_tx, task_rx) = std::sync::mpsc::channel();
        let (open_tx, open_rx) = std::sync::mpsc::channel();
        for fifo in &fifos {
            let (task_tx, open_tx, fifo) = (task_tx.clone(), open_tx.clone(), fifo.clone());
            std::thread::spawn(move || {
                task_tx
                    .send(std::fs::read_link("/proc/thread-self").unwrap())
                    .unwrap();
                let _ = rustix::fs::open(&fifo, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty());
                let _ = open_tx.send(());
            });
        }
        // Each reader open releases the writer of its FIFO. The call waits for
        // the `waiting` writers that did not end yet.
        let release = |waiting: usize| {
            let readers: Vec<_> = fifos
                .iter()
                .map(|fifo| {
                    rustix::fs::open(
                        fifo,
                        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .unwrap()
                })
                .collect();
            for _ in 0..waiting {
                let _ = open_rx.recv_timeout(std::time::Duration::from_secs(10));
            }
            drop(readers);
        };
        // The writer sleeps in its open when its task state is `S`.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        for _ in &fifos {
            let task = task_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            let stat = std::path::Path::new("/proc").join(task).join("stat");
            loop {
                let text = std::fs::read_to_string(&stat).unwrap();
                let state = text.rsplit_once(") ").map(|(_, rest)| &rest[..1]);
                if state == Some("S") {
                    break;
                }
                if std::time::Instant::now() > deadline {
                    release(fifos.len());
                    panic!("a writer does not wait in its open: {text}");
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        let remotes = BTreeMap::from([("o".to_owned(), "org.example.O".to_owned())]);
        let heads = collect_heads(&repo, open_refs(&repo).unwrap().as_ref(), &|_| true);
        let remote_refs = collect_remotes(&repo);
        let remote_collections = collect_remote_collections(&repo, &remotes);
        let mirrors = collect_mirrors(
            &repo,
            open_refs(&repo).unwrap().as_ref(),
            &|_| false,
            &|_| true,
        );
        let all = ostrya_rt::block_on(repo.list_all_refs());
        std::thread::sleep(std::time::Duration::from_millis(200));
        let ended = open_rx.try_iter().count();
        release(fifos.len() - ended);
        assert_eq!(ended, 0, "a listing opened a FIFO");
        assert!(heads.unwrap().is_empty());
        assert!(remote_refs.unwrap().is_empty());
        assert!(remote_collections.unwrap().is_empty());
        assert!(mirrors.unwrap().is_empty());
        assert!(all.unwrap().is_empty());
    }

    /// The ref listings leave out a FIFO entry with mode 000, and the
    /// listings do not fail. A read of its ref path fails with the error of
    /// the open. The root user opens a file whatever its mode, so the test
    /// does not run as root.
    #[test]
    fn the_ref_listings_leave_out_a_special_entry_that_the_permissions_refuse() {
        if rustix::process::geteuid().is_root() {
            eprintln!("skipped: the root user opens a FIFO with mode 000");
            return;
        }
        let root = Root::new("listing-locked");
        let repo_dir = root.dir.join("repo");
        let repo = ostrya_rt::block_on(Repo::create(
            &repo_dir,
            crate::CreateOptions::new(RepoMode::Archive),
        ))
        .unwrap();
        let commit = Checksum::from_bytes([1; 32]);
        let dirs = [
            "refs/heads",
            "refs/remotes/o",
            "refs/mirrors/org.example.Other",
        ];
        for dir in dirs {
            let dir = repo_dir.join(dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("main"), format!("{}\n", commit.to_hex())).unwrap();
            rustix::fs::mknodat(
                rustix::fs::CWD,
                dir.join("locked"),
                FileType::Fifo,
                Mode::empty(),
                0,
            )
            .unwrap();
        }
        let remotes = BTreeMap::from([("o".to_owned(), "org.example.O".to_owned())]);
        assert_eq!(
            collect_heads(&repo, open_refs(&repo).unwrap().as_ref(), &|_| true).unwrap(),
            [("main".to_owned(), commit)]
        );
        assert_eq!(
            collect_remotes(&repo).unwrap(),
            [("o:main".to_owned(), commit)]
        );
        assert_eq!(
            collect_remote_collections(&repo, &remotes).unwrap(),
            [(
                "o".to_owned(),
                "org.example.O".to_owned(),
                "main".to_owned(),
                commit
            )]
        );
        assert_eq!(
            collect_mirrors(
                &repo,
                open_refs(&repo).unwrap().as_ref(),
                &|_| false,
                &|_| true
            )
            .unwrap(),
            [("org.example.Other".to_owned(), "main".to_owned(), commit)]
        );
        let mut all: Vec<(String, Checksum)> = ostrya_rt::block_on(repo.list_all_refs())
            .unwrap()
            .into_iter()
            .map(|listed| (listed.name, listed.checksum))
            .collect();
        all.sort();
        assert_eq!(
            all,
            [
                ("main".to_owned(), commit),
                ("o:main".to_owned(), commit),
                ("org.example.Other/main".to_owned(), commit),
            ]
        );
        for dir in dirs {
            let relpath = format!("{dir}/locked");
            match read_ref(repo.root_dir(), "locked", &relpath) {
                Err(Error::Io(e)) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{dir}");
                }
                other => panic!("{dir}: {other:?}"),
            }
        }
    }

    /// The collection id of the repositories of the own-collection tests.
    const OWN: &str = "org.example.Os";
    /// The ref name of the own-collection tests.
    const NAME: &str = "os/stable";

    /// Creates an archive repository at `path` with the collection id
    /// [`OWN`].
    async fn own_repo(path: &std::path::Path) -> Repo {
        Repo::create(
            path,
            crate::CreateOptions::new(RepoMode::Archive).collection_id(OWN),
        )
        .await
        .unwrap()
    }

    /// The implicit read access of a handle takes the collection id of the
    /// repository as the local namespace. It reads the local path of a ref
    /// of that id, and no mirror path of that id.
    #[test]
    fn the_implicit_read_access_takes_the_collection_id_of_the_repository() {
        let root = Root::new("implicit-reads");
        ostrya_rt::block_on(async {
            let repo = own_repo(&root.dir.join("repo")).await;
            let reads = repo.implicit_reads();
            assert_eq!(reads.access().namespace(Some(OWN)), Namespace::Local);
            assert!(reads.can_read_path(&format!("refs/heads/{NAME}")));
            assert!(!reads.can_read_path(&format!("refs/mirrors/{OWN}/{NAME}")));
        });
    }

    /// A collection ref of the collection id of the repository maps to the
    /// local path, and a ref of each other id maps to the mirror path. A pair
    /// that fails the rule fails the call with its label.
    #[test]
    fn a_collection_ref_of_the_own_id_maps_to_the_local_path() {
        let path = |own, id, name| ref_relpath(own, &Ref::collection(id, name));
        assert_eq!(
            path(Some(OWN), OWN, NAME).unwrap(),
            format!("refs/heads/{NAME}")
        );
        assert_eq!(
            path(Some(OWN), "org.example.Other", NAME).unwrap(),
            format!("refs/mirrors/org.example.Other/{NAME}")
        );
        assert_eq!(
            path(None, OWN, NAME).unwrap(),
            format!("refs/mirrors/{OWN}/{NAME}")
        );
        assert_eq!(
            ref_relpath(Some(OWN), &Ref::local(NAME)).unwrap(),
            format!("refs/heads/{NAME}")
        );
        assert_eq!(
            ref_relpath(Some(OWN), &Ref::remote("origin", NAME)).unwrap(),
            format!("refs/remotes/origin/{NAME}")
        );
        for name in ["../x", "origin:x"] {
            let err = path(Some(OWN), OWN, name).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidRefspec(label) if *label == format!("@{OWN}:{name}")),
                "{err:?}"
            );
        }
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
        let err = sync_dirs_all(&root.handle(), dirs).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidFormat(text) if text == "refs/heads/a/file is not a directory"),
            "{err:?}"
        );
        assert_eq!(test_syncs::count(&root.dir), before + 4);
    }

    /// A failed alias write leaves the directories that it made, and no temp
    /// entry in `tmp/`. A write below a file fails before a temp entry.
    #[test]
    fn a_failed_alias_write_leaves_no_temp_entry() {
        let root = Root::new("alias-failed");
        let handle = root.handle();
        std::fs::write(root.dir.join("refs/heads/file"), b"").unwrap();
        let mut dirs = Vec::new();
        let err = put_alias_blocking(
            &handle,
            "file/deep/alias",
            "refs/heads/file/deep/alias",
            "refs/heads/main",
            true,
            &mut dirs,
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::InvalidFormat(text) if text.ends_with("is not a directory")),
            "{err:?}"
        );
        assert!(dirs.is_empty());

        // An alias over a directory fails at the rename.
        std::fs::create_dir_all(root.dir.join("refs/heads/other/deep/alias/x")).unwrap();
        let err = put_alias_blocking(
            &handle,
            "other/deep/alias",
            "refs/heads/other/deep/alias",
            "refs/heads/main",
            true,
            &mut dirs,
        )
        .unwrap_err();
        assert!(matches!(&err, Error::Io(_)), "{err:?}");
        assert!(dirs.is_empty());
        assert_eq!(temp_entries(&root.dir), 0);
    }
}
