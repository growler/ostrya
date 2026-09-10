//! Reachability traversal and loose-object enumeration.
//!
//! [`Repo::list_objects`] enumerates every loose object present under
//! `objects/`. [`Repo::traverse_commit`] and [`Repo::traverse_reachable`] walk
//! the Merkle DAG from one or more commits, collecting the [`ObjectName`] of
//! every object reachable from them: the commit object, its root dirmeta, and
//! recursively each dirtree, subdirectory dirmeta, and file object, following
//! parent commits up to a caller-supplied depth. These are the primitives prune
//! and fsck build on.
//!
//! Depth follows the tool's observed semantics (recovered by running
//! `ostree prune --refs-only --depth=N`): `depth` is the number of parent
//! commits to follow. `depth = 0` keeps only the named commit; `depth = 1`
//! keeps it and its immediate parent; `depth = -1` follows the whole ancestry.
//!
//! Traversal is lenient about objects that are referenced but absent: a missing
//! object's name is still collected (it is a reachable reference), but a missing
//! or unparseable commit or dirtree cannot be descended into, so its children
//! are not enumerated. [`traverse_commit`](Repo::traverse_commit) is the one
//! exception: the commit the caller names must exist, else
//! [`Error::ObjectNotFound`] is returned.
//!
//! A walk follows two further edges under `GcRoots`, which
//! [`PruneOptions`](crate::PruneOptions) exposes. The commit `parent` edge is
//! optional, and any number of metadata keys name further commits: the value of
//! each configured key, in a commit's own metadata and in its detached
//! metadata, is an `aay` whose elements are commit checksums. Each such commit
//! is walked in turn, so a metadata-key edge reaches everything the commit it
//! names reaches. A commit arrived at this way is a root in its own right and
//! is given the walk's full depth, since depth counts parent hops.

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsFd, BorrowedFd};

use ostrya_core::{Checksum, Commit, ObjectName, ObjectType, Value};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::refs::walk_ref_dir;
use crate::repo::Repo;

/// The GVariant type a garbage-collection root metadata key holds: an array of
/// commit checksums in their 32-byte binary form.
const GC_ROOT_SIGNATURE: &str = "aay";

/// The edges a reachability walk follows out of a commit, beyond the objects its
/// tree names.
#[derive(Debug, Clone)]
pub(crate) struct GcRoots {
    /// Metadata keys whose value names further reachable commits. Empty
    /// configures the walk to read no metadata at all.
    pub metadata_keys: Vec<String>,
    /// Whether the commit `parent` edge is followed.
    pub traverse_parent: bool,
}

impl GcRoots {
    /// The plain ostree walk: the `parent` edge and no metadata-key edges.
    fn parents_only() -> GcRoots {
        GcRoots {
            metadata_keys: Vec::new(),
            traverse_parent: true,
        }
    }
}

impl Repo {
    /// Enumerate every loose object present under `objects/`.
    ///
    /// The `objects/<xx>/` fanout directories are scanned and each
    /// `<62hex>.<ext>` entry is parsed into an [`ObjectName`]. Entries whose
    /// name is not a valid loose object (a leftover `.tmp-` temporary, say) are
    /// skipped.
    pub async fn list_objects(&self) -> Result<HashSet<ObjectName>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || list_objects_blocking(repo.objects_fd())).await
    }

    /// Collect every object reachable from `commit`, following parent commits up
    /// to `max_depth` (`-1` for the whole ancestry). The named commit must
    /// exist; a parent that is absent stops that chain without error.
    pub async fn traverse_commit(
        &self,
        commit: &Checksum,
        max_depth: i32,
    ) -> Result<HashSet<ObjectName>> {
        if !self.has_object(ObjectType::Commit, commit).await? {
            return Err(Error::ObjectNotFound {
                checksum: *commit,
                ty: ObjectType::Commit,
            });
        }
        let mut reachable = HashSet::new();
        self.collect_reachable(
            vec![(*commit, max_depth)],
            max_depth,
            &GcRoots::parents_only(),
            None,
            &mut reachable,
        )
        .await?;
        Ok(reachable)
    }

    /// Collect every object reachable from any of `roots`, each followed to
    /// `max_depth` parents. Roots that are absent are skipped, so a dangling ref
    /// does not fail the walk.
    pub async fn traverse_reachable(
        &self,
        roots: impl IntoIterator<Item = Checksum>,
        max_depth: i32,
    ) -> Result<HashSet<ObjectName>> {
        self.traverse_reachable_gc(roots, max_depth, &GcRoots::parents_only(), None)
            .await
    }

    /// Collect every object reachable from any of `roots` under the edges `gc`
    /// names. This is [`traverse_reachable`](Repo::traverse_reachable) with the
    /// `parent` edge made optional and the metadata-key edges added.
    ///
    /// `pending_delete` names a commit the walk reads as absent. Prune unlinks
    /// the commit it deletes only once the walk has succeeded, and this keeps
    /// the walk's result the same as one run against the store the unlink
    /// leaves: the commit's own name is reachable, and nothing under it is.
    pub(crate) async fn traverse_reachable_gc(
        &self,
        roots: impl IntoIterator<Item = Checksum>,
        max_depth: i32,
        gc: &GcRoots,
        pending_delete: Option<Checksum>,
    ) -> Result<HashSet<ObjectName>> {
        let seeds = roots.into_iter().map(|c| (c, max_depth)).collect();
        let mut reachable = HashSet::new();
        self.collect_reachable(seeds, max_depth, gc, pending_delete, &mut reachable)
            .await?;
        Ok(reachable)
    }

    /// The shared reachability walk. `seeds` pairs each root commit with the
    /// number of parents still to follow (`-1` for unbounded). Names are added
    /// for every referenced object; recursion into a commit or dirtree needs the
    /// object to load, so an absent or corrupt one contributes its own name but
    /// none beneath it.
    ///
    /// A commit reached from more than one root is expanded at the deepest
    /// remaining depth any root gives it, so the reachable set does not depend on
    /// the order roots are supplied in: a commit already expanded at a depth that
    /// follows at least as many parents is skipped, otherwise it is expanded
    /// again to push its parent further back.
    ///
    /// `root_depth` is the walk's configured depth, which every commit a
    /// metadata-key edge names is seeded at. `pending_delete` names a commit
    /// that is read as absent.
    async fn collect_reachable(
        &self,
        seeds: Vec<(Checksum, i32)>,
        root_depth: i32,
        gc: &GcRoots,
        pending_delete: Option<Checksum>,
        reachable: &mut HashSet<ObjectName>,
    ) -> Result<()> {
        let mut commit_stack = seeds;
        let mut seen_commits: HashMap<Checksum, i32> = HashMap::new();
        let mut seen_dirtrees: HashSet<Checksum> = HashSet::new();

        while let Some((commit_checksum, depth)) = commit_stack.pop() {
            if let Some(&prev) = seen_commits.get(&commit_checksum)
                && reaches_at_least(prev, depth)
            {
                continue;
            }
            seen_commits.insert(commit_checksum, depth);
            reachable.insert(ObjectName::new(commit_checksum, ObjectType::Commit));

            if pending_delete == Some(commit_checksum) {
                continue;
            }
            let Some(commit) = self.try_load_commit(&commit_checksum).await? else {
                continue;
            };

            reachable.insert(ObjectName::new(commit.root_dirmeta, ObjectType::DirMeta));
            self.walk_tree(commit.root_dirtree, &mut seen_dirtrees, reachable)
                .await?;

            if !gc.metadata_keys.is_empty() {
                self.push_metadata_key_edges(
                    &commit_checksum,
                    &commit.metadata,
                    gc,
                    root_depth,
                    &mut commit_stack,
                )
                .await?;
            }

            if gc.traverse_parent
                && depth != 0
                && let Some(parent) = commit.parent
            {
                let next = if depth < 0 { -1 } else { depth - 1 };
                commit_stack.push((parent, next));
            }
        }
        Ok(())
    }

    /// Walk a dirtree subtree, collecting the name of every dirtree, dirmeta,
    /// and file reachable from it. A dirtree that cannot be loaded contributes
    /// its own name only.
    async fn walk_tree(
        &self,
        root_dirtree: Checksum,
        seen_dirtrees: &mut HashSet<Checksum>,
        reachable: &mut HashSet<ObjectName>,
    ) -> Result<()> {
        let mut stack = vec![root_dirtree];
        while let Some(dirtree_checksum) = stack.pop() {
            if !seen_dirtrees.insert(dirtree_checksum) {
                continue;
            }
            reachable.insert(ObjectName::new(dirtree_checksum, ObjectType::DirTree));

            let Some(dirtree) = self.try_load_dirtree(&dirtree_checksum).await? else {
                continue;
            };
            for (_, file_checksum) in dirtree.files {
                reachable.insert(ObjectName::new(file_checksum, ObjectType::File));
            }
            for (_, subtree, submeta) in dirtree.dirs {
                reachable.insert(ObjectName::new(submeta, ObjectType::DirMeta));
                stack.push(subtree);
            }
        }
        Ok(())
    }

    /// Push every commit the configured metadata keys name onto the walk.
    ///
    /// Each key is read from `metadata`, the commit's own, and then from its
    /// detached metadata, so one key name carries edges from both. A key no
    /// dict holds contributes nothing. A key that is present and does not hold
    /// an `aay` of 32-byte checksums fails the walk with
    /// [`Error::InvalidGcRoot`], because a value the walk cannot read is an
    /// edge it cannot follow, and objects would be deleted for it.
    ///
    /// The detached metadata is read once per expansion of a commit, and only
    /// for a walk that has metadata keys configured. A commit reached again at
    /// a depth that follows more parents is expanded a second time and read
    /// again.
    async fn push_metadata_key_edges(
        &self,
        commit: &Checksum,
        metadata: &Value,
        gc: &GcRoots,
        root_depth: i32,
        stack: &mut Vec<(Checksum, i32)>,
    ) -> Result<()> {
        let detached = self.read_commit_detached_metadata(commit).await?;
        for key in &gc.metadata_keys {
            for source in [Some(metadata), detached.as_ref()].into_iter().flatten() {
                let Some(value) = source.dict_get(key) else {
                    continue;
                };
                for target in metadata_key_targets(commit, key, value)? {
                    stack.push((target, root_depth));
                }
            }
        }
        Ok(())
    }

    /// Load and parse a commit, treating an absent object as `None` rather than
    /// an error, for the lenient traversal walk.
    async fn try_load_commit(&self, checksum: &Checksum) -> Result<Option<Commit>> {
        match self.load_object_bytes(ObjectType::Commit, checksum).await {
            Ok(bytes) => Ok(Some(Commit::parse(&bytes)?)),
            Err(Error::ObjectNotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Load and parse a dirtree, treating an absent object as `None`.
    async fn try_load_dirtree(&self, checksum: &Checksum) -> Result<Option<ostrya_core::DirTree>> {
        match self.load_dirtree(checksum).await {
            Ok(dirtree) => Ok(Some(dirtree)),
            Err(Error::ObjectNotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Collect the commit checksum every ref resolves to, across
    /// `refs/heads`, `refs/remotes`, and `refs/mirrors`. Used to seed prune and
    /// fsck with the set of refs' targets.
    pub(crate) async fn list_all_ref_targets(&self) -> Result<Vec<Checksum>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            let mut out = Vec::new();
            for top in ["refs/heads", "refs/remotes", "refs/mirrors"] {
                collect_ref_targets(repo.repo_fd(), top, &mut out)?;
            }
            Ok(out)
        })
        .await
    }
}

/// Read one metadata key's value as the list of commits it names.
///
/// The value is the variant an `a{sv}` entry holds. It has to carry an `aay`
/// whose every element is a 32-byte commit checksum; anything else is an
/// [`Error::InvalidGcRoot`] naming the commit the value came from.
fn metadata_key_targets(commit: &Checksum, key: &str, value: &Value) -> Result<Vec<Checksum>> {
    let invalid = |reason: String| Error::InvalidGcRoot {
        commit: *commit,
        metadata_key: key.to_owned(),
        reason,
    };
    let Some((ty, elements)) = value.as_variant() else {
        return Err(invalid("value is not a variant".into()));
    };
    let signature = ty.signature();
    if signature != GC_ROOT_SIGNATURE {
        return Err(invalid(format!(
            "type is `{signature}`, not `{GC_ROOT_SIGNATURE}`"
        )));
    }
    let Some(elements) = elements.as_array() else {
        return Err(invalid("value is not an array".into()));
    };
    let mut targets = Vec::with_capacity(elements.len());
    for (index, element) in elements.iter().enumerate() {
        let Some(bytes) = element.as_bytes() else {
            return Err(invalid(format!("element {index} is not a byte array")));
        };
        let checksum = Checksum::from_ay(bytes)
            .map_err(|_| invalid(format!("element {index} is {} bytes, not 32", bytes.len())))?;
        targets.push(checksum);
    }
    Ok(targets)
}

/// Whether a commit already expanded at remaining depth `prev` follows at least
/// as many parents as a fresh arrival at remaining depth `depth`. A negative
/// depth is unbounded and dominates any finite depth.
pub(crate) fn reaches_at_least(prev: i32, depth: i32) -> bool {
    if prev < 0 {
        true
    } else if depth < 0 {
        false
    } else {
        prev >= depth
    }
}

/// Enumerate loose objects under an `objects/` directory fd.
fn list_objects_blocking(objects_fd: BorrowedFd<'_>) -> Result<HashSet<ObjectName>> {
    let mut out = HashSet::new();
    for fanout in read_dir_names(objects_fd)? {
        // Object fanout directories are exactly two hex characters; anything
        // else under `objects/` (a stray file, a cache directory) is not a
        // loose-object fanout.
        if fanout.len() != 2 || !fanout.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let dir = match rustix::fs::openat(
            objects_fd,
            fanout.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => continue,
            Err(e) => return Err(Error::Io(e.into())),
        };
        for entry in read_dir_names(dir.as_fd())? {
            if let Some(name) = parse_object_entry(&fanout, &entry) {
                out.insert(name);
            }
        }
    }
    Ok(out)
}

/// Parse one `objects/<fanout>/<rest>.<ext>` entry into an [`ObjectName`], or
/// `None` when the name is not a valid loose object.
fn parse_object_entry(fanout: &str, entry: &str) -> Option<ObjectName> {
    let (rest, ext) = entry.rsplit_once('.')?;
    if rest.len() != 62 {
        return None;
    }
    let ty = ObjectType::from_extension(ext)?;
    let mut hex = String::with_capacity(64);
    hex.push_str(fanout);
    hex.push_str(rest);
    let checksum = Checksum::from_hex(&hex).ok()?;
    Some(ObjectName::new(checksum, ty))
}

/// Read the entry names of an open directory, skipping `.` and `..`.
pub(crate) fn read_dir_names(dir: BorrowedFd<'_>) -> Result<Vec<String>> {
    let reader = rustix::fs::Dir::read_from(dir).map_err(|e| Error::Io(e.into()))?;
    let mut names = Vec::new();
    for entry in reader {
        let entry = entry.map_err(|e| Error::Io(e.into()))?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        // Object and fanout names are ASCII and a ref name is UTF-8; anything
        // else is neither a loose object nor a ref.
        if let Ok(name) = std::str::from_utf8(bytes) {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

/// Recursively collect the checksum each ref file under `top` resolves to,
/// following the `refs/` subtree. Alias symlinks are followed; a dangling one is
/// skipped. Names are not retained -- only the target checksums.
fn collect_ref_targets(repo_fd: BorrowedFd<'_>, top: &str, out: &mut Vec<Checksum>) -> Result<()> {
    let dir = match rustix::fs::openat(
        repo_fd,
        top,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(()),
        Err(e) => return Err(Error::Io(e.into())),
    };
    walk_ref_dir(dir.as_fd(), "", &mut |entry| {
        if let Some(checksum) = read_ref_target(entry.dir, entry.name)? {
            out.push(checksum);
        }
        Ok(())
    })
}

/// The largest ref file the reader will load; a ref is 65 bytes.
const REF_READ_CAP: u64 = 4096;

/// Read a ref file's target checksum relative to `dir`, following alias
/// symlinks; `None` when the file is absent.
fn read_ref_target(dir: BorrowedFd<'_>, name: &str) -> Result<Option<Checksum>> {
    use std::io::Read;
    let fd = match rustix::fs::openat(dir, name, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(Error::Io(e.into())),
    };
    let mut buf = Vec::new();
    std::fs::File::from(fd)
        .take(REF_READ_CAP)
        .read_to_end(&mut buf)
        .map_err(Error::Io)?;
    let text = std::str::from_utf8(&buf)
        .map_err(|_| Error::InvalidFormat("ref content is not valid UTF-8".into()))?;
    Ok(Some(Checksum::from_hex(text.trim())?))
}
