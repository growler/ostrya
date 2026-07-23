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

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsFd, BorrowedFd};

use ostrya_core::{Checksum, Commit, ObjectName, ObjectType};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::repo::Repo;

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
        self.collect_reachable(vec![(*commit, max_depth)], &mut reachable)
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
        let seeds = roots.into_iter().map(|c| (c, max_depth)).collect();
        let mut reachable = HashSet::new();
        self.collect_reachable(seeds, &mut reachable).await?;
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
    async fn collect_reachable(
        &self,
        seeds: Vec<(Checksum, i32)>,
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

            let Some(commit) = self.try_load_commit(&commit_checksum).await? else {
                continue;
            };

            reachable.insert(ObjectName::new(commit.root_dirmeta, ObjectType::DirMeta));
            self.walk_tree(commit.root_dirtree, &mut seen_dirtrees, reachable)
                .await?;

            if depth != 0
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

/// Whether a commit already expanded at remaining depth `prev` follows at least
/// as many parents as a fresh arrival at remaining depth `depth`. A negative
/// depth is unbounded and dominates any finite depth.
fn reaches_at_least(prev: i32, depth: i32) -> bool {
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
fn read_dir_names(dir: BorrowedFd<'_>) -> Result<Vec<String>> {
    let reader = rustix::fs::Dir::read_from(dir).map_err(|e| Error::Io(e.into()))?;
    let mut names = Vec::new();
    for entry in reader {
        let entry = entry.map_err(|e| Error::Io(e.into()))?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        // Object and fanout names are ASCII; anything else is not a loose
        // object.
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
    walk_ref_targets(dir.as_fd(), out)
}

/// Walk an open `refs/` subdirectory, recursing into subdirectories and reading
/// each ref file's target checksum.
fn walk_ref_targets(dir: BorrowedFd<'_>, out: &mut Vec<Checksum>) -> Result<()> {
    for name in read_dir_names(dir)? {
        let stat = match rustix::fs::statat(dir, name.as_str(), AtFlags::empty()) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => continue, // dangling alias
            Err(e) => return Err(Error::Io(e.into())),
        };
        if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            let sub = rustix::fs::openat(
                dir,
                name.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| Error::Io(e.into()))?;
            walk_ref_targets(sub.as_fd(), out)?;
        } else if let Some(checksum) = read_ref_target(dir, name.as_str())? {
            out.push(checksum);
        }
    }
    Ok(())
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
