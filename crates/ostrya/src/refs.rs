//! Ref resolution, listing, and writing.
//!
//! A ref is a loose file under `refs/` holding a 64-char hex checksum and a
//! trailing newline (65 bytes). A local ref `name` maps to `refs/heads/name`; a
//! refspec `remote:name` maps to `refs/remotes/remote/name`; a collection ref
//! maps to `refs/mirrors/collection/name`. A ref may be a relative symlink
//! aliasing another ref; opening follows the link and reads the target ref's
//! checksum. Refspec components are validated to keep resolution inside the
//! `refs/` tree.
//!
//! Writes are individually atomic -- a fresh file written, `fdatasync`-ed when
//! fsync is enabled, and renamed over the target, with the parent directories
//! created for a `/`-bearing name. A `None` checksum removes the ref file. A
//! transaction queues its ref writes with [`Transaction::set_ref`] and applies
//! them at commit after object publication;
//! [`Repo::set_ref_immediate`](Repo::set_ref_immediate) writes one outside a
//! transaction.

use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use ostrya_core::Checksum;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::transaction::Transaction;

/// A collection-qualified ref: a ref name optionally bound to a collection id.
///
/// A ref with a collection id maps to `refs/mirrors/<collection>/<name>`; one
/// without maps to a local `refs/heads/<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionRef {
    /// The collection id, or `None` for a local ref.
    pub collection_id: Option<String>,
    /// The ref name, which may contain `/`.
    pub ref_name: String,
}

impl CollectionRef {
    /// A ref bound to a collection id.
    pub fn new(collection_id: impl Into<String>, ref_name: impl Into<String>) -> CollectionRef {
        CollectionRef {
            collection_id: Some(collection_id.into()),
            ref_name: ref_name.into(),
        }
    }

    /// A local ref with no collection id.
    pub fn local(ref_name: impl Into<String>) -> CollectionRef {
        CollectionRef {
            collection_id: None,
            ref_name: ref_name.into(),
        }
    }
}

/// A queued ref target: either a refspec or a collection ref.
enum QueuedRef {
    Ref(String),
    Collection(CollectionRef),
}

impl QueuedRef {
    /// The path under `refs/` this target writes to, rejecting a name that
    /// would escape the tree.
    fn relpath(&self) -> Result<String> {
        match self {
            QueuedRef::Ref(refspec) => refspec_to_relpath(refspec),
            QueuedRef::Collection(cref) => collection_ref_to_relpath(cref),
        }
    }
}

/// One queued ref write: a target and the checksum to point it at (`None`
/// removes the ref).
pub(crate) struct RefWrite {
    target: QueuedRef,
    checksum: Option<Checksum>,
}

impl Transaction {
    /// Queue a refspec-to-checksum write, applied at
    /// [`commit`](Transaction::commit) after object publication. A `None`
    /// checksum queues the ref's removal. The refspec is validated at commit,
    /// before any object is published.
    pub fn set_ref(&self, refspec: &str, checksum: Option<&Checksum>) {
        self.refs.lock().unwrap().push(RefWrite {
            target: QueuedRef::Ref(refspec.to_owned()),
            checksum: checksum.copied(),
        });
    }

    /// Queue a collection-ref write, applied at
    /// [`commit`](Transaction::commit). A `None` checksum queues the ref's
    /// removal.
    pub fn set_collection_ref(&self, cref: &CollectionRef, checksum: Option<&Checksum>) {
        self.refs.lock().unwrap().push(RefWrite {
            target: QueuedRef::Collection(cref.clone()),
            checksum: checksum.copied(),
        });
    }

    /// Map every queued ref to its path under `refs/`, failing on a malformed
    /// refspec. Called at the start of [`commit`](Transaction::commit) so a bad
    /// refspec fails before any object is published.
    pub(crate) fn resolve_ref_queue(&self) -> Result<Vec<(String, Option<Checksum>)>> {
        let queue = self.refs.lock().unwrap();
        queue
            .iter()
            .map(|w| Ok((w.target.relpath()?, w.checksum)))
            .collect()
    }

    /// Write the resolved refs on the blocking pool, each atomically.
    pub(crate) async fn write_resolved_refs(
        &self,
        refs: &[(String, Option<Checksum>)],
    ) -> Result<()> {
        if refs.is_empty() {
            return Ok(());
        }
        let fsync = self.repo().config().fsync()?;
        let repo_fd = self.repo().repo_fd().try_clone_to_owned()?;
        let refs = refs.to_vec();
        ostrya_rt::unblock(move || {
            for (relpath, checksum) in &refs {
                write_ref_blocking(repo_fd.as_fd(), relpath, *checksum, fsync)?;
            }
            Ok(())
        })
        .await
    }
}

/// The largest ref file the reader will load; a ref is 65 bytes.
const REF_READ_CAP: u64 = 4096;

impl Repo {
    /// Resolve a refspec or a bare commit checksum to a commit id. A 64-char
    /// hex string resolves to itself. When the refspec names no ref,
    /// `allow_noent` chooses between `Ok(None)` and [`Error::RefNotFound`].
    pub async fn resolve_rev(&self, refspec: &str, allow_noent: bool) -> Result<Option<Checksum>> {
        if refspec.len() == 64
            && let Ok(checksum) = Checksum::from_hex(refspec)
        {
            return Ok(Some(checksum));
        }

        let relpath = refspec_to_relpath(refspec)?;
        let repo = self.clone();
        let bytes = ostrya_rt::unblock(move || read_ref_file(repo.repo_fd(), &relpath)).await?;
        match bytes {
            Some(bytes) => Ok(Some(parse_ref_content(&bytes)?)),
            None if allow_noent => Ok(None),
            None => Err(Error::RefNotFound(refspec.to_owned())),
        }
    }

    /// List local refs (under `refs/heads`) as (name, commit) pairs, sorted by
    /// name. `prefix`, when given, keeps only the ref equal to it or nested
    /// under it.
    pub async fn list_refs(&self, prefix: Option<&str>) -> Result<Vec<(String, Checksum)>> {
        let repo = self.clone();
        let mut refs = ostrya_rt::unblock(move || collect_heads(&repo)).await?;
        if let Some(prefix) = prefix {
            let nested = format!("{prefix}/");
            refs.retain(|(name, _)| name == prefix || name.starts_with(&nested));
        }
        refs.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(refs)
    }

    /// List collection-mirror refs (under `refs/mirrors`) as
    /// `(collection_id, ref_name, commit)` triples. The first path component
    /// under `refs/mirrors` is the collection id; the remainder is the ref
    /// name, which may contain `/`. Results are unsorted; callers that need a
    /// stable order sort them.
    pub async fn list_mirror_refs(&self) -> Result<Vec<(String, String, Checksum)>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || collect_mirrors(&repo)).await
    }

    /// Write one ref outside a transaction, atomically. A `None` checksum
    /// removes the ref file. The write follows the same tmpfile, `fdatasync`,
    /// rename sequence a transaction uses, honoring `[core] fsync`.
    pub async fn set_ref_immediate(
        &self,
        refspec: &str,
        checksum: Option<&Checksum>,
    ) -> Result<()> {
        let relpath = refspec_to_relpath(refspec)?;
        let fsync = self.config().fsync()?;
        let checksum = checksum.copied();
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || write_ref_blocking(repo_fd.as_fd(), &relpath, checksum, fsync))
            .await
    }
}

/// Collect every ref under `refs/heads`, walking subdirectories.
fn collect_heads(repo: &Repo) -> Result<Vec<(String, Checksum)>> {
    let heads = match rustix::fs::openat(
        repo.repo_fd(),
        "refs/heads",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e.into())),
    };
    let mut out = Vec::new();
    walk_refs(heads, "", &mut out)?;
    Ok(out)
}

/// Collect every ref under `refs/mirrors`, splitting each into its collection
/// id (the first path component) and ref name (the remainder).
fn collect_mirrors(repo: &Repo) -> Result<Vec<(String, String, Checksum)>> {
    let mirrors = match rustix::fs::openat(
        repo.repo_fd(),
        "refs/mirrors",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e.into())),
    };
    let mut walked = Vec::new();
    walk_refs(mirrors, "", &mut walked)?;
    let mut out = Vec::with_capacity(walked.len());
    for (path, checksum) in walked {
        // A mirror ref is <collection>/<ref>; the collection id is a single
        // component, the ref name is everything after the first slash.
        let Some((collection, ref_name)) = path.split_once('/') else {
            // A file directly under refs/mirrors has no collection component;
            // ignore it, matching the tool's collection-qualified layout.
            continue;
        };
        out.push((collection.to_owned(), ref_name.to_owned(), checksum));
    }
    Ok(out)
}

/// Recursively collect refs under an open directory, prefixing names with the
/// path walked so far.
fn walk_refs(dir: OwnedFd, prefix: &str, out: &mut Vec<(String, Checksum)>) -> Result<()> {
    // DirEntry borrows the Dir, so gather names before touching `dir` again.
    let mut names: Vec<Vec<u8>> = Vec::new();
    let reader = rustix::fs::Dir::read_from(&dir).map_err(|e| Error::Io(e.into()))?;
    for entry in reader {
        let entry = entry.map_err(|e| Error::Io(e.into()))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.push(name.to_vec());
    }

    for name_bytes in names {
        let Ok(name) = std::str::from_utf8(&name_bytes) else {
            // Ref names are UTF-8; skip anything else.
            continue;
        };
        // Follow symlinks so a ref alias resolves to the directory or file it
        // points at.
        let stat = match rustix::fs::statat(&dir, name, AtFlags::empty()) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => continue, // dangling alias
            Err(e) => return Err(Error::Io(e.into())),
        };
        let child = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            let sub = rustix::fs::openat(
                &dir,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| Error::Io(e.into()))?;
            walk_refs(sub, &child, out)?;
        } else if let Some(bytes) = read_ref_file(dir.as_fd(), name)? {
            out.push((child, parse_ref_content(&bytes)?));
        }
    }
    Ok(())
}

/// Read a ref file relative to `dir`, following alias symlinks. `None` when the
/// file does not exist.
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
    let mut buf = Vec::new();
    std::fs::File::from(fd)
        .take(REF_READ_CAP)
        .read_to_end(&mut buf)?;
    Ok(Some(buf))
}

/// Parse a ref file's content: a hex checksum with trailing whitespace.
fn parse_ref_content(bytes: &[u8]) -> Result<Checksum> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::InvalidFormat("ref content is not valid UTF-8".into()))?;
    Ok(Checksum::from_hex(text.trim())?)
}

/// Map a refspec to its path under `refs/`, rejecting anything that would
/// escape the tree.
fn refspec_to_relpath(refspec: &str) -> Result<String> {
    if let Some((remote, name)) = refspec.split_once(':') {
        check_component(remote)?;
        check_ref_path(name)?;
        Ok(format!("refs/remotes/{remote}/{name}"))
    } else {
        check_ref_path(refspec)?;
        Ok(format!("refs/heads/{refspec}"))
    }
}

/// A ref name may contain `/` but no empty, `.`, or `..` components, and no
/// interior NUL.
fn check_ref_path(name: &str) -> Result<()> {
    if name.is_empty() || name.contains('\0') {
        return Err(Error::InvalidFormat(format!("invalid refspec '{name}'")));
    }
    for component in name.split('/') {
        check_component(component)?;
    }
    Ok(())
}

/// A single path component: non-empty, not a traversal, no slash or NUL.
fn check_component(component: &str) -> Result<()> {
    if component.is_empty() || component == "." || component == ".." || component.contains('\0') {
        return Err(Error::InvalidFormat(format!(
            "invalid refspec component '{component}'"
        )));
    }
    Ok(())
}

/// Map a collection ref to its path under `refs/`. A collection id places the
/// ref under `refs/mirrors/<collection>/`; a `None` id is a local
/// `refs/heads/` ref. The collection id is a single component (dots allowed, no
/// slash or traversal).
fn collection_ref_to_relpath(cref: &CollectionRef) -> Result<String> {
    check_ref_path(&cref.ref_name)?;
    match &cref.collection_id {
        Some(collection_id) => {
            check_component(collection_id)?;
            Ok(format!("refs/mirrors/{collection_id}/{}", cref.ref_name))
        }
        None => Ok(format!("refs/heads/{}", cref.ref_name)),
    }
}

/// The permission bits forced on a ref file, independent of the umask, matching
/// the tool's `0644` ref files.
const REF_FILE_MODE: u32 = 0o644;
/// The request mode for a created ref parent directory, reduced by the umask
/// (the tool's ref subdirectories are `0755` under a `022` umask). A
/// group-shared repository is arranged at the filesystem level, not here: an
/// operator sets the repository directory `2775` with a default group ACL
/// (`setfacl -d -m g::rwx`) before `init`, and the OS propagates the setgid bit
/// and group permissions to every directory created underneath, refs included.
const REF_DIR_MODE: u32 = 0o777;

/// Write or remove one ref file relative to `repo_fd`, atomically.
///
/// `Some(checksum)` writes the 65-byte `<hex>\n` content to a fresh temp file
/// in the target's parent directory (created as needed), `fdatasync`-es it when
/// `fsync` is set, and renames it over the target. `None` unlinks the ref,
/// treating an already-absent file as success.
fn write_ref_blocking(
    repo_fd: BorrowedFd<'_>,
    relpath: &str,
    checksum: Option<Checksum>,
    fsync: bool,
) -> Result<()> {
    let Some(checksum) = checksum else {
        return match rustix::fs::unlinkat(repo_fd, relpath, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(e) => Err(e.into()),
        };
    };

    create_ref_parents(repo_fd, relpath)?;
    let content = format!("{}\n", checksum.to_hex());
    let tmp = format!(
        "{relpath}.tmp-{}-{}",
        std::process::id(),
        crate::write::unique()
    );
    let fd = rustix::fs::openat(
        repo_fd,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(REF_FILE_MODE),
    )?;
    let write_and_rename = || -> Result<()> {
        let mut file = std::fs::File::from(fd);
        file.write_all(content.as_bytes())?;
        file.flush()?;
        rustix::fs::fchmod(file.as_fd(), Mode::from_raw_mode(REF_FILE_MODE))?;
        if fsync {
            rustix::fs::fdatasync(file.as_fd())?;
        }
        drop(file);
        rustix::fs::renameat(repo_fd, tmp.as_str(), repo_fd, relpath)?;
        Ok(())
    };
    write_and_rename().inspect_err(|_| {
        let _ = rustix::fs::unlinkat(repo_fd, tmp.as_str(), AtFlags::empty());
    })
}

/// Create the parent directories of a ref path, idempotently. Every component
/// but the last is created; existing directories are left in place.
fn create_ref_parents(repo_fd: BorrowedFd<'_>, relpath: &str) -> Result<()> {
    let mut acc = String::new();
    let mut components: Vec<&str> = relpath.split('/').collect();
    components.pop(); // the final component is the ref file itself
    for component in components {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(component);
        match rustix::fs::mkdirat(repo_fd, acc.as_str(), Mode::from_raw_mode(REF_DIR_MODE)) {
            Ok(()) | Err(Errno::EXIST) => {}
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
        for bad in ["", "..", "a/../b", "/a", "a/", "a//b", "a/.."] {
            assert!(refspec_to_relpath(bad).is_err(), "should reject {bad:?}");
        }
        assert!(refspec_to_relpath("origin:../escape").is_err());
    }

    #[test]
    fn parses_ref_content_with_newline() {
        let hex = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";
        let checksum = parse_ref_content(format!("{hex}\n").as_bytes()).unwrap();
        assert_eq!(checksum.to_hex(), hex);
        assert!(parse_ref_content(b"not-a-checksum\n").is_err());
    }
}
