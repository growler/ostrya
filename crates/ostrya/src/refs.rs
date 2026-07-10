//! Ref resolution and listing.
//!
//! A ref is a loose file under `refs/` holding a 64-char hex checksum and a
//! trailing newline. A local ref `name` maps to `refs/heads/name`; a refspec
//! `remote:name` maps to `refs/remotes/remote/name`. A ref may be a relative
//! symlink aliasing another ref; opening follows the link and reads the target
//! ref's checksum. Refspec components are validated to keep resolution inside
//! the `refs/` tree.

use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};

use ostrya_core::Checksum;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::repo::Repo;

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
