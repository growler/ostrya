//! The `.tombstone-commit` marker and the one function that writes it.
//!
//! A `.tombstone-commit` object marks a deleted commit. Two operations write
//! the marker, and both write the same bytes:
//!
//! - A prune writes it for each commit that it removes, if the run has
//!   `--delete-commit` or the repository config sets
//!   `[core] tombstone-commits`.
//! - `fsck --add-tombstones` writes it for each commit whose parent commit
//!   object is absent. The same step removes that commit object.

use std::os::fd::BorrowedFd;

use ostrya_core::{Checksum, DictBuilder, ObjectType, RepoMode, Type, loose_path, to_bytes};

use crate::error::Result;

/// The GVariant type that a `.tombstone-commit` object holds.
const TOMBSTONE_SIGNATURE: &str = "a{sv}";
/// The one key that a `.tombstone-commit` dict carries.
const TOMBSTONE_KEY: &str = "commit";

/// Writes the `.tombstone-commit` marker that names `commit`.
///
/// The object is an `a{sv}` with one key, `commit`. Its `ay` value is the
/// commit checksum in lowercase hex, with a NUL terminator. `tmp_fd` is the
/// open `tmp/` of the repository, where the write creates its temp file.
pub(crate) fn write_tombstone(
    tmp_fd: BorrowedFd<'_>,
    objects_fd: BorrowedFd<'_>,
    commit: &Checksum,
    mode: RepoMode,
    fsync: bool,
) -> Result<()> {
    let mut payload = commit.to_hex().into_bytes();
    payload.push(0);
    let mut builder = DictBuilder::new();
    builder.insert_bytes(TOMBSTONE_KEY, &payload);
    let ty = Type::parse(TOMBSTONE_SIGNATURE).map_err(ostrya_core::Error::from)?;
    let bytes = to_bytes(&ty, &builder.build()).map_err(ostrya_core::Error::from)?;
    let dest = loose_path(commit, ObjectType::TombstoneCommit, mode);
    crate::commit::write_detached_blocking(tmp_fd, objects_fd, &dest, &bytes, fsync, mode)
}
