//! The `.tombstone-commit` marker and the one call that writes it.
//!
//! Two commands write the marker. A prune writes it for every commit it removes
//! where the command line carries `--delete-commit` or the repository config
//! sets `[core] tombstone-commits`. An `fsck --add-tombstones` writes it for
//! every commit whose parent commit object is absent, removing that commit
//! object in the same step. The bytes are the same at both sites and are
//! recorded in `docs/format-reference.md`, "Object types".

use std::os::fd::BorrowedFd;

use ostrya_core::{Checksum, DictBuilder, ObjectType, RepoMode, Type, loose_path, to_bytes};

use crate::error::Result;

/// The GVariant type a `.tombstone-commit` object holds.
const TOMBSTONE_SIGNATURE: &str = "a{sv}";
/// The one key a `.tombstone-commit` dict carries.
const TOMBSTONE_KEY: &str = "commit";

/// Write the `.tombstone-commit` marker naming `commit`.
///
/// The object is the `a{sv}` holding one `commit` key whose `ay` value is the
/// commit checksum in lowercase hex, NUL-terminated
/// (`docs/format-reference.md`, "Object types").
pub(crate) fn write_tombstone(
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
    crate::commit::write_detached_blocking(objects_fd, &dest, &bytes, fsync, mode)
}
