//! Static-delta reading and offline application (Phase 15a), and the reading a
//! delta-accelerated pull does over the network (Phase 16d).
//!
//! A static delta is a compact description of the objects that make up a target
//! commit, optionally expressed as a patch against a source commit. The format
//! this module reads was recovered by observing the `ostree` tool as a black box
//! (see `format-reference.md`, "Static delta wire format"). This module reads a
//! delta -- one the tool wrote or one [`crate::deltagen`] wrote -- and applies it
//! offline, producing the target commit's objects into the repository.
//!
//! A delta directory holds a `superblock` and numbered part files `0`, `1`, ...
//! The superblock is a GVariant listing the target commit (embedded whole),
//! per-part checksums and object lists, and any fallback objects; each part is a
//! compressed GVariant carrying a mode table, an xattr table, a data-source
//! blob, and an operation stream. Applying a part runs the operation stream
//! against the data source and the source commit's objects, and every produced
//! object's checksum is asserted as it is written, so a malformed or misapplied
//! delta fails rather than storing a wrong object.
//!
//! Application is memory-bounded, and a part is checked before it is expanded.
//! The part file is taken in under the size its meta-entry declares and hashed
//! against the checksum that entry names; the verified bytes then decompress
//! through `async-compression`'s xz codec into the payload the operations read.
//! Each blob stays on the heap at or below [`MMAP_THRESHOLD`] and is spilled to a
//! read-only mmapped temp file above it, so a large part costs address space and
//! staging space rather than resident heap, and a body that passes its declared
//! size never reaches the decoder. Splice and bspatch output streams through the
//! transaction's content writer, and a bspatch source object is spilled to a temp
//! file the same way, so no whole object is materialized.
//!
//! Signed deltas wrap the superblock in a magic-prefixed envelope carrying the
//! detached signatures; [`Repo::verify_static_delta`] checks them with the
//! Phase 13 signing engines over the raw superblock bytes, and
//! [`DeltaSuperblock::verify`] does the same for a superblock file read under
//! any name.
//!
//! An HTTP pull reads a delta through the same superblock parse and part
//! application, over a fetched response body rather than a part file, and applies
//! it into the pull's own transaction.
//!
//! [`DeltaSuperblock::part_stats`] reads what a part holds -- the table counts,
//! the blob and operation-stream sizes, and the count of each opcode -- without
//! applying it. It needs no transaction and no staging directory, so a
//! read-only repository can report a delta. The payload framing sits at the end
//! of the payload, so the part is read in up to three passes: one that verifies
//! the part against its meta-entry with no byte decompressed, one that finds the
//! framing and keeps the payload's last 1 MiB, and, where that tail does not
//! hold the operations and the xattr framing, one that reads them. Each pass
//! holds one fixed-size buffer and the tail, and a compressed pass holds the xz
//! decoder's state under a 128 MiB limit, whatever the payload size.

use std::ffi::{CStr, CString};
use std::io::{self, SeekFrom};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use async_compression::futures::bufread::XzDecoder;
use futures_io::{AsyncRead, AsyncSeek, AsyncWrite};
use futures_lite::io::{BufReader, Cursor};
use futures_lite::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use ostrya_core::{
    ArrayIter, Checksum, GvDecode, ObjectType, Type, Value, Xattrs, from_bytes, offset_size_for,
    to_bytes, varint,
};
use ostrya_rt::File as RtFile;
use sha2::{Digest, Sha256};

use crate::bspatch::bspatch;
use crate::error::{Error, Result};
use crate::hashing::HashingReader;
use crate::pull::{ModeChecks, PullFlags};
use crate::repo::Repo;
use crate::sign::{Verifier, VerifyOutcome, signatures_for};
use crate::transaction::Transaction;
use crate::write::{ContentWriter, FileMeta};

/// The superblock GVariant type: metadata, timestamp, from/to checksums, the
/// embedded target commit, an (always empty) recursion array, the per-part
/// meta-entry array, and the fallback array.
pub(crate) const SUPERBLOCK_SIG: &str = "(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))";
/// The signed-delta envelope type: magic, raw superblock bytes, signatures.
pub(crate) const SIGNED_SIG: &str = "(taya{sv})";
/// The commit object type, used to re-serialize the embedded target commit.
pub(crate) const COMMIT_SIG: &str = "(a{sv}aya(say)sstayay)";
/// The signed-delta magic. Stored as the eight ASCII bytes "OSTSGNDT".
pub(crate) const SIGNED_MAGIC: &[u8; 8] = b"OSTSGNDT";

/// The superblock metadata key stating the byte order of its host-order fields.
pub(crate) const ENDIANNESS_KEY: &str = "ostree.endianness";
/// The little-endian marker the `ostree.endianness` byte carries.
pub(crate) const ENDIANNESS_LITTLE: u8 = b'l';
/// The big-endian marker the `ostree.endianness` byte carries.
pub(crate) const ENDIANNESS_BIG: u8 = b'B';

/// No compression: the part body is the payload verbatim.
const COMPRESSION_NONE: u8 = 0;
/// xz compression: the part body is a standard `.xz` stream.
pub(crate) const COMPRESSION_XZ: u8 = b'x';

pub(crate) const OP_OPEN_SPLICE_CLOSE: u8 = b'S';
pub(crate) const OP_OPEN: u8 = b'o';
pub(crate) const OP_WRITE: u8 = b'w';
pub(crate) const OP_SET_READ_SOURCE: u8 = b'r';
pub(crate) const OP_UNSET_READ_SOURCE: u8 = b'R';
pub(crate) const OP_CLOSE: u8 = b'c';
pub(crate) const OP_BSPATCH: u8 = b'B';

/// The file-type mask of an `st_mode`.
const S_IFMT: u32 = 0o170000;
/// The symlink file-type bits.
const S_IFLNK: u32 = 0o120000;

/// The largest superblock accepted. The superblock is read whole onto the heap,
/// since it is parsed as one GVariant tree, so it is capped at the metadata
/// ceiling: it holds the embedded target commit (a metadata object) plus the
/// per-part and fallback tables, all bounded metadata.
pub(crate) const MAX_SUPERBLOCK: u64 = crate::object::MAX_METADATA_SIZE;

/// A decompressed part payload or source object at or below this size is kept on
/// the heap; a larger one is spilled to a temp file and read-only mmapped, so it
/// costs address space and demand-paged file cache rather than resident heap.
pub(crate) const MMAP_THRESHOLD: usize = 128 * 1024;

/// The chunk size for streaming object payloads to and from disk.
pub(crate) const IO_CHUNK: usize = 128 * 1024;

/// The largest combined heap footprint accepted for a part's mode and xattr
/// tables. They are bounded metadata, so they are collected onto the heap and
/// capped at the metadata ceiling, turning a hostile table size into a
/// bounded-size failure rather than an unbounded copy.
pub(crate) const MAX_TABLE_BYTES: usize = crate::object::MAX_METADATA_SIZE as usize;

/// The zero-copy view of a decompressed part payload
/// `(a(uuu) aa(ayay) ay ay)`: the mode table, the xattr table, the data-source
/// blob, and the operation stream. The two trailing byte arrays borrow the
/// backing payload rather than copying it.
type PartView<'a> = (
    ArrayIter<'a, (u32, u32, u32)>,
    ArrayIter<'a, ArrayIter<'a, (&'a [u8], &'a [u8])>>,
    &'a [u8],
    &'a [u8],
);

/// A parsed static-delta superblock: the fields `static-delta show` reports and
/// what application reads.
///
/// [`DeltaSuperblock::read`] takes a superblock file, signed or not, and
/// [`DeltaSuperblock::part_stats`] reads what one part payload holds without
/// applying it.
#[derive(Debug)]
pub struct DeltaSuperblock {
    /// The source commit checksum, `None` for a from-scratch delta.
    pub(crate) from: Option<Checksum>,
    /// The target commit checksum.
    pub(crate) to: Checksum,
    /// The normal-form bytes of the embedded target commit object.
    pub(crate) commit_bytes: Vec<u8>,
    /// The per-part meta-entries, in part order.
    pub(crate) meta_entries: Vec<DeltaPart>,
    /// The fallback objects the delta references but does not carry.
    pub(crate) fallbacks: Vec<DeltaFallback>,
    /// The detached signatures when the delta is signed.
    pub(crate) signatures: Option<Value>,
    /// The raw superblock bytes: the payload signatures cover. Empty for an
    /// unsigned superblock, which no signature check reads.
    pub(crate) superblock_bytes: Vec<u8>,
    /// The leading `a{sv}`: `ostree.endianness`, a copy of the target commit's
    /// detached metadata, and any part carried inline.
    pub(crate) metadata: Value,
    /// For each meta-entry, in part order, the position in `metadata` of the
    /// entry that carries the part inline, from [`index_inline_parts`].
    pub(crate) inline_index: Vec<Option<usize>>,
    /// Field 1, converted from big-endian.
    pub(crate) timestamp: u64,
    /// The byte length of field 5, the recursion `ay`.
    pub(crate) recursion_len: usize,
}

/// One part's meta-entry: its part-file checksum, the part file's size, the
/// size of what the part delivers, and the ordered list of objects the part
/// produces.
#[derive(Debug, Clone)]
pub struct DeltaPart {
    pub(crate) part_csum: Checksum,
    /// The part file's on-disk size, the compression byte included. It bounds
    /// what a part fetch takes off the connection and what a part read takes in
    /// before the checksum above is asserted.
    pub(crate) size: u64,
    /// The `usize` field: what the part's objects add up to.
    pub(crate) uncompressed_size: u64,
    pub(crate) objects: Vec<(ObjectType, Checksum)>,
}

impl DeltaPart {
    /// The SHA-256 of the part file, the compression byte included.
    pub fn checksum(&self) -> &Checksum {
        &self.part_csum
    }

    /// The part file's size in bytes, the compression byte included.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The `usize` field: the sum of the sizes of the objects the part
    /// delivers, as its producer wrote it.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// The objects the part produces, in the order its operations produce them.
    pub fn objects(&self) -> &[(ObjectType, Checksum)] {
        &self.objects
    }
}

/// A fallback object: one delivered outside the parts (as a plain loose object).
#[derive(Debug, Clone)]
pub struct DeltaFallback {
    pub(crate) objtype: ObjectType,
    pub(crate) checksum: Checksum,
    /// The loose object's size in the producing repository.
    pub(crate) size: u64,
    /// The object's content size.
    pub(crate) uncompressed_size: u64,
}

impl DeltaFallback {
    /// The fallback object's type.
    pub fn object_type(&self) -> ObjectType {
        self.objtype
    }

    /// The fallback object's checksum.
    pub fn checksum(&self) -> &Checksum {
        &self.checksum
    }

    /// The compressed size field: the loose object's size in the repository
    /// that produced the delta.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The uncompressed size field: the object's content size.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }
}

/// The byte order the `ostree.endianness` byte declares for the host-order
/// fields of a superblock: a meta-entry's `size` and `usize`, and a fallback's
/// two sizes. A superblock carrying no such byte, or any byte other than `B`,
/// reads as little-endian. [`DeltaOptions::endianness`](crate::DeltaOptions)
/// selects the order the generator writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaEndianness {
    /// Read: the byte is `l`, absent, or another value. Write: the byte `l`,
    /// and the four fields little-endian.
    Little,
    /// Read: the byte is `B`. Write: the byte `B`, and the four fields
    /// big-endian.
    Big,
}

/// What one part payload holds, read without applying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaPartStats {
    /// The number of entries of the mode table.
    pub modes: u64,
    /// The number of entries of the xattr table.
    pub xattrs: u64,
    /// The length of the data-source blob in bytes.
    pub blob_size: u64,
    /// The length of the operation stream in bytes.
    pub ops_size: u64,
    /// The operations of the stream, by opcode.
    pub ops: DeltaOpCounts,
}

/// The operations of one part stream, counted by opcode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeltaOpCounts {
    /// `S`, open-splice-and-close.
    pub open_splice_close: u64,
    /// `o`, open.
    pub open: u64,
    /// `w`, write.
    pub write: u64,
    /// `r`, set-read-source.
    pub set_read_source: u64,
    /// `R`, unset-read-source.
    pub unset_read_source: u64,
    /// `c`, close.
    pub close: u64,
    /// `B`, bspatch.
    pub bspatch: u64,
}

/// Random-access backing for a decompressed part payload or a source object: on
/// the heap when small, a read-only memory map of a temp file when large.
pub(crate) enum Blob {
    Ram(Vec<u8>),
    Mapped(ostrya_sys::Mmap),
}

impl Blob {
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Blob::Ram(v) => v,
            Blob::Mapped(m) => m.as_slice(),
        }
    }
}

impl Repo {
    /// Apply a static delta from `dir` offline, producing the target commit and
    /// its objects into the repository, and return the target commit checksum.
    ///
    /// A part the superblock carries inline, under the metadata key
    /// `<relative_dir>/<index>`, is read from the metadata dict, and any other
    /// part from the file `dir/<index>`. Where both are present, the inline part
    /// is used. An inline part is checked against the size and the checksum its
    /// meta-entry declares before it is decompressed, as a part file is.
    ///
    /// The delta's source objects (for parts that patch against a source commit)
    /// must already be present in the repository. Every produced object's
    /// checksum is asserted as it is written. Fallback objects the delta
    /// references must already be present; offline application does not fetch
    /// them. The target commit's ref is not set: the caller decides that.
    pub async fn apply_static_delta_offline(&self, dir: &Path) -> Result<Checksum> {
        let sb_bytes = read_capped(dir.join("superblock")).await?;
        let mut sb = DeltaSuperblock::parse(sb_bytes)?;
        // Nothing here checks a signature, so a signed superblock's payload
        // goes before the parts are applied.
        drop(std::mem::take(&mut sb.superblock_bytes));

        // Fallback objects the delta references but does not carry must already
        // be present; offline application does not fetch them. Checked up front,
        // against the repository, so a missing prerequisite fails before any
        // object is staged.
        for fb in &sb.fallbacks {
            if !self.has_object(fb.objtype, &fb.checksum).await? {
                return Err(Error::ObjectNotFound {
                    checksum: fb.checksum,
                    ty: fb.objtype,
                });
            }
        }

        let txn = self.transaction().await?;
        let staging = txn.staging_fd().try_clone_to_owned()?;

        // The target commit object is embedded in the superblock, not a part.
        txn.write_metadata(ObjectType::Commit, Some(&sb.to), &sb.commit_bytes)
            .await?;

        // Offline application carries no pull flags, so the checks are the
        // destination's own: a bare-user-only repository stores an object under a
        // name that covers the canonical form alone, which it states here rather
        // than through the checksum the content writer would miss.
        let checks = ModeChecks::new(PullFlags::empty(), self.mode());
        for (i, entry) in sb.meta_entries.iter().enumerate() {
            // A part the superblock carries inline is read from there, also
            // where a part file of the same number is present.
            match sb.inline_part(i)? {
                Some((compression, body)) => {
                    verify_inline_part(compression, body, entry)?;
                    let payload = decode_inline_part(compression, body, &staging).await?;
                    apply_part(&txn, payload.as_slice(), &entry.objects, &staging, checks).await?;
                }
                None => {
                    let blob = decode_part(dir.join(i.to_string()), entry, &staging).await?;
                    apply_part(&txn, blob.as_slice(), &entry.objects, &staging, checks).await?;
                }
            }
        }

        txn.commit().await?;
        Ok(sb.to)
    }

    /// Verify a signed static delta's signatures against `verifiers`.
    ///
    /// Each verifier receives the signature blobs stored under its engine key in
    /// the delta's envelope together with the raw superblock bytes (the signed
    /// payload). The outcome is valid when any verifier reports a valid
    /// signature. An unsigned delta returns [`Error::Signature`].
    pub async fn verify_static_delta(
        &self,
        dir: &Path,
        verifiers: &[&dyn Verifier],
    ) -> Result<VerifyOutcome> {
        DeltaSuperblock::read(&dir.join("superblock"))
            .await?
            .verify(verifiers)
            .await
    }

    /// List the static deltas stored in the repository under `deltas/`, sorted
    /// by name.
    ///
    /// Each is named as the tool names it: the target commit hex for a
    /// from-scratch delta, or `<from-hex>-<to-hex>` for a delta against a source
    /// commit. A `deltas/<fanout>/<rest>` entry is a delta only where
    /// `<fanout>` and `<rest>` are directories and `<rest>/superblock`
    /// resolves. No symlink at `<fanout>` or at `<rest>` is followed, and a
    /// symlink at `superblock` or at `deltas` itself is followed. A dangling
    /// symlink at `deltas` holds no delta. Other entries are skipped, also
    /// where their names do not decode. An entry that holds a superblock and
    /// whose name does not decode fails the call.
    ///
    /// The `delta-indexes/` cache that advertises these deltas to a fetcher is
    /// written by [`reindex_static_deltas`](Repo::reindex_static_deltas) and
    /// read by a pull.
    pub async fn list_static_deltas(&self) -> Result<Vec<String>> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || list_static_deltas_blocking(repo_fd.as_fd())).await
    }

    /// Remove one static delta: from scratch to `to` where `from` is `None`,
    /// and from `from` to `to` otherwise.
    ///
    /// The call removes the entry at the delta's `deltas/<fanout>/<rest>` path
    /// and everything below it: nested directories, and also a regular file or
    /// a directory with no superblock at that path. A symlink at that path is
    /// removed as a link, and its target stays. No symlink below the path is
    /// followed. The fanout directory stays, also where it becomes empty.
    /// `delta-indexes/` and `summary` stay as they are, so they can still name
    /// the delta; [`reindex_static_deltas`](Repo::reindex_static_deltas) and a
    /// new summary refresh them.
    ///
    /// Where nothing resolves at the path, the call returns
    /// [`Error::StaticDeltaNotFound`]. The check follows symlinks, so a
    /// dangling symlink at the path reports the same error and stays.
    ///
    /// The call takes no repository lock. A concurrent generation of the same
    /// delta can fail, or can leave a partial directory. A removal that fails
    /// leaves the entries it did not reach.
    pub async fn delete_static_delta(&self, from: Option<&Checksum>, to: &Checksum) -> Result<()> {
        let (from, to) = (from.copied(), *to);
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || {
            delete_static_delta_blocking(repo_fd.as_fd(), from.as_ref(), &to)
        })
        .await
    }
}

/// Remove the entry at one delta's `deltas/<fanout>/<rest>` path, following no
/// symlink at or below that path.
fn delete_static_delta_blocking(
    repo_fd: BorrowedFd<'_>,
    from: Option<&Checksum>,
    to: &Checksum,
) -> Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags, openat, statat, unlinkat};
    use rustix::io::Errno;

    let not_found = || Error::StaticDeltaNotFound {
        from: from.copied(),
        to: *to,
    };
    let rel = crate::deltagen::delta_relative_dir(from, to);
    let (parent_rel, leaf) = rel
        .rsplit_once('/')
        .expect("a delta path holds a fanout directory");
    // The existence check follows symlinks, as the tool's does: a dangling
    // symlink at the path is an absent delta.
    match statat(repo_fd, rel.as_str(), AtFlags::empty()) {
        Ok(_) => {}
        Err(Errno::NOENT) => return Err(not_found()),
        Err(e) => return Err(Error::Io(e.into())),
    }
    let parent = match openat(
        repo_fd,
        parent_rel,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Err(not_found()),
        Err(e) => return Err(Error::Io(e.into())),
    };
    let leaf = CString::new(leaf).expect("a delta name holds no NUL");
    // The no-follow directory open refuses a symlink and every other
    // non-directory with `ENOTDIR`, and that entry is unlinked alone.
    match open_dir_nofollow(parent.as_fd(), &leaf) {
        Ok(dir) => remove_dir_tree(parent.as_fd(), &leaf, dir),
        Err(Errno::NOTDIR) => match unlinkat(&parent, leaf.as_c_str(), AtFlags::empty()) {
            Ok(()) => Ok(()),
            Err(Errno::NOENT) => Err(not_found()),
            Err(e) => Err(Error::Io(e.into())),
        },
        Err(Errno::NOENT) => Err(not_found()),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Scan `deltas/<fanout>/<leaf>` and reconstruct each delta's tool name.
fn list_static_deltas_blocking(repo_fd: BorrowedFd<'_>) -> Result<Vec<String>> {
    let mut names = scan_deltas(repo_fd, delta_name)?;
    names.sort();
    Ok(names)
}

/// Scan `deltas/<fanout>/<leaf>` and collect the source and target commit of
/// every delta present, for the index cache.
pub(crate) fn list_delta_targets(
    repo_fd: BorrowedFd<'_>,
) -> Result<Vec<(Option<Checksum>, Checksum)>> {
    scan_deltas(repo_fd, parse_delta_dir)
}

/// One delta's `deltas/<fanout>/<leaf>` directory names and the target commit
/// it carries, for the prune sweep.
pub(crate) struct DeltaDir {
    /// The `deltas/` fanout directory name.
    pub(crate) fanout: String,
    /// The delta directory name below the fanout.
    pub(crate) leaf: String,
    /// The commit the delta produces.
    pub(crate) to: Checksum,
}

/// Scan `deltas/<fanout>/<leaf>` and collect each delta's directory names
/// alongside the commit it produces. A directory with no superblock is not a
/// delta, so the prune sweep leaves it, which is what the `ostree` tool's prune
/// leaves.
pub(crate) fn list_delta_dirs(repo_fd: BorrowedFd<'_>) -> Result<Vec<DeltaDir>> {
    scan_deltas(repo_fd, |fanout, leaf| {
        let (_, to) = parse_delta_dir(fanout, leaf)?;
        Ok(DeltaDir {
            fanout: fanout.to_owned(),
            leaf: leaf.to_owned(),
            to,
        })
    })
}

/// Remove one `deltas/<fanout>/<leaf>` directory and everything below it.
///
/// A delta directory is removed whole, nested directories included, and no
/// symlink at the fanout, at the path, or below it is followed. An entry at the
/// fanout or at the path that is not a directory is left in place, which is
/// what a prune by the `ostree` tool leaves. The fanout directory above it is
/// left in place, empty where this was its last entry. A directory that is
/// already gone is success.
pub(crate) fn remove_delta_dir(repo_fd: BorrowedFd<'_>, dir: &DeltaDir) -> Result<()> {
    use rustix::fs::{Mode, OFlags, openat};
    use rustix::io::Errno;

    let deltas = match openat(
        repo_fd,
        "deltas",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(()),
        Err(e) => return Err(Error::Io(e.into())),
    };
    let name = |s: &str| CString::new(s).expect("a directory entry name holds no NUL");
    // The no-follow directory open refuses a symlink and every other
    // non-directory, at the fanout and at the delta path, with `ENOTDIR` or
    // `ELOOP`, and that entry stays.
    let fanout = match open_dir_nofollow(deltas.as_fd(), &name(&dir.fanout)) {
        Ok(fd) => fd,
        Err(Errno::NOTDIR | Errno::LOOP | Errno::NOENT) => return Ok(()),
        Err(e) => return Err(Error::Io(e.into())),
    };
    let leaf = name(&dir.leaf);
    match open_dir_nofollow(fanout.as_fd(), &leaf) {
        Ok(level) => remove_dir_tree(fanout.as_fd(), &leaf, level),
        Err(Errno::NOTDIR | Errno::LOOP | Errno::NOENT) => Ok(()),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Remove the directory `name` under `parent`, open as `dir`, and everything
/// below it, following no symlink. A symlink below it is unlinked as a link.
///
/// The removal is a loop over an explicit stack of levels, and it holds at
/// most two directory descriptors of its own at a time, whatever the depth:
/// the level in hand, and the child or the `..` it opens next. Descending
/// replaces the level's descriptor with the child's, and ascending replaces it
/// with the one `..` opens, which names the parent while the emptied level is
/// still linked where it was opened. Each level keeps the device and inode of
/// its directory, and the descriptor `..` opens must match the recorded
/// parent, so a directory that a concurrent rename moves stops the removal
/// instead of redirecting it. Depth costs a name and an entry list on the
/// heap, so a tree deeper than the process descriptor limit is removed whole.
///
/// A directory is read through the descriptor that opened it, which needs
/// read permission alone. A child directory with no entries is removed from
/// its parent at once, so an empty directory with no search permission goes
/// too. Names are kept as bytes, so a name that is not UTF-8 is removed too.
/// An entry that is gone before it is reached is skipped.
fn remove_dir_tree(parent: BorrowedFd<'_>, name: &CStr, dir: OwnedFd) -> Result<()> {
    use rustix::fs::{AtFlags, Dir};
    use rustix::io::Errno;

    let io_err = |e: Errno| Error::Io(e.into());
    let identity = dir_identity(dir.as_fd())?;
    let mut level = Dir::new(dir).map_err(io_err)?;
    // One entry per level on the path from `name` down to the level in hand:
    // the level's own name, its device and inode, and what is left to remove
    // within it.
    let mut levels = vec![(name.to_owned(), identity, read_tree_level(&mut level)?)];

    while let Some((_, _, entries)) = levels.last_mut() {
        match entries.pop() {
            Some((child, false)) => {
                unlink_tree_entry(level.fd().map_err(io_err)?, &child, AtFlags::empty())?
            }
            Some((child, true)) => {
                let child_fd = match open_dir_nofollow(level.fd().map_err(io_err)?, &child) {
                    Ok(fd) => fd,
                    // The child is gone, which the removal wanted anyway.
                    Err(Errno::NOENT) => continue,
                    Err(e) => return Err(io_err(e)),
                };
                let identity = dir_identity(child_fd.as_fd())?;
                let mut child_dir = Dir::new(child_fd).map_err(io_err)?;
                let child_entries = read_tree_level(&mut child_dir)?;
                if child_entries.is_empty() {
                    drop(child_dir);
                    unlink_tree_entry(level.fd().map_err(io_err)?, &child, AtFlags::REMOVEDIR)?;
                    continue;
                }
                level = child_dir;
                levels.push((child, identity, child_entries));
            }
            None => {
                let (cleared, _, _) = levels.pop().expect("a level is in hand within the loop");
                let Some((_, parent_identity, _)) = levels.last() else {
                    drop(level);
                    return unlink_tree_entry(parent, &cleared, AtFlags::REMOVEDIR);
                };
                let up = open_dir_nofollow(level.fd().map_err(io_err)?, c"..").map_err(io_err)?;
                level = Dir::new(up).map_err(io_err)?;
                let level_fd = level.fd().map_err(io_err)?;
                if dir_identity(level_fd)? != *parent_identity {
                    return Err(Error::Io(io::Error::other(
                        "a directory moved during the removal",
                    )));
                }
                unlink_tree_entry(level_fd, &cleared, AtFlags::REMOVEDIR)?;
            }
        }
    }
    Ok(())
}

/// Unlink `name` under `dir`. A name that is already gone is not an error.
fn unlink_tree_entry(dir: BorrowedFd<'_>, name: &CStr, flags: rustix::fs::AtFlags) -> Result<()> {
    match rustix::fs::unlinkat(dir, name, flags) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Open the directory `name` under `dir`, following no symlink.
fn open_dir_nofollow(dir: BorrowedFd<'_>, name: &CStr) -> rustix::io::Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, openat};

    openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// The device and inode of an open directory.
fn dir_identity(dir: BorrowedFd<'_>) -> Result<(u64, u64)> {
    let st = rustix::fs::fstat(dir).map_err(|e| Error::Io(e.into()))?;
    Ok((st.st_dev, st.st_ino))
}

/// The entries of one directory level, each with whether it is a directory.
///
/// `getdents64` already carries the type. A filesystem that reports
/// [`FileType::Unknown`](rustix::fs::FileType::Unknown) leaves the type to one
/// no-follow `statat` for that name alone; a name that is gone by the time that
/// call runs is left out.
fn read_tree_level(dir: &mut rustix::fs::Dir) -> Result<Vec<(CString, bool)>> {
    use rustix::fs::{AtFlags, FileType, statat};

    let mut read = Vec::new();
    for entry in dir.by_ref() {
        let entry = entry.map_err(|e| Error::Io(e.into()))?;
        let name = entry.file_name();
        if name != c"." && name != c".." {
            read.push((name.to_owned(), entry.file_type()));
        }
    }
    let fd = dir.fd().map_err(|e| Error::Io(e.into()))?;
    let mut entries = Vec::with_capacity(read.len());
    for (name, file_type) in read {
        let is_dir = match file_type {
            FileType::Directory => true,
            FileType::Unknown => match statat(fd, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => FileType::from_raw_mode(st.st_mode) == FileType::Directory,
                Err(rustix::io::Errno::NOENT) => continue,
                Err(e) => return Err(Error::Io(e.into())),
            },
            _ => false,
        };
        entries.push((name, is_dir));
    }
    Ok(entries)
}

/// Walk the two-level `deltas/` tree, applying `parse` to each delta's fanout
/// and leaf directory names. A repository with no `deltas/` yields nothing.
///
/// A fanout and a leaf count only where they are directories, and no symlink
/// at either is followed. A symlink at `deltas` itself is followed, as the
/// tool follows it. A leaf counts as a delta only where
/// `<leaf>/superblock` resolves, following symlinks, which is the `ostree`
/// tool's rule. Any other entry is skipped before its name is parsed, so such
/// an entry with a malformed name is skipped too. The entry type comes from
/// the directory read, and only a filesystem that reports no type costs one
/// no-follow `statat` per entry more; no superblock byte is read.
fn scan_deltas<T>(
    repo_fd: BorrowedFd<'_>,
    parse: impl Fn(&str, &str) -> Result<T>,
) -> Result<Vec<T>> {
    use rustix::fs::{AtFlags, Dir, Mode, OFlags, openat, statat};
    use rustix::io::Errno;

    let io_err = |e: Errno| Error::Io(e.into());

    let deltas = match openat(
        repo_fd,
        "deltas",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(Vec::new()),
        Err(e) => return Err(io_err(e)),
    };

    let mut deltas = Dir::new(deltas).map_err(io_err)?;
    let mut out = Vec::new();
    for (fanout, is_dir) in read_tree_level(&mut deltas)? {
        // Delta directory names are base64, so a name that is not UTF-8 is
        // no fanout.
        let (true, Ok(fanout_name)) = (is_dir, fanout.to_str()) else {
            continue;
        };
        // The no-follow open refuses an entry that became a symlink or a
        // non-directory since the read, and that entry is skipped too.
        let fan_fd = match open_dir_nofollow(deltas.fd().map_err(io_err)?, &fanout) {
            Ok(fd) => fd,
            Err(Errno::NOTDIR | Errno::LOOP | Errno::NOENT) => continue,
            Err(e) => return Err(io_err(e)),
        };
        let mut fan_dir = Dir::new(fan_fd).map_err(io_err)?;
        for (leaf, is_dir) in read_tree_level(&mut fan_dir)? {
            let (true, Ok(leaf_name)) = (is_dir, leaf.to_str()) else {
                continue;
            };
            match statat(
                fan_dir.fd().map_err(io_err)?,
                format!("{leaf_name}/superblock").as_str(),
                AtFlags::empty(),
            ) {
                Ok(_) => {}
                Err(Errno::NOENT | Errno::NOTDIR) => continue,
                Err(e) => return Err(io_err(e)),
            }
            out.push(parse(fanout_name, leaf_name)?);
        }
    }
    Ok(out)
}

/// Collect the child names of an open directory, dropping `.` and `..` and any
/// non-UTF-8 name (delta directory names are base64, so always UTF-8).
pub(crate) fn dir_child_names(dir: &OwnedFd) -> Result<Vec<String>> {
    let reader = rustix::fs::Dir::read_from(dir).map_err(|e| Error::Io(e.into()))?;
    let mut out = Vec::new();
    for entry in reader {
        let entry = entry.map_err(|e| Error::Io(e.into()))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if let Ok(name) = std::str::from_utf8(name) {
            out.push(name.to_owned());
        }
    }
    Ok(out)
}

/// Recover a delta's source and target commit from its
/// `deltas/<fanout>/<leaf>` directory names. The leaf carries a `-` (which never
/// occurs in base64) exactly when the delta is from a source commit.
fn parse_delta_dir(fanout: &str, leaf: &str) -> Result<(Option<Checksum>, Checksum)> {
    match leaf.split_once('-') {
        Some((from_rest, to_b64)) => Ok((
            Some(Checksum::from_base64_modified(&format!(
                "{fanout}{from_rest}"
            ))?),
            Checksum::from_base64_modified(to_b64)?,
        )),
        None => Ok((
            None,
            Checksum::from_base64_modified(&format!("{fanout}{leaf}"))?,
        )),
    }
}

/// Reconstruct a delta's hex name from its `deltas/<fanout>/<leaf>` directory.
fn delta_name(fanout: &str, leaf: &str) -> Result<String> {
    let (from, to) = parse_delta_dir(fanout, leaf)?;
    Ok(delta_hex_name(from.as_ref(), &to))
}

/// A delta's hex name as the tool names it: the target hex for a delta from
/// scratch, and `<from-hex>-<to-hex>` otherwise.
pub(crate) fn delta_hex_name(from: Option<&Checksum>, to: &Checksum) -> String {
    match from {
        Some(from) => format!("{}-{}", from.to_hex(), to.to_hex()),
        None => to.to_hex(),
    }
}

impl DeltaSuperblock {
    /// Parse a superblock file's bytes, detecting and unwrapping the signed
    /// envelope.
    ///
    /// The file bytes are dropped once they are decoded, and the payload of the
    /// signed envelope moves out of the decoded envelope with no copy, so the
    /// parse holds at most two copies of the superblock at once: the bytes and
    /// the tree decoded from them. The signed payload is kept after the parse,
    /// since [`verify`](DeltaSuperblock::verify) reads it. An unsigned
    /// superblock keeps no raw bytes.
    pub fn parse(bytes: Vec<u8>) -> Result<DeltaSuperblock> {
        let (payload, signatures) = if bytes.starts_with(SIGNED_MAGIC) {
            let ty = Type::parse(SIGNED_SIG).map_err(ostrya_core::Error::from)?;
            let value = from_bytes(&ty, &bytes).map_err(ostrya_core::Error::from)?;
            drop(bytes);
            let fields = tuple(&value)?;
            bytes_field(&fields[1], "signed superblock payload")?;
            let Value::Tuple(mut owned) = value else {
                unreachable!("`tuple` accepted the envelope as a tuple");
            };
            let signatures = owned.swap_remove(2);
            let Value::Bytes(inner) = owned.swap_remove(1) else {
                unreachable!("`bytes_field` accepted the payload as bytes");
            };
            (inner, Some(signatures))
        } else {
            (bytes, None)
        };

        let ty = Type::parse(SUPERBLOCK_SIG).map_err(ostrya_core::Error::from)?;
        let value = from_bytes(&ty, &payload).map_err(ostrya_core::Error::from)?;
        // Only a signature check reads the raw bytes, so an unsigned
        // superblock drops them here.
        let superblock_bytes = if signatures.is_some() {
            payload
        } else {
            drop(payload);
            Vec::new()
        };
        let fields = tuple(&value)?;

        // The `ostree.endianness` metadata byte gates the meta-entry and
        // fallback size fields, so the byte is read here and those fields are
        // swapped for a big-endian producer. The timestamp and the `(uuu)`
        // modes are always big-endian and the embedded commit is normal-form
        // little-endian, so nothing else here turns on it.
        let big_endian = declares_big_endian(&fields[0]);
        // GVariant decodes the `t` little-endian; the field is big-endian.
        let timestamp = fields[1]
            .as_u64()
            .ok_or_else(|| {
                Error::InvalidFormat("expected superblock timestamp to be a u64".into())
            })?
            .swap_bytes();
        let recursion_len = bytes_field(&fields[5], "superblock recursion array")?.len();
        let to = Checksum::from_ay(bytes_field(&fields[3], "superblock to")?)?;
        // The source commit is a zero-length `ay` for a from-scratch delta.
        let from_bytes = bytes_field(&fields[2], "superblock from")?;
        let from = if from_bytes.is_empty() {
            None
        } else {
            Some(Checksum::from_ay(from_bytes)?)
        };

        // Re-serialize the embedded commit to its normal-form bytes and assert
        // the target checksum, closing the loop on the commit the delta carries.
        let commit_ty = Type::parse(COMMIT_SIG).map_err(ostrya_core::Error::from)?;
        let commit_bytes = to_bytes(&commit_ty, &fields[4]).map_err(ostrya_core::Error::from)?;
        if Checksum::sha256(&commit_bytes) != to {
            return Err(Error::InvalidFormat(
                "static delta embedded commit does not match the target checksum".to_owned(),
            ));
        }

        let meta_entries = parse_meta_entries(array(&fields[6])?, big_endian)?;
        let fallbacks = parse_fallbacks(array(&fields[7])?, big_endian)?;

        // The metadata dict moves out of the parsed tree rather than being
        // copied: it can carry inline parts.
        let Value::Tuple(mut owned) = value else {
            unreachable!("`tuple` accepted the value as a tuple");
        };
        let metadata = owned.swap_remove(0);
        let inline_index = index_inline_parts(
            &metadata,
            &crate::deltagen::delta_relative_dir(from.as_ref(), &to),
            meta_entries.len(),
        );

        Ok(DeltaSuperblock {
            from,
            to,
            commit_bytes,
            meta_entries,
            fallbacks,
            signatures,
            superblock_bytes,
            metadata,
            inline_index,
            timestamp,
            recursion_len,
        })
    }

    /// Read a superblock file, under the metadata ceiling, and parse it.
    pub async fn read(path: &Path) -> Result<DeltaSuperblock> {
        DeltaSuperblock::parse(read_capped(path.to_owned()).await?)
    }

    /// The source commit, `None` for a delta from scratch.
    pub fn from_commit(&self) -> Option<&Checksum> {
        self.from.as_ref()
    }

    /// The target commit.
    pub fn to_commit(&self) -> &Checksum {
        &self.to
    }

    /// Whether the superblock file is the signed envelope.
    pub fn is_signed(&self) -> bool {
        self.signatures.is_some()
    }

    /// Verify the signed envelope's signatures against `verifiers`.
    ///
    /// Each verifier receives the signature blobs stored under its engine key
    /// in the envelope together with the raw superblock bytes the envelope
    /// wraps (the signed payload). A verifier whose engine key holds no blob
    /// examines no signature. The outcome is valid when any verifier reports a
    /// valid signature. A superblock with no envelope returns
    /// [`Error::Signature`].
    pub async fn verify(&self, verifiers: &[&dyn Verifier]) -> Result<VerifyOutcome> {
        let signatures = self
            .signatures
            .as_ref()
            .ok_or_else(|| Error::Signature("static delta carries no signatures".to_owned()))?;
        let mut outcome = VerifyOutcome::default();
        for verifier in verifiers {
            let blobs = signatures_for(signatures, verifier.metadata_key());
            let result = verifier.verify(&self.superblock_bytes, &blobs).await?;
            outcome.valid |= result.valid;
            outcome.signatures.extend(result.signatures);
        }
        Ok(outcome)
    }

    /// The byte order the `ostree.endianness` byte declares.
    pub fn endianness(&self) -> DeltaEndianness {
        if declares_big_endian(&self.metadata) {
            DeltaEndianness::Big
        } else {
            DeltaEndianness::Little
        }
    }

    /// The generation timestamp, in seconds since the Unix epoch.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// The byte length of the recursion array, field 5, divided by 64: the
    /// parent count `static-delta show` reports.
    pub fn parent_count(&self) -> usize {
        self.recursion_len / 64
    }

    /// The per-part meta-entries, in part order.
    pub fn parts(&self) -> &[DeltaPart] {
        &self.meta_entries
    }

    /// The fallback objects, in superblock order.
    pub fn fallbacks(&self) -> &[DeltaFallback] {
        &self.fallbacks
    }

    /// The delta's directory relative to the repository root,
    /// `deltas/<fanout>/<rest>`, derived from the source and target commits.
    pub fn relative_dir(&self) -> String {
        crate::deltagen::delta_relative_dir(self.from.as_ref(), &self.to)
    }

    /// Part `index` as the superblock carries it inline: its compression byte
    /// and its body, borrowed from the metadata dict. `None` where the dict
    /// holds no key for it.
    pub(crate) fn inline_part(&self, index: usize) -> Result<Option<(u8, &[u8])>> {
        inline_part_at(&self.metadata, &self.inline_index, index, || {
            self.relative_dir()
        })
    }

    /// Read what part `index` holds without applying it.
    ///
    /// A part the superblock carries inline, under the metadata key
    /// `<relative_dir>/<index>`, is read from the metadata dict; any other part
    /// is read from the file `dir/<index>`. The part is checked against the
    /// size and the checksum its meta-entry declares before any byte of it is
    /// decompressed. No transaction and no temp file are needed: the payload is
    /// read in up to three passes over the part source, and the heap holds one
    /// fixed-size read buffer, a 1 MiB tail of the payload, and the xz
    /// decoder's state, whatever the payload size. The decoder takes at most
    /// 128 MiB, and a part whose xz stream states a dictionary that needs more
    /// is refused.
    pub async fn part_stats(&self, index: usize, dir: &Path) -> Result<DeltaPartStats> {
        let entry = self
            .meta_entries
            .get(index)
            .ok_or_else(|| Error::InvalidFormat(format!("static delta has no part {index}")))?;
        match self.inline_part(index)? {
            Some((compression, body)) => {
                let source = InlineSource {
                    compression,
                    body,
                    pos: 0,
                };
                part_stats_from(source, entry).await
            }
            None => {
                let path = dir.join(index.to_string());
                let file = ostrya_rt::unblock(move || std::fs::File::open(&path))
                    .await
                    .map_err(Error::Io)?;
                part_stats_from(RtFile::from(file), entry).await
            }
        }
    }
}

/// Find, in one pass over a superblock metadata dict, the entry that carries
/// each of `parts` parts inline: for part `index`, the position of the first
/// entry keyed `<dir>/<index>`, where `dir` is the delta's repository-relative
/// directory, and `None` where the dict holds no such key. A later entry under
/// the same key is not read, which is the rule of a lookup by key. A key whose
/// last component is not a part number in plain decimal, or is a number no
/// meta-entry has, names no part. Nothing is type-checked here:
/// [`inline_part_at`] checks each value when its part is read.
pub(crate) fn index_inline_parts(metadata: &Value, dir: &str, parts: usize) -> Vec<Option<usize>> {
    let mut index = vec![None; parts];
    let Some(entries) = metadata.as_array() else {
        return index;
    };
    for (position, entry) in entries.iter().enumerate() {
        let Some([key, _]) = entry.as_tuple() else {
            continue;
        };
        let Some(number) = key
            .as_str()
            .and_then(|key| key.strip_prefix(dir))
            .and_then(|rest| rest.strip_prefix('/'))
        else {
            continue;
        };
        // The key is `format!("{dir}/{index}")`, so a sign, a leading zero, or
        // any other character is another key.
        let plain = !number.is_empty()
            && number.bytes().all(|b| b.is_ascii_digit())
            && (number == "0" || !number.starts_with('0'));
        let Some(slot) = plain
            .then(|| number.parse::<usize>().ok())
            .flatten()
            .and_then(|i| index.get_mut(i))
        else {
            continue;
        };
        if slot.is_none() {
            *slot = Some(position);
        }
    }
    index
}

/// Part `part` as a superblock metadata dict carries it inline, at the
/// position [`index_inline_parts`] found for it: its compression byte and its
/// body, borrowed from the dict. `None` where the dict carries the part
/// nowhere. A value of a type other than `(yay)` is refused, and the caller
/// does not read the part file in its place. `dir` gives the delta's
/// repository-relative directory, for the refusal text alone.
pub(crate) fn inline_part_at<'a>(
    metadata: &'a Value,
    index: &[Option<usize>],
    part: usize,
    dir: impl FnOnce() -> String,
) -> Result<Option<(u8, &'a [u8])>> {
    let Some(position) = index.get(part).copied().flatten() else {
        return Ok(None);
    };
    let fields = metadata
        .as_array()
        .and_then(|entries| entries.get(position))
        .and_then(Value::as_tuple)
        .and_then(|pair| pair.get(1))
        .and_then(Value::as_variant)
        .filter(|(ty, _)| ty.signature() == INLINE_PART_SIG)
        .and_then(|(_, value)| value.as_tuple());
    match fields {
        Some([Value::Byte(compression), Value::Bytes(body)]) => Ok(Some((*compression, body))),
        _ => Err(Error::InvalidFormat(format!(
            "static delta inline part {}/{part} is not a {INLINE_PART_SIG} variant",
            dir()
        ))),
    }
}

/// Check an inline part against its meta-entry by the rules a part file is
/// read under: the compression byte and the body together fit in the size the
/// entry declares, their SHA-256 is the checksum the entry names, and the
/// compression byte is one the reader decodes. Nothing is decompressed.
pub(crate) fn verify_inline_part(compression: u8, body: &[u8], entry: &DeltaPart) -> Result<()> {
    let limit = entry.size.saturating_sub(1);
    if body.len() as u64 > limit {
        return Err(op_error(&format!(
            "a stream passed the {limit} byte(s) declared for it"
        )));
    }
    let mut hasher = Sha256::new();
    hasher.update([compression]);
    hasher.update(body);
    if Checksum::from_bytes(hasher.finalize().into()) != entry.part_csum {
        return Err(Error::InvalidFormat(
            "static delta part checksum mismatch".to_owned(),
        ));
    }
    match compression {
        COMPRESSION_NONE | COMPRESSION_XZ => Ok(()),
        other => Err(Error::InvalidFormat(format!(
            "static delta part compression byte {other:#x} is not supported"
        ))),
    }
}

/// The payload of an inline part: the body itself where it is uncompressed, and
/// the decompressed [`Blob`] where it is xz.
pub(crate) enum InlinePayload<'a> {
    Borrowed(&'a [u8]),
    Owned(Blob),
}

impl InlinePayload<'_> {
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            InlinePayload::Borrowed(bytes) => bytes,
            InlinePayload::Owned(blob) => blob.as_slice(),
        }
    }
}

/// Decode the body of an inline part that [`verify_inline_part`] accepted. An
/// uncompressed body is used where it lies, with no copy. An xz body
/// decompresses through [`spill_to_blob`], on the heap at or below
/// [`MMAP_THRESHOLD`] and into a mapped temp file in `staging` above it.
pub(crate) async fn decode_inline_part<'a>(
    compression: u8,
    body: &'a [u8],
    staging: &OwnedFd,
) -> Result<InlinePayload<'a>> {
    match compression {
        COMPRESSION_NONE => Ok(InlinePayload::Borrowed(body)),
        COMPRESSION_XZ => {
            let decoder = XzDecoder::new(Cursor::new(body));
            Ok(InlinePayload::Owned(
                spill_to_blob(decoder, staging, None).await?,
            ))
        }
        other => Err(Error::InvalidFormat(format!(
            "static delta part compression byte {other:#x} is not supported"
        ))),
    }
}

/// An inline part read as the part file it stands for: the compression byte,
/// then the body, borrowed from the metadata dict. It seeks, so
/// [`part_stats_from`] reads it as it reads a file.
struct InlineSource<'a> {
    compression: u8,
    body: &'a [u8],
    pos: u64,
}

impl AsyncRead for InlineSource<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() || this.pos > this.body.len() as u64 {
            return Poll::Ready(Ok(0));
        }
        if this.pos == 0 {
            buf[0] = this.compression;
            this.pos = 1;
            return Poll::Ready(Ok(1));
        }
        let rest = &this.body[(this.pos - 1) as usize..];
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        this.pos += n as u64;
        Poll::Ready(Ok(n))
    }
}

impl AsyncSeek for InlineSource<'_> {
    fn poll_seek(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        let len = 1 + this.body.len() as u64;
        let target = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => len.checked_add_signed(delta),
            SeekFrom::Current(delta) => this.pos.checked_add_signed(delta),
        };
        Poll::Ready(match target {
            Some(target) => {
                this.pos = target;
                Ok(target)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of an inline part",
            )),
        })
    }
}

/// Parse the meta-entry array `a(uayttay)`. The `size` field is the ceiling a
/// part is read under; the `usize` field states what the part's objects add up
/// to. Both are host order.
fn parse_meta_entries(entries: &[Value], big_endian: bool) -> Result<Vec<DeltaPart>> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = tuple(entry)?;
        let part_csum = Checksum::from_ay(bytes_field(&fields[1], "part checksum")?)?;
        let size = size_field(&fields[2], "part size", big_endian)?;
        let uncompressed_size = size_field(&fields[3], "part uncompressed size", big_endian)?;
        let objects = parse_object_array(bytes_field(&fields[4], "object array")?)?;
        out.push(DeltaPart {
            part_csum,
            size,
            uncompressed_size,
            objects,
        });
    }
    Ok(out)
}

/// Whether the superblock's metadata dict states big-endian host order. A
/// superblock carrying no `ostree.endianness` byte is read as little-endian,
/// which is what every producer of these deltas writes.
fn declares_big_endian(metadata: &Value) -> bool {
    metadata
        .dict_get(ENDIANNESS_KEY)
        .and_then(Value::as_variant)
        .and_then(|(_, value)| value.as_byte())
        == Some(ENDIANNESS_BIG)
}

/// Read one host-order `t` field. GVariant decodes it little-endian, which is the
/// order a little-endian producer wrote it in, so a big-endian producer's field is
/// swapped back.
fn size_field(value: &Value, what: &str, big_endian: bool) -> Result<u64> {
    let raw = value
        .as_u64()
        .ok_or_else(|| Error::InvalidFormat(format!("expected {what} to be a u64")))?;
    Ok(if big_endian { raw.swap_bytes() } else { raw })
}

/// Parse the stride-33 `objtype + 32-byte checksum` object array that gives each
/// part's object order and types.
fn parse_object_array(bytes: &[u8]) -> Result<Vec<(ObjectType, Checksum)>> {
    if !bytes.len().is_multiple_of(33) {
        return Err(Error::InvalidFormat(
            "static delta object array is not a multiple of 33 bytes".to_owned(),
        ));
    }
    let mut out = Vec::with_capacity(bytes.len() / 33);
    for chunk in bytes.chunks_exact(33) {
        let objtype = ObjectType::from_u32(u32::from(chunk[0]))?;
        let checksum = Checksum::from_ay(&chunk[1..33])?;
        out.push((objtype, checksum));
    }
    Ok(out)
}

/// Parse the fallback array `a(yaytt)`. The two sizes are host order.
fn parse_fallbacks(entries: &[Value], big_endian: bool) -> Result<Vec<DeltaFallback>> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = tuple(entry)?;
        let objtype = ObjectType::from_u32(u32::from(byte_field(&fields[0], "fallback objtype")?))?;
        let checksum = Checksum::from_ay(bytes_field(&fields[1], "fallback checksum")?)?;
        let size = size_field(&fields[2], "fallback size", big_endian)?;
        let uncompressed_size = size_field(&fields[3], "fallback uncompressed size", big_endian)?;
        out.push(DeltaFallback {
            objtype,
            checksum,
            size,
            uncompressed_size,
        });
    }
    Ok(out)
}

/// Decode a part file into a random-access [`Blob`], verifying the part
/// checksum over the whole on-disk file before the payload is expanded.
async fn decode_part(part_path: PathBuf, entry: &DeltaPart, staging: &OwnedFd) -> Result<Blob> {
    let std_file = ostrya_rt::unblock(move || std::fs::File::open(&part_path))
        .await
        .map_err(Error::Io)?;
    decode_part_stream(RtFile::from(std_file), entry, staging).await
}

/// Decode a part stream into a random-access [`Blob`], verifying the part
/// checksum over the whole stream before any of it is decompressed.
///
/// The `(yay)` part frame is a compression byte followed by the body to EOF (a
/// tuple whose fixed `y` sits at offset 0 and whose trailing `ay` runs to the
/// end). The stream is a part file for an offline application and a fetched
/// response body for a pull.
///
/// The body is taken in under the size `entry` declares for the part file and
/// hashed as it arrives, and the part checksum is asserted before the decoder
/// runs. What the payload decompresses to is therefore bounded by a stream that
/// hashes to the checksum the superblock names: a body that grew, shrank, or was
/// swapped is refused having written at most the declared size, and a payload
/// that expands without bound is one the delta's own publisher wrote. Both blobs
/// spill through [`spill_to_blob`], so neither the body nor the payload is held
/// beyond [`MMAP_THRESHOLD`] on the heap.
pub(crate) async fn decode_part_stream<R: AsyncRead + Unpin>(
    mut stream: R,
    entry: &DeltaPart,
    staging: &OwnedFd,
) -> Result<Blob> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await.map_err(Error::Io)?;
    // The checksum covers the whole part file, so the framing byte seeds the
    // digest the body streams into.
    let mut hasher = Sha256::new();
    hasher.update(first);
    let mut reader = HashingReader::new(hasher, stream);

    // What the declared size leaves for the body, the framing byte spent.
    let body_limit = entry.size.saturating_sub(1);
    let body = spill_to_blob(&mut reader, staging, Some(body_limit)).await?;
    let (part_csum, _size) = reader.finalize();
    if part_csum != entry.part_csum {
        return Err(Error::InvalidFormat(
            "static delta part checksum mismatch".to_owned(),
        ));
    }

    match first[0] {
        COMPRESSION_NONE => Ok(body),
        COMPRESSION_XZ => {
            let decoder = XzDecoder::new(Cursor::new(body.as_slice()));
            spill_to_blob(decoder, staging, None).await
        }
        other => Err(Error::InvalidFormat(format!(
            "static delta part compression byte {other:#x} is not supported"
        ))),
    }
}

/// The type of a part the superblock carries inline in its metadata dict: the
/// compression byte and the body, the framing a part file has on disk.
const INLINE_PART_SIG: &str = "(yay)";

/// The number of trailing payload bytes [`part_stats_from`] keeps as it reads a
/// payload to its end. A payload whose operation stream and xattr framing lie
/// in this tail is read once.
const PAYLOAD_TAIL: usize = 1024 * 1024;

/// The memory the xz decoder may take to read the statistics of a part. The
/// dictionary size an xz stream states sets what the decoder allocates, so a
/// small part could state a dictionary of gigabytes. A part the tool's
/// generator or the port's writes states a 32 MiB dictionary in its xz block
/// header.
pub(crate) const STATS_XZ_MEM_LIMIT: u64 = 128 * 1024 * 1024;

/// How far [`part_stats_from`] read a payload after the pass that found its
/// framing. The tests assert which reads a payload took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TailWalk {
    /// The kept tail held the operation stream and the xattr framing.
    TailOnly,
    /// The kept tail held the operation stream: the payload was read again up
    /// to the end of the xattr table.
    ToXattrs,
    /// The kept tail held neither: the payload was read again up to the end of
    /// the operation stream.
    Full,
}

/// Read what one part source holds without applying it.
///
/// The framing offsets of the payload `(a(uuu)aa(ayay)ayay)` sit at its end,
/// so one forward pass cannot find the operation stream, and a payload has no
/// size ceiling, so it is never held. The source is read in up to three
/// passes:
///
/// 1. Verify: the body is hashed under the size `entry` declares and the part
///    checksum is asserted, with no byte decompressed, the rules
///    [`decode_part_stream`] applies.
/// 2. Frame: the payload streams to its end, keeping its length and its last
///    [`PAYLOAD_TAIL`] bytes, which end with the three framing offsets of the
///    tuple. An uncompressed body is the payload itself, so pass 1 keeps the
///    tail and this pass is not made.
/// 3. Walk: where the tail does not hold the operation stream and the last
///    framing offset of the xattr table, the payload is read again up to the
///    last of the two. An uncompressed body is read at those offsets through
///    a seek, and a compressed one streams from its start.
///
/// Each pass holds one [`IO_CHUNK`] buffer and the tail. A compressed pass
/// also holds the xz decoder's state, whose size the dictionary the stream
/// states sets, and which [`STATS_XZ_MEM_LIMIT`] caps.
pub(crate) async fn part_stats_from<R>(source: R, entry: &DeltaPart) -> Result<DeltaPartStats>
where
    R: AsyncRead + AsyncSeek + Unpin + Send,
{
    part_stats_walk(source, entry)
        .await
        .map(|(stats, _walk)| stats)
}

async fn part_stats_walk<R>(mut source: R, entry: &DeltaPart) -> Result<(DeltaPartStats, TailWalk)>
where
    R: AsyncRead + AsyncSeek + Unpin + Send,
{
    let mut chunk = vec![0u8; IO_CHUNK];
    let (compression, verified) = verify_part_source(&mut source, entry, &mut chunk).await?;
    let (total, tail) = match verified {
        Some(kept) => kept,
        None => {
            source.seek(SeekFrom::Start(1)).await.map_err(Error::Io)?;
            let mut payload = xz_payload(&mut source, entry);
            let mut tail = Tail::new(PAYLOAD_TAIL);
            let mut total = 0u64;
            loop {
                let n = payload.read(&mut chunk).await.map_err(payload_error)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                tail.push(&chunk[..n]);
            }
            (total, tail.into_vec())
        }
    };
    let mut last24 = [0u8; 24];
    let keep = tail.len().min(24);
    last24[24 - keep..].copy_from_slice(&tail[tail.len() - keep..]);
    let frame = PartFrame::from_tail(total, &last24)?;

    let xattr_len = frame.xattrs_end - frame.modes_end;
    let xattr_offset_size = offset_size(xattr_len)?;
    // The last framing offset of the xattr table, which states where the
    // table's framing starts. An empty table carries none.
    let last_start = if xattr_len == 0 {
        frame.xattrs_end
    } else {
        frame
            .xattrs_end
            .checked_sub(xattr_offset_size as u64)
            .filter(|start| *start >= frame.modes_end)
            .ok_or_else(bad_frame)?
    };
    let xattr_range = last_start..frame.xattrs_end;
    let ops_range = frame.blob_end..frame.ops_end;

    let tail_start = total - tail.len() as u64;
    let in_tail = |range: &std::ops::Range<u64>| range.is_empty() || range.start >= tail_start;
    let at = |off: u64| (off - tail_start) as usize;
    let xattr_in_tail = in_tail(&xattr_range);
    let ops_in_tail = in_tail(&ops_range);

    let mut last = [0u8; 8];
    let mut counter = OpCounter::new(&entry.objects, frame.blob_end - frame.xattrs_end);
    if xattr_in_tail && !xattr_range.is_empty() {
        last[..xattr_offset_size]
            .copy_from_slice(&tail[at(xattr_range.start)..at(xattr_range.end)]);
    }
    if ops_in_tail && !ops_range.is_empty() {
        counter.feed(&tail[at(ops_range.start)..at(ops_range.end)])?;
    }
    drop(tail);

    let walk = match (xattr_in_tail, ops_in_tail) {
        (true, true) => TailWalk::TailOnly,
        (false, true) => TailWalk::ToXattrs,
        _ => TailWalk::Full,
    };
    if walk != TailWalk::TailOnly {
        if compression == COMPRESSION_NONE {
            if !xattr_in_tail {
                source
                    .seek(SeekFrom::Start(1 + xattr_range.start))
                    .await
                    .map_err(Error::Io)?;
                source
                    .read_exact(&mut last[..xattr_offset_size])
                    .await
                    .map_err(Error::Io)?;
            }
            if !ops_in_tail {
                source
                    .seek(SeekFrom::Start(1 + ops_range.start))
                    .await
                    .map_err(Error::Io)?;
                let mut ops = (&mut source).take(ops_range.end - ops_range.start);
                read_region(
                    &mut ops,
                    &mut chunk,
                    ops_range.start,
                    ops_range.end,
                    |_, bytes| counter.feed(bytes),
                )
                .await?;
            }
        } else {
            source.seek(SeekFrom::Start(1)).await.map_err(Error::Io)?;
            let mut payload = xz_payload(&mut source, entry);
            let upto = if ops_in_tail {
                frame.xattrs_end
            } else {
                frame.ops_end
            };
            read_region(&mut payload, &mut chunk, 0, upto, |pos, bytes| {
                let end = pos + bytes.len() as u64;
                let lo = xattr_range.start.max(pos);
                let hi = xattr_range.end.min(end);
                if lo < hi {
                    last[(lo - xattr_range.start) as usize..(hi - xattr_range.start) as usize]
                        .copy_from_slice(&bytes[(lo - pos) as usize..(hi - pos) as usize]);
                }
                if !ops_in_tail {
                    let from = ops_range.start.max(pos);
                    if from < end {
                        counter.feed(&bytes[(from - pos) as usize..])?;
                    }
                }
                Ok(())
            })
            .await?;
        }
    }
    let ops = counter.finish()?;

    let xattrs = if xattr_len == 0 {
        0
    } else {
        let last = u64::from_le_bytes(last);
        let framing = xattr_len
            .checked_sub(last)
            .filter(|framing| {
                *framing >= xattr_offset_size as u64
                    && framing.is_multiple_of(xattr_offset_size as u64)
            })
            .ok_or_else(bad_frame)?;
        framing / xattr_offset_size as u64
    };

    let stats = DeltaPartStats {
        modes: frame.modes_end / 12,
        xattrs,
        blob_size: frame.blob_end - frame.xattrs_end,
        ops_size: frame.ops_end - frame.blob_end,
        ops,
    };
    Ok((stats, walk))
}

/// Stream `reader`, positioned at payload offset `from`, up to payload offset
/// `upto`, handing each chunk to `sink` with the payload offset it starts at.
async fn read_region<R, F>(
    reader: &mut R,
    chunk: &mut [u8],
    from: u64,
    upto: u64,
    mut sink: F,
) -> Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
    F: FnMut(u64, &[u8]) -> Result<()>,
{
    let mut pos = from;
    while pos < upto {
        let want = usize::try_from(upto - pos).map_or(chunk.len(), |left| left.min(chunk.len()));
        let n = reader
            .read(&mut chunk[..want])
            .await
            .map_err(payload_error)?;
        if n == 0 {
            return Err(op_error("part payload ended before its operation stream"));
        }
        sink(pos, &chunk[..n])?;
        pos += n as u64;
    }
    Ok(())
}

/// Pass 1 of [`part_stats_from`]: hash the part source under the size `entry`
/// declares, assert the part checksum, and return the compression byte. No byte
/// is decompressed. For an uncompressed part, whose body is the payload, the
/// payload length and its last [`PAYLOAD_TAIL`] bytes come back too.
async fn verify_part_source<R: AsyncRead + Unpin>(
    source: &mut R,
    entry: &DeltaPart,
    chunk: &mut [u8],
) -> Result<(u8, Option<(u64, Vec<u8>)>)> {
    let mut first = [0u8; 1];
    source.read_exact(&mut first).await.map_err(Error::Io)?;
    let mut hasher = Sha256::new();
    hasher.update(first);
    let limit = entry.size.saturating_sub(1);
    let mut tail = (first[0] == COMPRESSION_NONE).then(|| Tail::new(PAYLOAD_TAIL));
    let mut total = 0u64;
    loop {
        let n = source.read(chunk).await.map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > limit {
            return Err(op_error(&format!(
                "a stream passed the {limit} byte(s) declared for it"
            )));
        }
        hasher.update(&chunk[..n]);
        if let Some(tail) = tail.as_mut() {
            tail.push(&chunk[..n]);
        }
    }
    if Checksum::from_bytes(hasher.finalize().into()) != entry.part_csum {
        return Err(Error::InvalidFormat(
            "static delta part checksum mismatch".to_owned(),
        ));
    }
    match first[0] {
        COMPRESSION_NONE => Ok((first[0], tail.map(|tail| (total, tail.into_vec())))),
        COMPRESSION_XZ => Ok((first[0], None)),
        other => Err(Error::InvalidFormat(format!(
            "static delta part compression byte {other:#x} is not supported"
        ))),
    }
}

/// The payload of an xz part source positioned after its compression byte,
/// read under the body size `entry` declares and under [`STATS_XZ_MEM_LIMIT`]
/// of decoder memory.
fn xz_payload<'a, R>(source: &'a mut R, entry: &DeltaPart) -> impl AsyncRead + Send + Unpin + 'a
where
    R: AsyncRead + Unpin + Send,
{
    let body = source.take(entry.size.saturating_sub(1));
    XzDecoder::with_mem_limit(BufReader::with_capacity(IO_CHUNK, body), STATS_XZ_MEM_LIMIT)
}

/// Map a payload read error, naming a stream that needs more decoder memory
/// than [`STATS_XZ_MEM_LIMIT`].
fn payload_error(err: io::Error) -> Error {
    // liblzma reports the limit as an `Other` error carrying this text, and a
    // failed allocation as `OutOfMemory`.
    if err.kind() == io::ErrorKind::OutOfMemory || err.to_string() == "memory limit reached" {
        return op_error(&format!(
            "part payload needs more than {} MiB of xz decoder memory",
            STATS_XZ_MEM_LIMIT >> 20
        ));
    }
    Error::Io(err)
}

/// The last `cap` bytes of a stream, kept in a ring that grows up to `cap`.
struct Tail {
    buf: Vec<u8>,
    /// Where the oldest byte sits once the ring is full.
    head: usize,
    cap: usize,
}

impl Tail {
    fn new(cap: usize) -> Tail {
        Tail {
            buf: Vec::new(),
            head: 0,
            cap,
        }
    }

    fn push(&mut self, mut bytes: &[u8]) {
        if bytes.len() >= self.cap {
            self.buf.clear();
            self.buf.extend_from_slice(&bytes[bytes.len() - self.cap..]);
            self.head = 0;
            return;
        }
        let room = self.cap - self.buf.len();
        if room > 0 {
            let n = room.min(bytes.len());
            self.buf.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
        }
        while !bytes.is_empty() {
            let n = (self.cap - self.head).min(bytes.len());
            self.buf[self.head..self.head + n].copy_from_slice(&bytes[..n]);
            self.head = (self.head + n) % self.cap;
            bytes = &bytes[n..];
        }
    }

    /// The kept bytes, oldest first.
    fn into_vec(mut self) -> Vec<u8> {
        self.buf.rotate_left(self.head);
        self.buf
    }
}

/// The member ends of a part payload `(a(uuu)aa(ayay)ayay)`, read from its three
/// trailing framing offsets. Each end is an offset from the payload start.
struct PartFrame {
    /// The end of the mode table, the first member.
    modes_end: u64,
    /// The end of the xattr table.
    xattrs_end: u64,
    /// The end of the data-source blob, where the operation stream starts.
    blob_end: u64,
    /// The end of the operation stream, where the framing offsets start.
    ops_end: u64,
}

impl PartFrame {
    /// Read the framing of a payload of `len` bytes whose last 24 bytes are
    /// `tail`. The last offset closes the mode table, the one before it the
    /// xattr table, and the one before that the blob.
    fn from_tail(len: u64, tail: &[u8; 24]) -> Result<PartFrame> {
        let z = offset_size(len)?;
        let ops_end = len.checked_sub(3 * z as u64).ok_or_else(bad_frame)?;
        let read = |from_end: usize| {
            let start = tail.len() - from_end * z;
            let mut bytes = [0u8; 8];
            bytes[..z].copy_from_slice(&tail[start..start + z]);
            u64::from_le_bytes(bytes)
        };
        let frame = PartFrame {
            modes_end: read(1),
            xattrs_end: read(2),
            blob_end: read(3),
            ops_end,
        };
        if frame.modes_end > frame.xattrs_end
            || frame.xattrs_end > frame.blob_end
            || frame.blob_end > frame.ops_end
            || !frame.modes_end.is_multiple_of(12)
        {
            return Err(bad_frame());
        }
        Ok(frame)
    }
}

/// The framing-offset width of a GVariant container of `len` bytes.
fn offset_size(len: u64) -> Result<usize> {
    let len = usize::try_from(len).map_err(|_| bad_frame())?;
    Ok(offset_size_for(len))
}

fn bad_frame() -> Error {
    Error::InvalidFormat("static delta part payload framing is invalid".to_owned())
}

/// The operand count of `opcode`, `meta` stating whether the object at the
/// current index is a metadata object: the rules [`apply_part`] decodes by.
/// `None` for a byte that is no opcode.
fn operand_count(opcode: u8, meta: bool) -> Option<usize> {
    match opcode {
        OP_OPEN_SPLICE_CLOSE if meta => Some(2),
        OP_OPEN_SPLICE_CLOSE => Some(4),
        OP_OPEN => Some(3),
        OP_WRITE | OP_BSPATCH => Some(2),
        OP_SET_READ_SOURCE => Some(1),
        OP_UNSET_READ_SOURCE | OP_CLOSE => Some(0),
        _ => None,
    }
}

/// Count the operations of a part stream fed in chunks of any size.
///
/// The operands are decoded by the rules [`apply_part`] applies. Two ranges into
/// the data-source blob are checked against the blob length, the ones the
/// tool's `static-delta show` also refuses: the payload range of an `S` and the
/// checksum range of an `r`. The ranges of `w` and `B` are counted with no
/// check, as the tool counts them, and so are the mode and xattr indexes of an
/// `o`, on which the tool aborts where they leave the tables. The rules that
/// need the objects themselves -- an open object at `c`, every object produced
/// by the end -- are application's and are not checked here.
struct OpCounter<'a> {
    objects: &'a [(ObjectType, Checksum)],
    blob_len: u64,
    /// The object the next `S` produces, advanced by `S` and `c`.
    index: usize,
    pending: Option<PendingOp>,
    counts: DeltaOpCounts,
}

/// An operation whose operands are still arriving.
struct PendingOp {
    opcode: u8,
    need: usize,
    have: usize,
    operands: [u64; 4],
    /// The bytes of the operand being read. Eleven bytes always hold a value
    /// [`varint::decode`] refuses, so the buffer never needs to grow.
    leb: [u8; 11],
    leb_len: usize,
}

impl<'a> OpCounter<'a> {
    fn new(objects: &'a [(ObjectType, Checksum)], blob_len: u64) -> OpCounter<'a> {
        OpCounter {
            objects,
            blob_len,
            index: 0,
            pending: None,
            counts: DeltaOpCounts::default(),
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        for &byte in bytes {
            self.step(byte)?;
        }
        Ok(())
    }

    fn step(&mut self, byte: u8) -> Result<()> {
        let Some(op) = self.pending.as_mut() else {
            let meta =
                byte == OP_OPEN_SPLICE_CLOSE && object_at(self.objects, self.index)?.0.is_meta();
            let need = operand_count(byte, meta).ok_or_else(|| {
                Error::InvalidFormat(format!("unknown static delta opcode {byte:#x}"))
            })?;
            let op = PendingOp {
                opcode: byte,
                need,
                have: 0,
                operands: [0; 4],
                leb: [0; 11],
                leb_len: 0,
            };
            return if need == 0 {
                self.complete(&op)
            } else {
                self.pending = Some(op);
                Ok(())
            };
        };
        op.leb[op.leb_len] = byte;
        op.leb_len += 1;
        if byte & 0x80 != 0 && op.leb_len < op.leb.len() {
            return Ok(());
        }
        let (value, _) = varint::decode(&op.leb[..op.leb_len])?;
        op.operands[op.have] = value;
        op.have += 1;
        op.leb_len = 0;
        if op.have < op.need {
            return Ok(());
        }
        let op = self.pending.take().expect("an operation is pending");
        self.complete(&op)
    }

    fn complete(&mut self, op: &PendingOp) -> Result<()> {
        let [a, b, c, d] = op.operands;
        match op.opcode {
            OP_OPEN_SPLICE_CLOSE => {
                let (len, off) = if op.need == 2 { (a, b) } else { (c, d) };
                self.check_range(off, len)?;
                self.index += 1;
                self.counts.open_splice_close += 1;
            }
            OP_OPEN => self.counts.open += 1,
            OP_WRITE => self.counts.write += 1,
            OP_SET_READ_SOURCE => {
                self.check_range(a, 32)?;
                self.counts.set_read_source += 1;
            }
            OP_UNSET_READ_SOURCE => self.counts.unset_read_source += 1,
            OP_CLOSE => {
                self.index += 1;
                self.counts.close += 1;
            }
            _ => self.counts.bspatch += 1,
        }
        Ok(())
    }

    /// Refuse a range `[off, off + len)` that leaves the data-source blob.
    fn check_range(&self, off: u64, len: u64) -> Result<()> {
        off.checked_add(len)
            .filter(|end| *end <= self.blob_len)
            .map(|_| ())
            .ok_or_else(|| op_error("data-source range out of bounds"))
    }

    fn finish(self) -> Result<DeltaOpCounts> {
        if self.pending.is_some() {
            return Err(op_error("operation stream ends inside an operation"));
        }
        Ok(self.counts)
    }
}

/// Drain `reader` into a [`Blob`], keeping bytes on the heap until they exceed
/// [`MMAP_THRESHOLD`], then spilling to an anonymous temp file that is mmapped
/// read-only. A blob past the heap threshold costs staging-filesystem space and
/// address space, not resident heap.
///
/// `limit` is the number of bytes the stream is allowed to deliver, for a stream
/// whose length is declared ahead of it: a part file's body is read under the size
/// its meta-entry states, so a body that grew is refused at that ceiling instead
/// of filling the staging filesystem. A stream with nothing declared for it takes
/// `None` and is bounded by free disk the way the reference tool is: a spill that
/// would exhaust the filesystem fails when the write returns `ENOSPC`.
pub(crate) async fn spill_to_blob<R: AsyncRead + Unpin>(
    mut reader: R,
    staging: &OwnedFd,
    limit: Option<u64>,
) -> Result<Blob> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; IO_CHUNK];
    let mut total = 0usize;
    let mut spilled: Option<RtFile> = None;

    loop {
        let n = reader.read(&mut chunk).await.map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n)
            .ok_or_else(|| op_error("blob size overflows usize"))?;
        if let Some(limit) = limit
            && total as u64 > limit
        {
            return Err(op_error(&format!(
                "a stream passed the {limit} byte(s) declared for it"
            )));
        }
        match &mut spilled {
            Some(file) => file.write_all(&chunk[..n]).await.map_err(Error::Io)?,
            None if buf.len() + n <= MMAP_THRESHOLD => buf.extend_from_slice(&chunk[..n]),
            None => {
                let owned = staging.try_clone()?;
                let fd = ostrya_rt::unblock(move || open_rw_temp(owned.as_fd())).await?;
                let mut file = RtFile::from(fd);
                file.write_all(&buf).await.map_err(Error::Io)?;
                file.write_all(&chunk[..n]).await.map_err(Error::Io)?;
                buf = Vec::new();
                spilled = Some(file);
            }
        }
    }

    match spilled {
        None => Ok(Blob::Ram(buf)),
        Some(mut file) => {
            file.flush().await.map_err(Error::Io)?;
            let std_file = file.into_std().await;
            let len = total;
            let mmap = ostrya_rt::unblock(move || ostrya_sys::Mmap::read_only(&std_file, len))
                .await
                .map_err(|e| Error::Io(e.into()))?;
            Ok(Blob::Mapped(mmap))
        }
    }
}

/// Copy `slices`, in order, into one [`Blob`]: on the heap where they total
/// [`MMAP_THRESHOLD`] or less, and otherwise into one anonymous temp file in
/// `staging`, mapped read-only. A slice starts in the blob at the sum of the
/// lengths before it. The heap held after the call is [`MMAP_THRESHOLD`] at
/// most, whatever the number of slices.
pub(crate) async fn concat_to_blob(slices: &[&[u8]], staging: &OwnedFd) -> Result<Blob> {
    let total = slices
        .iter()
        .try_fold(0usize, |sum, slice| sum.checked_add(slice.len()))
        .ok_or_else(|| op_error("blob size overflows usize"))?;
    if total <= MMAP_THRESHOLD {
        return Ok(Blob::Ram(slices.concat()));
    }
    let owned = staging.try_clone()?;
    let fd = ostrya_rt::unblock(move || open_rw_temp(owned.as_fd())).await?;
    let mut file = RtFile::from(fd);
    for slice in slices {
        file.write_all(slice).await.map_err(Error::Io)?;
    }
    file.flush().await.map_err(Error::Io)?;
    let std_file = file.into_std().await;
    let mmap = ostrya_rt::unblock(move || ostrya_sys::Mmap::read_only(&std_file, total))
        .await
        .map_err(|e| Error::Io(e.into()))?;
    Ok(Blob::Mapped(mmap))
}

/// Open an anonymous read-write temp file on the staging filesystem: `O_TMPFILE`
/// where supported, a named temp unlinked immediately otherwise. Both yield a
/// readable-writable descriptor that needs no later cleanup.
pub(crate) fn open_rw_temp(staging: BorrowedFd<'_>) -> Result<OwnedFd> {
    use rustix::fs::{AtFlags, Mode, OFlags, openat, unlinkat};

    let mode = Mode::from_raw_mode(0o600);
    match openat(
        staging,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
        mode,
    ) {
        Ok(fd) => Ok(fd),
        Err(_) => {
            let name = format!(
                ".ostrya-delta-{}-{}",
                std::process::id(),
                crate::write::unique()
            );
            let fd = openat(
                staging,
                name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                mode,
            )
            .map_err(|e| Error::Io(e.into()))?;
            let _ = unlinkat(staging, name.as_str(), AtFlags::empty());
            Ok(fd)
        }
    }
}

/// Execute a part's operation stream, producing its objects into `txn`.
///
/// Objects are produced in `objects` order; the object type at the current index
/// determines whether an operation carries file metadata (mode and xattr
/// indices) or is a bare metadata splice. Each produced object is written with
/// its expected checksum, so a misapply fails at the write rather than storing a
/// wrong object. The mode and xattr tables are small (format-bounded) and are
/// collected up front; the data source and operation stream borrow the part
/// blob, and object payloads stream to disk without buffering the whole object.
///
/// `checks` holds the mode checks a content object this part produces is subject
/// to: what the caller's flags require and what the destination mode requires.
/// They are made on the part's own mode and xattr tables, before the object's
/// bytes are written, so a delta delivers no object a loose fetch of the same
/// object would be refused.
pub(crate) async fn apply_part(
    txn: &Transaction,
    payload: &[u8],
    objects: &[(ObjectType, Checksum)],
    staging: &OwnedFd,
    checks: ModeChecks,
) -> Result<()> {
    let view: PartView<'_> = GvDecode::decode(payload).map_err(ostrya_core::Error::from)?;
    let (mode_it, xattr_it, data_source, ops) = view;

    // The (uuu) mode triples are big-endian on the wire regardless of the
    // superblock endianness byte, so they are byte-swapped here to host order.
    // The mode and xattr tables are bounded metadata (a handful of distinct
    // triples and xattr sets), so they are collected onto the heap; their
    // combined footprint is capped at the metadata ceiling so a hostile part
    // cannot force an unbounded table copy.
    let mut table_bytes = 0usize;
    let mut modes: Vec<(u32, u32, u32)> = Vec::new();
    for entry in mode_it {
        let (u, g, m) = entry.map_err(ostrya_core::Error::from)?;
        table_bytes = bump_table(table_bytes, 12)?;
        modes.push((u.swap_bytes(), g.swap_bytes(), m.swap_bytes()));
    }

    let mut xattrs: Vec<Xattrs> = Vec::new();
    for entry in xattr_it {
        let entry = entry.map_err(ostrya_core::Error::from)?;
        let mut pairs = Vec::new();
        for pair in entry {
            let (name, value) = pair.map_err(ostrya_core::Error::from)?;
            table_bytes = bump_table(table_bytes, name.len() + value.len())?;
            pairs.push((name.to_vec(), value.to_vec()));
        }
        xattrs.push(Xattrs::new(pairs)?);
    }

    let mut cur = 0usize;
    let mut index = 0usize;
    let mut source = SourceCache::default();
    let mut open: Option<OpenState> = None;

    while cur < ops.len() {
        let opcode = ops[cur];
        cur += 1;
        match opcode {
            OP_OPEN_SPLICE_CLOSE => {
                let (objtype, csum) = object_at(objects, index)?;
                if objtype.is_meta() {
                    let len = take_leb(ops, &mut cur)? as usize;
                    let off = take_leb(ops, &mut cur)? as usize;
                    // A spliced metadata object is buffered whole (it re-hashes
                    // to its checksum), so it is held to the metadata ceiling.
                    if len > crate::object::MAX_METADATA_SIZE as usize {
                        return Err(op_error(
                            "spliced metadata object exceeds the metadata ceiling",
                        ));
                    }
                    let bytes = slice(data_source, off, len)?;
                    txn.write_metadata(objtype, Some(&csum), bytes).await?;
                } else {
                    let mode_idx = take_leb(ops, &mut cur)? as usize;
                    let xattr_idx = take_leb(ops, &mut cur)? as usize;
                    let len = take_leb(ops, &mut cur)? as usize;
                    let off = take_leb(ops, &mut cur)? as usize;
                    let bytes = slice(data_source, off, len)?;
                    write_content_slice(
                        txn, &modes, &xattrs, mode_idx, xattr_idx, bytes, &csum, checks,
                    )
                    .await?;
                }
                index += 1;
            }
            OP_OPEN => {
                let mode_idx = take_leb(ops, &mut cur)? as usize;
                let xattr_idx = take_leb(ops, &mut cur)? as usize;
                let out_size = take_leb(ops, &mut cur)? as usize;
                let (objtype, csum) = object_at(objects, index)?;
                let meta = if objtype.is_meta() {
                    None
                } else {
                    let meta = file_meta(&modes, &xattrs, mode_idx, xattr_idx)?;
                    // Before the content writer opens, so a refused object
                    // writes nothing.
                    checks.check(&csum, &meta)?;
                    Some(meta)
                };
                // A metadata object or a symlink target buffers whole on the
                // heap ([`Sink::Buffer`]), so its declared size is held to the
                // metadata ceiling. A regular file streams to the content writer,
                // so its size is bounded by the staging filesystem rather than a
                // fixed ceiling; `close_object` asserts the produced size equals
                // `out_size` and the content writer asserts the checksum.
                let streams = matches!(&meta, Some(m) if m.mode & S_IFMT != S_IFLNK);
                if !streams && out_size > crate::object::MAX_METADATA_SIZE as usize {
                    return Err(op_error("open object size exceeds the metadata ceiling"));
                }
                open = Some(open_object(txn, objtype, csum, out_size, meta).await?);
            }
            OP_BSPATCH => {
                let stream_off = take_leb(ops, &mut cur)? as usize;
                let stream_len = take_leb(ops, &mut cur)? as usize;
                let read_source = source
                    .active()
                    .ok_or_else(|| op_error("bspatch without a read source"))?;
                let obj = open
                    .as_mut()
                    .ok_or_else(|| op_error("bspatch without an open object"))?;
                let stream = slice(data_source, stream_off, stream_len)?;
                let remaining = obj
                    .out_size
                    .checked_sub(obj.sink.produced())
                    .ok_or_else(|| op_error("bspatch output exceeds the open size"))?;
                bspatch(read_source, stream, remaining, &mut obj.sink).await?;
            }
            OP_CLOSE => {
                let obj = open
                    .take()
                    .ok_or_else(|| op_error("close without an open object"))?;
                close_object(txn, obj).await?;
                index += 1;
            }
            OP_SET_READ_SOURCE => {
                let off = take_leb(ops, &mut cur)? as usize;
                let csum = Checksum::from_ay(slice(data_source, off, 32)?)?;
                source.set(txn, &csum, staging).await?;
            }
            OP_UNSET_READ_SOURCE => {
                source.unset();
            }
            OP_WRITE => {
                // The rollsum `write` op appends `length` bytes to the open
                // object, read at `offset` in the current source: the read-source
                // object when one is set, the part's data source otherwise. The
                // tool emits it for from->to deltas of larger objects, copying
                // unchanged runs out of the source object and carrying only the
                // changed runs in the payload.
                let length = take_leb(ops, &mut cur)? as usize;
                let off = take_leb(ops, &mut cur)? as usize;
                let from = source.active().unwrap_or(data_source);
                let obj = open
                    .as_mut()
                    .ok_or_else(|| op_error("write without an open object"))?;
                let remaining = obj
                    .out_size
                    .checked_sub(obj.sink.produced())
                    .ok_or_else(|| op_error("write output exceeds the open size"))?;
                if length > remaining {
                    return Err(op_error("write output exceeds the open size"));
                }
                let bytes = slice(from, off, length)?;
                for chunk in bytes.chunks(IO_CHUNK) {
                    obj.sink.write_all(chunk).await.map_err(Error::Io)?;
                }
            }
            other => {
                return Err(Error::InvalidFormat(format!(
                    "unknown static delta opcode {other:#x}"
                )));
            }
        }
    }

    if open.is_some() {
        return Err(op_error("operation stream ended with an object still open"));
    }
    if index != objects.len() {
        return Err(op_error(
            "operation stream produced fewer objects than declared",
        ));
    }
    Ok(())
}

/// State for an object opened by `open` and finished by `close`.
struct OpenState<'t> {
    objtype: ObjectType,
    csum: Checksum,
    out_size: usize,
    /// The file metadata for a content object; `None` for a metadata object.
    meta: Option<FileMeta>,
    sink: Sink<'t>,
}

/// The output sink for an opened object: a bounded in-memory buffer for a
/// metadata object or a symlink target, or the streaming content writer for a
/// regular file.
enum Sink<'t> {
    Buffer(Vec<u8>),
    Content {
        // Boxed: a `ContentWriter` is far larger than the buffer variant.
        writer: Box<ContentWriter<'t>>,
        written: usize,
    },
}

impl Sink<'_> {
    /// The number of object bytes produced so far.
    fn produced(&self) -> usize {
        match self {
            Sink::Buffer(buf) => buf.len(),
            Sink::Content { written, .. } => *written,
        }
    }
}

impl AsyncWrite for Sink<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Sink::Buffer(v) => {
                v.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }
            Sink::Content { writer, written } => {
                let n = ready!(Pin::new(&mut **writer).poll_write(cx, buf))?;
                *written += n;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Sink::Buffer(_) => Poll::Ready(Ok(())),
            Sink::Content { writer, .. } => Pin::new(&mut **writer).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Sink::Buffer(_) => Poll::Ready(Ok(())),
            Sink::Content { writer, .. } => Pin::new(&mut **writer).poll_close(cx),
        }
    }
}

/// Open the sink for the object at the current index: a content writer for a
/// regular file, a buffer for a metadata object (`meta` is `None`) or a symlink.
async fn open_object<'t>(
    txn: &'t Transaction,
    objtype: ObjectType,
    csum: Checksum,
    out_size: usize,
    meta: Option<FileMeta>,
) -> Result<OpenState<'t>> {
    let sink = match &meta {
        Some(m) if m.mode & S_IFMT != S_IFLNK => Sink::Content {
            writer: Box::new(txn.content_writer(Some(&csum), m).await?),
            written: 0,
        },
        // A metadata object or a symlink target accumulates in a buffer.
        _ => Sink::Buffer(Vec::new()),
    };
    Ok(OpenState {
        objtype,
        csum,
        out_size,
        meta,
        sink,
    })
}

/// Finish an opened object: assert its produced size and write it out, letting
/// the content writer's `finish` or the metadata/symlink write assert the
/// checksum.
async fn close_object(txn: &Transaction, obj: OpenState<'_>) -> Result<()> {
    let OpenState {
        objtype,
        csum,
        out_size,
        meta,
        sink,
    } = obj;
    if sink.produced() != out_size {
        return Err(op_error("closed object size does not match its open size"));
    }
    match sink {
        Sink::Buffer(buf) => {
            if objtype.is_meta() {
                txn.write_metadata(objtype, Some(&csum), &buf).await?;
            } else {
                let meta = meta.ok_or_else(|| op_error("content object without metadata"))?;
                let target = std::str::from_utf8(&buf)
                    .map_err(|_| op_error("symlink target is not valid UTF-8"))?;
                txn.write_symlink(target, &meta, Some(&csum)).await?;
            }
        }
        Sink::Content { writer, .. } => {
            (*writer).finish().await?;
        }
    }
    Ok(())
}

/// Write a content object (a regular file or a symlink) spliced from `content`,
/// with the mode and xattrs the part's tables supply. A regular file streams to
/// disk in bounded chunks; a symlink takes the bytes as its target.
#[allow(clippy::too_many_arguments)]
async fn write_content_slice(
    txn: &Transaction,
    modes: &[(u32, u32, u32)],
    xattrs: &[Xattrs],
    mode_idx: usize,
    xattr_idx: usize,
    content: &[u8],
    expected: &Checksum,
    checks: ModeChecks,
) -> Result<()> {
    let meta = file_meta(modes, xattrs, mode_idx, xattr_idx)?;
    // Before either writer opens, so a refused object writes nothing.
    checks.check(expected, &meta)?;
    if meta.mode & S_IFMT == S_IFLNK {
        let target = std::str::from_utf8(content)
            .map_err(|_| op_error("symlink target is not valid UTF-8"))?;
        txn.write_symlink(target, &meta, Some(expected)).await?;
    } else {
        let mut writer = txn.content_writer(Some(expected), &meta).await?;
        for chunk in content.chunks(IO_CHUNK) {
            writer.write_all(chunk).await.map_err(Error::Io)?;
        }
        writer.finish().await?;
    }
    Ok(())
}

/// Build the file metadata for the object at `mode_idx`/`xattr_idx`.
fn file_meta(
    modes: &[(u32, u32, u32)],
    xattrs: &[Xattrs],
    mode_idx: usize,
    xattr_idx: usize,
) -> Result<FileMeta> {
    let &(uid, gid, mode) = modes
        .get(mode_idx)
        .ok_or_else(|| op_error("mode index out of range"))?;
    let xattrs = xattrs
        .get(xattr_idx)
        .ok_or_else(|| op_error("xattr index out of range"))?
        .clone();
    Ok(FileMeta {
        uid,
        gid,
        mode,
        xattrs,
    })
}

/// The read source the `r`/`R` ops select, holding the loaded object across the
/// pairs that name it.
///
/// A part sets and unsets the read source once per contiguous run it copies out
/// of the source object, so a heavily modified object names the same source
/// dozens of times: the 4 MiB object of a delta with forty scattered edits
/// carries forty-one `r` ops. Reloading on each one would re-read and re-spill
/// the whole object every time, so the loaded blob outlives the `R` that ends a
/// run and a later `r` naming the same checksum reuses it. Objects are
/// content-addressed, so a checksum match means identical bytes and the reuse
/// needs no revalidation. At most one source object is held: a different
/// checksum drops the previous blob (releasing its temp file and mapping) before
/// loading the next.
#[derive(Default)]
struct SourceCache {
    loaded: Option<(Checksum, Blob)>,
    /// Whether an `r` op currently has the loaded source selected. `R` clears
    /// this without dropping the blob, so a `write` op with no read source falls
    /// back to the part's data source as the format requires.
    active: bool,
}

impl SourceCache {
    /// Select `checksum` as the read source, loading it unless it is already
    /// held.
    async fn set(
        &mut self,
        txn: &Transaction,
        checksum: &Checksum,
        staging: &OwnedFd,
    ) -> Result<()> {
        if !matches!(&self.loaded, Some((held, _)) if held == checksum) {
            // Drop any previously held source first, so the peak cost is one
            // source object's temp file and mapping rather than two.
            self.loaded = None;
            self.loaded = Some((*checksum, load_source_blob(txn, checksum, staging).await?));
        }
        self.active = true;
        Ok(())
    }

    /// Deselect the read source, keeping it loaded for a later `r`.
    fn unset(&mut self) {
        self.active = false;
    }

    /// The selected read source's bytes, or `None` when no `r` op is in effect.
    fn active(&self) -> Option<&[u8]> {
        self.active
            .then_some(self.loaded.as_ref())
            .flatten()
            .map(|(_, blob)| blob.as_slice())
    }
}

/// Load a content object as a random-access [`Blob`] for use as a bspatch or
/// rollsum source, checking the current transaction's staged objects before the
/// repository. The object streams through its reader into the same spill path as
/// a part payload, so a large source object is mmapped rather than held on the
/// heap.
async fn load_source_blob(
    txn: &Transaction,
    checksum: &Checksum,
    staging: &OwnedFd,
) -> Result<Blob> {
    let file = txn.load_file_staged_first(checksum).await?;
    let reader = file.reader().await?;
    spill_to_blob(reader, staging, None).await
}

/// Read a whole file into a size-bounded buffer, off the async thread. Used for
/// the superblock, which is bounded metadata.
///
/// The read stops one byte past the ceiling, whatever the file is: a device or a
/// FIFO states no length, so the ceiling is applied to the bytes read.
pub(crate) async fn read_capped(path: PathBuf) -> Result<Vec<u8>> {
    read_under(path, MAX_SUPERBLOCK).await
}

/// [`read_capped`] under a ceiling of `cap` bytes.
async fn read_under(path: PathBuf, cap: u64) -> Result<Vec<u8>> {
    ostrya_rt::unblock(move || {
        use std::io::Read;
        let file = std::fs::File::open(&path)?;
        let mut bytes = Vec::new();
        file.take(cap + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > cap {
            return Err(std::io::Error::other(format!(
                "static delta file {} exceeds the size ceiling",
                path.display()
            )));
        }
        Ok(bytes)
    })
    .await
    .map_err(Error::Io)
}

/// Decode one LEB128 operand from `ops` at `*cur`, advancing the cursor.
fn take_leb(ops: &[u8], cur: &mut usize) -> Result<u64> {
    let (value, consumed) = varint::decode(&ops[*cur..])?;
    *cur += consumed;
    Ok(value)
}

/// Borrow `data[off..off + len]`, erroring on an out-of-range range.
fn slice(data: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    let end = off
        .checked_add(len)
        .ok_or_else(|| op_error("data-source range overflow"))?;
    data.get(off..end)
        .ok_or_else(|| op_error("data-source range out of bounds"))
}

/// Look up the object at `index`, erroring when the stream runs past the list.
fn object_at(objects: &[(ObjectType, Checksum)], index: usize) -> Result<(ObjectType, Checksum)> {
    objects
        .get(index)
        .copied()
        .ok_or_else(|| op_error("operation stream produced more objects than declared"))
}

fn op_error(msg: &str) -> Error {
    Error::InvalidFormat(format!("static delta: {msg}"))
}

/// Add `n` bytes to a running mode/xattr table footprint, failing once the
/// combined tables would exceed [`MAX_TABLE_BYTES`].
fn bump_table(total: usize, n: usize) -> Result<usize> {
    total
        .checked_add(n)
        .filter(|t| *t <= MAX_TABLE_BYTES)
        .ok_or_else(|| op_error("mode/xattr tables exceed the metadata ceiling"))
}

// --- Value tree accessors ------------------------------------------------

pub(crate) fn tuple(value: &Value) -> Result<&[Value]> {
    match value {
        Value::Tuple(fields) => Ok(fields),
        _ => Err(Error::InvalidFormat("expected a GVariant tuple".to_owned())),
    }
}

fn array(value: &Value) -> Result<&[Value]> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(Error::InvalidFormat("expected a GVariant array".to_owned())),
    }
}

pub(crate) fn bytes_field<'a>(value: &'a Value, what: &str) -> Result<&'a [u8]> {
    value
        .as_bytes()
        .ok_or_else(|| Error::InvalidFormat(format!("expected {what} to be a byte array")))
}

fn byte_field(value: &Value, what: &str) -> Result<u8> {
    value
        .as_byte()
        .ok_or_else(|| Error::InvalidFormat(format!("expected {what} to be a byte")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_rt::block_on;

    /// A directory descriptor for the spill path. Every part here is far below
    /// [`MMAP_THRESHOLD`], so no temp file is opened through it.
    fn staging_fd() -> OwnedFd {
        use rustix::fs::{Mode, OFlags, open};
        open(
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    /// A meta-entry naming a part file of `file` bytes, declaring `size` for it.
    fn meta_entry(file: &[u8], size: u64) -> DeltaPart {
        DeltaPart {
            part_csum: Checksum::sha256(file),
            size,
            uncompressed_size: 0,
            objects: Vec::new(),
        }
    }

    /// One meta-entry tuple `(uayttay)` declaring `size`.
    fn meta_entry_value(size: u64) -> Value {
        Value::Tuple(vec![
            Value::U32(0),
            Value::Bytes(Checksum::from_bytes([0x11; 32]).as_bytes().to_vec()),
            Value::U64(size),
            Value::U64(0),
            Value::Bytes(Vec::new()),
        ])
    }

    /// A superblock metadata dict carrying one `ostree.endianness` byte.
    fn endianness_dict(byte: u8) -> Value {
        let mut dict = Value::Array(Vec::new());
        crate::commit::append_dict_entry(
            &mut dict,
            ENDIANNESS_KEY,
            Value::variant(Type::parse("y").unwrap(), Value::Byte(byte)),
        )
        .unwrap();
        dict
    }

    /// An uncompressed part reads back as its payload, and a body longer than the
    /// meta-entry declares is refused at that ceiling -- here with a checksum that
    /// covers the longer body, so the size is what stops it.
    #[test]
    fn a_part_body_is_read_under_the_declared_size() {
        block_on(async {
            let staging = staging_fd();
            let payload = b"a part payload";
            let mut file = vec![COMPRESSION_NONE];
            file.extend_from_slice(payload);
            let declared = file.len() as u64;

            let entry = meta_entry(&file, declared);
            let blob = decode_part_stream(Cursor::new(file.clone()), &entry, &staging)
                .await
                .unwrap();
            assert_eq!(blob.as_slice(), payload);

            let mut longer = file;
            longer.extend_from_slice(b"and more");
            let entry = meta_entry(&longer, declared);
            let Err(err) = decode_part_stream(Cursor::new(longer), &entry, &staging).await else {
                panic!("a body past the declared size was accepted");
            };
            assert!(
                err.to_string()
                    .contains(&format!("{} byte(s) declared", payload.len())),
                "{err}"
            );
        });
    }

    /// The part checksum is asserted before the decoder runs: a part declaring xz
    /// whose body is not an xz stream is refused for what it is, and the decoder
    /// never sees the body.
    #[test]
    fn a_swapped_part_body_fails_its_checksum_before_the_decoder_runs() {
        block_on(async {
            let staging = staging_fd();
            let mut file = vec![COMPRESSION_XZ];
            file.extend_from_slice(b"not an xz stream at all");
            let entry = meta_entry(b"a different part file", file.len() as u64);
            let Err(err) = decode_part_stream(Cursor::new(file), &entry, &staging).await else {
                panic!("a part whose body was swapped was accepted");
            };
            assert!(err.to_string().contains("part checksum mismatch"), "{err}");
        });
    }

    /// A meta-entry's size is host order, which the `ostree.endianness` byte
    /// declares, so a big-endian producer's field is swapped back.
    #[test]
    fn a_meta_entry_size_follows_the_endianness_byte() {
        let little = parse_meta_entries(&[meta_entry_value(8733)], false).unwrap();
        assert_eq!(little[0].size, 8733);
        let big = parse_meta_entries(&[meta_entry_value(8733u64.swap_bytes())], true).unwrap();
        assert_eq!(big[0].size, 8733);

        assert!(declares_big_endian(&endianness_dict(ENDIANNESS_BIG)));
        assert!(!declares_big_endian(&endianness_dict(ENDIANNESS_LITTLE)));
        // A superblock stating nothing reads as little-endian.
        assert!(!declares_big_endian(&Value::Array(Vec::new())));
    }

    /// The part payload type, as a delta generator writes it.
    const PART_SIG: &str = "(a(uuu)aa(ayay)ayay)";

    /// A metadata object and a content object, the two arities of `S`.
    fn two_objects() -> Vec<(ObjectType, Checksum)> {
        vec![
            (ObjectType::DirTree, Checksum::from_bytes([0x01; 32])),
            (ObjectType::File, Checksum::from_bytes([0x02; 32])),
        ]
    }

    /// The LEB128 encoding of an operation and its operands.
    fn op(opcode: u8, operands: &[u64]) -> Vec<u8> {
        let mut out = vec![opcode];
        for &operand in operands {
            varint::encode(operand, &mut out);
        }
        out
    }

    /// One of every opcode against a 64-byte blob: a metadata splice, a
    /// content splice, then an object built from a payload write, a read
    /// source, a write against it, and a bspatch.
    fn every_opcode() -> Vec<u8> {
        [
            op(OP_OPEN_SPLICE_CLOSE, &[3, 0]),
            op(OP_OPEN_SPLICE_CLOSE, &[0, 0, 5, 3]),
            op(OP_OPEN, &[0, 0, 300]),
            op(OP_WRITE, &[8, 8]),
            op(OP_SET_READ_SOURCE, &[16]),
            op(OP_WRITE, &[1_000_000, 0]),
            op(OP_BSPATCH, &[48, 16]),
            op(OP_UNSET_READ_SOURCE, &[]),
            op(OP_CLOSE, &[]),
        ]
        .concat()
    }

    fn every_opcode_counts() -> DeltaOpCounts {
        DeltaOpCounts {
            open_splice_close: 2,
            open: 1,
            write: 2,
            set_read_source: 1,
            unset_read_source: 1,
            close: 1,
            bspatch: 1,
        }
    }

    /// Operands split across feeds decode the same as a stream fed whole: a
    /// multi-byte operand may end one chunk and finish in the next.
    #[test]
    fn the_op_counter_reads_operands_split_across_chunks() {
        let objects = two_objects();
        let stream = every_opcode();

        let mut whole = OpCounter::new(&objects, 64);
        whole.feed(&stream).unwrap();
        assert_eq!(whole.finish().unwrap(), every_opcode_counts());

        let mut bytewise = OpCounter::new(&objects, 64);
        for byte in &stream {
            bytewise.feed(std::slice::from_ref(byte)).unwrap();
        }
        assert_eq!(bytewise.finish().unwrap(), every_opcode_counts());
    }

    /// `S` reads two operands for a metadata object and four for a content
    /// object: the same bytes count as two splices or as one.
    #[test]
    fn the_op_counter_takes_the_splice_arity_from_the_object_type() {
        let stream = op(OP_OPEN_SPLICE_CLOSE, &[1, 2, 3, 4]);

        let meta = [
            (ObjectType::DirTree, Checksum::from_bytes([0x01; 32])),
            (ObjectType::DirMeta, Checksum::from_bytes([0x02; 32])),
        ];
        // `(1, 2)` then `(3, 4)`: two metadata splices, the second `S` byte
        // being the opcode read from the stream's third byte.
        let mut two = OpCounter::new(&meta, 64);
        two.feed(&[OP_OPEN_SPLICE_CLOSE, 1, 2, OP_OPEN_SPLICE_CLOSE, 3, 4])
            .unwrap();
        assert_eq!(two.finish().unwrap().open_splice_close, 2);

        let file = [(ObjectType::File, Checksum::from_bytes([0x03; 32]))];
        let mut one = OpCounter::new(&file, 64);
        one.feed(&stream).unwrap();
        assert_eq!(one.finish().unwrap().open_splice_close, 1);
    }

    /// The counter refuses the streams the tool's `static-delta show` refuses
    /// on their bytes alone, and counts the `w`, `B`, and `o` operands the tool
    /// counts unchecked.
    #[test]
    fn the_op_counter_refuses_what_the_tools_show_refuses() {
        let objects = two_objects();
        let refused = |stream: &[u8]| {
            let mut counter = OpCounter::new(&objects, 64);
            match counter.feed(stream) {
                Err(err) => err.to_string(),
                Ok(()) => counter
                    .finish()
                    .expect_err("the stream was counted")
                    .to_string(),
            }
        };

        assert!(refused(b"X").contains("unknown static delta opcode 0x58"));
        assert!(refused(&[OP_OPEN, 0x80]).contains("ends inside an operation"));
        assert!(refused(&[OP_OPEN, 0]).contains("ends inside an operation"));
        let mut long = vec![OP_SET_READ_SOURCE];
        long.extend_from_slice(&[0xff; 11]);
        assert!(refused(&long).contains("varint"), "{}", refused(&long));
        assert!(refused(&op(OP_SET_READ_SOURCE, &[33])).contains("out of bounds"));
        assert!(refused(&op(OP_OPEN_SPLICE_CLOSE, &[3, 62])).contains("out of bounds"));
        let past_the_list = [
            op(OP_OPEN_SPLICE_CLOSE, &[1, 0]),
            op(OP_OPEN_SPLICE_CLOSE, &[0, 0, 1, 0]),
            vec![OP_OPEN_SPLICE_CLOSE],
        ]
        .concat();
        assert!(refused(&past_the_list).contains("more objects than declared"));
        // A close with no open object is application's refusal, not the
        // counter's.
        let mut closes = OpCounter::new(&objects, 64);
        closes.feed(&[OP_CLOSE, OP_CLOSE]).unwrap();
        assert_eq!(closes.finish().unwrap().close, 2);

        // Ranges past the blob in `w` with no read source and in `B`, and an
        // `o` whose xattr index is outside any table, are counted.
        let unchecked = [
            op(OP_WRITE, &[65, 0]),
            op(OP_BSPATCH, &[u64::MAX, 2]),
            op(OP_OPEN, &[0, 5, 0]),
        ]
        .concat();
        let mut counter = OpCounter::new(&objects, 64);
        counter.feed(&unchecked).unwrap();
        let counts = counter.finish().unwrap();
        assert_eq!((counts.write, counts.bspatch, counts.open), (1, 1, 1));
    }

    /// A part payload of `modes` mode entries, `xattrs` xattr sets, a `blob`
    /// of `blob_len` bytes, and `ops`.
    fn payload(modes: usize, xattrs: usize, blob_len: usize, ops: &[u8]) -> Vec<u8> {
        let modes = (0..modes)
            .map(|i| Value::Tuple(vec![Value::U32(0), Value::U32(0), Value::U32(i as u32)]))
            .collect();
        let xattrs = (0..xattrs)
            .map(|i| {
                Value::Array(
                    (0..i)
                        .map(|j| {
                            Value::Tuple(vec![
                                Value::Bytes(format!("user.k{j}\0").into_bytes()),
                                Value::Bytes(vec![b'v'; j]),
                            ])
                        })
                        .collect(),
                )
            })
            .collect();
        let value = Value::Tuple(vec![
            Value::Array(modes),
            Value::Array(xattrs),
            Value::Bytes(vec![0x5a; blob_len]),
            Value::Bytes(ops.to_vec()),
        ]);
        to_bytes(&Type::parse(PART_SIG).unwrap(), &value).unwrap()
    }

    /// A part file around `payload`, compressed with `compression`, and the
    /// meta-entry naming it.
    fn part_file(
        payload: &[u8],
        compression: u8,
        objects: Vec<(ObjectType, Checksum)>,
    ) -> (Vec<u8>, DeltaPart) {
        let mut file = vec![compression];
        if compression == COMPRESSION_XZ {
            block_on(async {
                let mut encoder = async_compression::futures::write::XzEncoder::new(Vec::new());
                encoder.write_all(payload).await.unwrap();
                encoder.close().await.unwrap();
                file.extend_from_slice(&encoder.into_inner());
            });
        } else {
            file.extend_from_slice(payload);
        }
        let entry = DeltaPart {
            part_csum: Checksum::sha256(&file),
            size: file.len() as u64,
            uncompressed_size: 0,
            objects,
        };
        (file, entry)
    }

    /// A metadata dict carrying `value` under `<dir>/<index>`.
    fn inline_dict(dir: &str, index: usize, value: Value) -> Value {
        let mut dict = endianness_dict(ENDIANNESS_LITTLE);
        crate::commit::append_dict_entry(&mut dict, &format!("{dir}/{index}"), value).unwrap();
        dict
    }

    /// The `(yay)` variant an inline part is carried as.
    fn inline_value(compression: u8, body: &[u8]) -> Value {
        Value::variant(
            Type::parse(INLINE_PART_SIG).unwrap(),
            Value::Tuple(vec![Value::Byte(compression), Value::Bytes(body.to_vec())]),
        )
    }

    /// The inline part at `index` of `dict`, looked up as a superblock does.
    fn lookup<'a>(
        dict: &'a Value,
        dir: &str,
        parts: usize,
        index: usize,
    ) -> Result<Option<(u8, &'a [u8])>> {
        let found = index_inline_parts(dict, dir, parts);
        inline_part_at(dict, &found, index, || dir.to_owned())
    }

    /// An inline part is borrowed from the dict under its own key, an absent
    /// key reads as no inline part, and a value of another type is refused.
    #[test]
    fn an_inline_part_is_borrowed_from_the_metadata_dict() {
        let dir = "deltas/ab/cdef";
        let dict = inline_dict(dir, 0, inline_value(COMPRESSION_XZ, b"body"));
        assert_eq!(
            lookup(&dict, dir, 2, 0).unwrap(),
            Some((COMPRESSION_XZ, &b"body"[..]))
        );
        assert_eq!(lookup(&dict, dir, 2, 1).unwrap(), None);
        assert_eq!(lookup(&dict, "deltas/ab/other", 2, 0).unwrap(), None);
        // A part number no meta-entry has is not looked up.
        assert_eq!(lookup(&dict, dir, 0, 0).unwrap(), None);

        let ay = Value::variant(Type::parse("ay").unwrap(), Value::Bytes(b"xbody".to_vec()));
        let dict = inline_dict(dir, 0, ay);
        let Err(Error::InvalidFormat(message)) = lookup(&dict, dir, 1, 0) else {
            panic!("an inline part that is not a (yay) variant was accepted");
        };
        assert!(message.contains("deltas/ab/cdef/0"), "{message}");
    }

    /// The one-pass index reads the keys a lookup by key reads: the first
    /// entry under a key wins, and a part number written with a sign, a
    /// leading zero, or a trailing character is another key.
    #[test]
    fn the_inline_index_takes_the_first_entry_under_the_exact_key() {
        let dir = "deltas/ab/cdef";
        let mut dict = inline_dict(dir, 1, inline_value(COMPRESSION_NONE, b"first"));
        for (key, body) in [
            (format!("{dir}/1"), &b"second"[..]),
            (format!("{dir}/01"), b"leading zero"),
            (format!("{dir}/+0"), b"sign"),
            (format!("{dir}/0x"), b"trailing"),
            (format!("{dir}0"), b"no slash"),
            (format!("{dir}/0"), b"zero"),
        ] {
            crate::commit::append_dict_entry(&mut dict, &key, inline_value(COMPRESSION_NONE, body))
                .unwrap();
        }
        let index = index_inline_parts(&dict, dir, 3);
        assert_eq!(index, [Some(7), Some(1), None]);
        let read = |part| inline_part_at(&dict, &index, part, || dir.to_owned()).unwrap();
        assert_eq!(read(0), Some((COMPRESSION_NONE, &b"zero"[..])));
        assert_eq!(read(1), Some((COMPRESSION_NONE, &b"first"[..])));
        assert_eq!(read(2), None);
    }

    /// An inline part is held to the rules a part file is read under, each
    /// checked before any decoder runs: the declared size, the checksum, and
    /// the compression byte.
    #[test]
    fn an_inline_part_is_checked_against_its_size_and_checksum() {
        let (file, entry) = part_file(b"a part payload", COMPRESSION_XZ, Vec::new());
        verify_inline_part(file[0], &file[1..], &entry).unwrap();

        let short = DeltaPart {
            size: entry.size - 1,
            ..entry.clone()
        };
        let err = verify_inline_part(file[0], &file[1..], &short).unwrap_err();
        assert!(err.to_string().contains("byte(s) declared"), "{err}");

        let mut swapped = file.clone();
        let last = swapped.len() - 1;
        swapped[last] ^= 0xff;
        let err = verify_inline_part(swapped[0], &swapped[1..], &entry).unwrap_err();
        assert!(err.to_string().contains("part checksum mismatch"), "{err}");

        let mut odd = file.clone();
        odd[0] = b'z';
        let odd_entry = meta_entry(&odd, odd.len() as u64);
        let err = verify_inline_part(odd[0], &odd[1..], &odd_entry).unwrap_err();
        assert!(err.to_string().contains("compression byte"), "{err}");
    }

    /// An uncompressed inline body is the payload where it lies, and an xz
    /// body decodes into a blob.
    #[test]
    fn an_uncompressed_inline_part_decodes_without_a_blob() {
        let body = b"a part payload";
        // `part_file` drives its own executor, so it runs outside this one.
        let (file, _) = part_file(body, COMPRESSION_XZ, Vec::new());
        block_on(async {
            let staging = staging_fd();
            let payload = decode_inline_part(COMPRESSION_NONE, body, &staging)
                .await
                .unwrap();
            let InlinePayload::Borrowed(bytes) = payload else {
                panic!("an uncompressed inline body was copied");
            };
            assert!(std::ptr::eq(bytes, &body[..]));

            let payload = decode_inline_part(file[0], &file[1..], &staging)
                .await
                .unwrap();
            assert!(matches!(payload, InlinePayload::Owned(_)));
            assert_eq!(payload.as_slice(), body);
        });
    }

    /// `part_stats` reads an inline part through the seekable source as it
    /// reads the same bytes from a part file, compressed or not.
    #[test]
    fn an_inline_part_reads_the_same_statistics_as_its_file() {
        // A blob past the kept tail makes the uncompressed walk seek back.
        for (blob_len, compression) in [
            (1_000, COMPRESSION_NONE),
            (1_000, COMPRESSION_XZ),
            (2 * PAYLOAD_TAIL, COMPRESSION_NONE),
        ] {
            let bytes = payload(3, 2, blob_len, &every_opcode());
            let (file, entry) = part_file(&bytes, compression, two_objects());
            let from_file = block_on(part_stats_from(Cursor::new(file.clone()), &entry)).unwrap();
            let source = InlineSource {
                compression: file[0],
                body: &file[1..],
                pos: 0,
            };
            let inline = block_on(part_stats_from(source, &entry)).unwrap();
            assert_eq!(inline, from_file);
        }
    }

    /// The framing offsets are read at the width the payload's total length
    /// gives, 1, 2, or 4 bytes, compressed or not.
    #[test]
    fn a_part_payload_frames_at_every_offset_width() {
        let ops = every_opcode();
        for (blob_len, width) in [(64usize, 1usize), (1_000, 2), (70_000, 4)] {
            let bytes = payload(3, 2, blob_len, &ops);
            assert_eq!(offset_size_for(bytes.len()), width);
            for compression in [COMPRESSION_NONE, COMPRESSION_XZ] {
                let (file, entry) = part_file(&bytes, compression, two_objects());
                let stats = block_on(part_stats_from(Cursor::new(file), &entry)).unwrap();
                assert_eq!(
                    stats,
                    DeltaPartStats {
                        modes: 3,
                        xattrs: 2,
                        blob_size: blob_len as u64,
                        ops_size: ops.len() as u64,
                        ops: every_opcode_counts(),
                    },
                    "blob {blob_len}, compression {compression:#x}"
                );
            }
        }

        // An all-metadata part carries empty tables.
        let bytes = payload(0, 0, 3, &op(OP_OPEN_SPLICE_CLOSE, &[3, 0]));
        let (file, entry) = part_file(&bytes, COMPRESSION_XZ, two_objects());
        let stats = block_on(part_stats_from(Cursor::new(file), &entry)).unwrap();
        assert_eq!((stats.modes, stats.xattrs, stats.blob_size), (0, 0, 3));
        assert_eq!(stats.ops.open_splice_close, 1);
    }

    /// A part whose checksum does not match, or whose file passes its declared
    /// size, is refused before any byte reaches the decoder.
    #[test]
    fn a_part_that_fails_its_checksum_is_refused_before_decoding() {
        let bytes = payload(1, 1, 64, &every_opcode());
        let (mut file, entry) = part_file(&bytes, COMPRESSION_NONE, two_objects());
        let last = file.len() - 1;
        file[last] ^= 0xff;
        let err = block_on(part_stats_from(Cursor::new(file.clone()), &entry)).unwrap_err();
        assert!(err.to_string().contains("part checksum mismatch"), "{err}");

        file.push(0);
        let err = block_on(part_stats_from(Cursor::new(file), &entry)).unwrap_err();
        assert!(err.to_string().contains("byte(s) declared for it"), "{err}");

        // A swapped body declaring xz fails the checksum, not the decoder.
        let mut swapped = vec![COMPRESSION_XZ];
        swapped.extend_from_slice(b"not an xz stream");
        let entry = DeltaPart {
            size: swapped.len() as u64,
            ..entry
        };
        let err = block_on(part_stats_from(Cursor::new(swapped), &entry)).unwrap_err();
        assert!(err.to_string().contains("part checksum mismatch"), "{err}");
    }

    /// A payload whose operation stream and xattr framing lie in the kept
    /// tail is read once past the verify pass. A large blob ahead of a short
    /// stream leaves the xattr framing outside the tail, and a stream longer
    /// than the tail leaves both outside it. Every walk gives the same counts,
    /// compressed or not.
    #[test]
    fn a_part_payload_reads_again_only_what_the_tail_misses() {
        let small_ops = every_opcode();
        let long_ops = [every_opcode(), vec![OP_UNSET_READ_SOURCE; PAYLOAD_TAIL]].concat();
        for (blob_len, ops, walk) in [
            (64usize, &small_ops, TailWalk::TailOnly),
            (PAYLOAD_TAIL + 64, &small_ops, TailWalk::ToXattrs),
            (64, &long_ops, TailWalk::Full),
        ] {
            let bytes = payload(3, 2, blob_len, ops);
            let mut counts = every_opcode_counts();
            counts.unset_read_source += (ops.len() - small_ops.len()) as u64;
            for compression in [COMPRESSION_NONE, COMPRESSION_XZ] {
                let (file, entry) = part_file(&bytes, compression, two_objects());
                let (stats, took) = block_on(part_stats_walk(Cursor::new(file), &entry)).unwrap();
                assert_eq!(took, walk, "blob {blob_len}, compression {compression:#x}");
                assert_eq!(
                    stats,
                    DeltaPartStats {
                        modes: 3,
                        xattrs: 2,
                        blob_size: blob_len as u64,
                        ops_size: ops.len() as u64,
                        ops: counts,
                    },
                    "blob {blob_len}, compression {compression:#x}"
                );
            }
        }
    }

    /// The tail ring keeps the last bytes of pushes of every size.
    #[test]
    fn the_tail_ring_keeps_the_last_bytes() {
        let stream: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        for step in [1usize, 3, 7, 10, 11, 64, 1000] {
            let mut tail = Tail::new(10);
            for piece in stream.chunks(step) {
                tail.push(piece);
            }
            assert_eq!(tail.into_vec(), stream[990..], "step {step}");
        }
        let mut short = Tail::new(10);
        short.push(b"abc");
        assert_eq!(short.into_vec(), b"abc");
    }

    /// The CRC-32 of `bytes`, the check an xz block header carries.
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
            }
        }
        !crc
    }

    /// An xz part whose block header states a 1.5 GiB dictionary is refused at
    /// the decoder memory limit, before the dictionary is allocated.
    #[test]
    fn a_part_stating_a_huge_xz_dictionary_is_refused() {
        let bytes = payload(0, 0, 3, &op(OP_OPEN_SPLICE_CLOSE, &[3, 0]));
        let (mut file, _) = part_file(&bytes, COMPRESSION_XZ, two_objects());
        // The block header follows the 12-byte stream header, after the
        // compression byte: a size byte, no flags, the LZMA2 filter with one
        // property byte, padding, and its CRC-32.
        let header = 1 + 12;
        assert_eq!(file[header..header + 4], [0x02, 0x00, 0x21, 0x01]);
        file[header + 4] = 37;
        let crc = crc32(&file[header..header + 8]);
        file[header + 8..header + 12].copy_from_slice(&crc.to_le_bytes());
        let entry = DeltaPart {
            part_csum: Checksum::sha256(&file),
            size: file.len() as u64,
            uncompressed_size: 0,
            objects: two_objects(),
        };
        let err = block_on(part_stats_from(Cursor::new(file), &entry)).unwrap_err();
        assert!(
            err.to_string()
                .contains("needs more than 128 MiB of xz decoder memory"),
            "{err}"
        );
    }

    /// A superblock file past the ceiling is refused on the bytes read, one at
    /// the ceiling is read whole, and a device that states no length is read
    /// only up to one byte past the ceiling.
    #[test]
    fn a_superblock_file_is_read_under_the_ceiling() {
        let dir = std::env::temp_dir().join(format!("ostrya-read-capped-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("superblock");
        std::fs::write(&path, [7u8; 16]).unwrap();
        assert_eq!(block_on(read_under(path.clone(), 16)).unwrap(), [7u8; 16]);
        let err = block_on(read_under(path, 15)).unwrap_err();
        assert!(
            err.to_string().contains("exceeds the size ceiling"),
            "{err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();

        let err = block_on(read_under(PathBuf::from("/dev/zero"), 16)).unwrap_err();
        assert!(
            err.to_string().contains("exceeds the size ceiling"),
            "{err}"
        );
    }

    /// A superblock whose embedded commit hashes to its target, with the given
    /// metadata dict, raw timestamp field, recursion field, meta-entries, and
    /// fallbacks.
    fn superblock(
        metadata: Value,
        timestamp: u64,
        recursion: usize,
        entries: Vec<Value>,
        fallbacks: Vec<Value>,
    ) -> Vec<u8> {
        let commit = Value::Tuple(vec![
            Value::Array(Vec::new()),
            Value::Bytes(Vec::new()),
            Value::Array(Vec::new()),
            Value::Str("subject".into()),
            Value::Str(String::new()),
            Value::U64(0),
            Value::Bytes(vec![0x11; 32]),
            Value::Bytes(vec![0x22; 32]),
        ]);
        let commit_bytes = to_bytes(&Type::parse(COMMIT_SIG).unwrap(), &commit).unwrap();
        let to = Checksum::sha256(&commit_bytes);
        let value = Value::Tuple(vec![
            metadata,
            Value::U64(timestamp),
            Value::Bytes(Vec::new()),
            Value::Bytes(to.as_bytes().to_vec()),
            commit,
            Value::Bytes(vec![0; recursion]),
            Value::Array(entries),
            Value::Array(fallbacks),
        ]);
        to_bytes(&Type::parse(SUPERBLOCK_SIG).unwrap(), &value).unwrap()
    }

    /// One fallback tuple `(yaytt)` with the two raw size fields.
    fn fallback_value(size: u64, uncompressed: u64) -> Value {
        Value::Tuple(vec![
            Value::Byte(ObjectType::File as u8),
            Value::Bytes(vec![0x33; 32]),
            Value::U64(size),
            Value::U64(uncompressed),
        ])
    }

    /// Under `B` the meta-entry `size` and `usize` and both fallback sizes are
    /// swapped; under `l` none is.
    #[test]
    fn a_big_endian_superblock_swaps_every_size_field() {
        let entry = |size: u64, usize: u64| {
            Value::Tuple(vec![
                Value::U32(0),
                Value::Bytes(vec![0x11; 32]),
                Value::U64(size),
                Value::U64(usize),
                Value::Bytes(Vec::new()),
            ])
        };
        let big = DeltaSuperblock::parse(superblock(
            endianness_dict(ENDIANNESS_BIG),
            0,
            0,
            vec![entry(237u64.swap_bytes(), 163u64.swap_bytes())],
            vec![fallback_value(
                5_001_564u64.swap_bytes(),
                5_000_000u64.swap_bytes(),
            )],
        ))
        .unwrap();
        assert_eq!(big.endianness(), DeltaEndianness::Big);
        assert_eq!(
            (big.parts()[0].size(), big.parts()[0].uncompressed_size()),
            (237, 163)
        );
        assert_eq!(
            (
                big.fallbacks()[0].size(),
                big.fallbacks()[0].uncompressed_size()
            ),
            (5_001_564, 5_000_000)
        );

        let little = DeltaSuperblock::parse(superblock(
            endianness_dict(ENDIANNESS_LITTLE),
            0,
            0,
            vec![entry(237, 163)],
            vec![fallback_value(5_001_564, 5_000_000)],
        ))
        .unwrap();
        assert_eq!(little.endianness(), DeltaEndianness::Little);
        assert_eq!(little.parts()[0].uncompressed_size(), 163);
        assert_eq!(little.fallbacks()[0].size(), 5_001_564);
    }

    /// The timestamp field is big-endian whatever the endianness byte states.
    #[test]
    fn the_timestamp_reads_big_endian() {
        for byte in [ENDIANNESS_LITTLE, ENDIANNESS_BIG] {
            let sb = DeltaSuperblock::parse(superblock(
                endianness_dict(byte),
                // The field's bytes are the big-endian form of the value, which
                // the serializer writes from their little-endian reading.
                u64::from_le_bytes(1_700_000_000u64.to_be_bytes()),
                0,
                Vec::new(),
                Vec::new(),
            ))
            .unwrap();
            assert_eq!(sb.timestamp(), 1_700_000_000, "byte {byte}");
        }
    }

    /// The parent count is field 5's byte length over 64, rounded down.
    #[test]
    fn the_parent_count_is_field_five_over_64() {
        for (len, parents) in [(0, 0), (63, 0), (64, 1), (130, 2)] {
            let sb = DeltaSuperblock::parse(superblock(
                Value::Array(Vec::new()),
                0,
                len,
                Vec::new(),
                Vec::new(),
            ))
            .unwrap();
            assert_eq!(sb.parent_count(), parents, "field 5 of {len} bytes");
        }
    }
}
