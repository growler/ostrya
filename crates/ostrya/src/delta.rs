//! Static-delta reads, offline application, and the part reads of a pull.
//!
//! Maintainer notes. The public items hold the text for the reader:
//!
//! - the format, the checks, and the memory rules: [`DeltaSuperblock`] and
//!   [`Repo::apply_static_delta_offline`]
//! - the signed envelope: [`DeltaSuperblock::verify`]
//! - the three passes of a part read: [`DeltaSuperblock::part_stats`]
//!
//! An HTTP pull uses the same superblock parse and the same part application.
//! It reads each part from a fetched response body, and it applies the part
//! into the transaction of the pull.

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
use ostrya_rt::{File as RtFile, FileReader};
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

/// The size limit of a superblock. The parse reads the superblock whole onto
/// the heap as one GVariant tree, so the limit is the metadata limit. The
/// superblock holds the embedded target commit (a metadata object) and the
/// part and fallback tables, which are all bounded metadata.
pub(crate) const MAX_SUPERBLOCK: u64 = crate::object::MAX_METADATA_SIZE;

/// The heap limit of a decompressed part payload or a source object. A larger
/// one goes to a temp file, mapped read-only. It costs address space and file
/// cache that loads on demand, and no resident heap.
pub(crate) const MMAP_THRESHOLD: usize = 128 * 1024;

/// The chunk size of the object payload streams to and from disk.
pub(crate) const IO_CHUNK: usize = 128 * 1024;

/// The limit of the combined heap size of the mode and xattr tables of a part.
/// The tables are bounded metadata, so they go onto the heap under the
/// metadata limit. A hostile table size fails at the limit and causes no
/// unbounded copy.
pub(crate) const MAX_TABLE_BYTES: usize = crate::object::MAX_METADATA_SIZE as usize;

/// The zero-copy view of a decompressed part payload
/// `(a(uuu) aa(ayay) ay ay)`: the mode table, the xattr table, the data-source
/// blob, and the operation stream. The two trailing byte arrays borrow the
/// backing payload with no copy.
type PartView<'a> = (
    ArrayIter<'a, (u32, u32, u32)>,
    ArrayIter<'a, ArrayIter<'a, (&'a [u8], &'a [u8])>>,
    &'a [u8],
    &'a [u8],
);

/// A parsed static-delta superblock.
///
/// A static delta describes the objects of a target commit. It carries them
/// whole, or as patches against the objects of a source commit. This type
/// reads a delta that the `ostree` command wrote or that
/// [`Repo::generate_static_delta`] wrote. It holds the fields that
/// `ostree static-delta show` reports and the fields that an application
/// reads.
///
/// [`read`](DeltaSuperblock::read) reads a superblock file, signed or not.
/// [`part_stats`](DeltaSuperblock::part_stats) reads what one part holds
/// and does not apply it. [`Repo::apply_static_delta`] applies the parsed
/// superblock.
///
/// # Format
///
/// The format is observed on the files that the `ostree` command writes. A
/// delta directory holds a `superblock` file and the part files `0`, `1`, and
/// so on.
///
/// The superblock is a GVariant of type
/// `(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))`. Its fields are,
/// in order:
///
/// - the metadata: `ostree.endianness`, a copy of the detached metadata of
///   the target commit, and the parts that the superblock carries inline
/// - the generation timestamp, big-endian
/// - the source commit, empty for a delta from scratch
/// - the target commit
/// - the target commit object, embedded whole
/// - the recursion array, which the `ostree` command and ostrya write empty.
///   A parse accepts any length, and
///   [`parent_count`](DeltaSuperblock::parent_count) reports it.
/// - one [meta-entry](DeltaPart) for each part: the part checksum, the
///   object list, and two sizes
/// - the [fallback objects](DeltaFallback)
///
/// A part is a compressed GVariant. It holds a mode table, an xattr table, a
/// data-source blob, and an operation stream. An application runs the
/// operation stream against the data-source blob and the objects of the
/// source commit.
///
/// [`Repo::generate_static_delta`]: crate::Repo::generate_static_delta
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
    /// The raw superblock bytes, which the signatures cover. Empty for an
    /// unsigned superblock, because no signature verification reads them.
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

/// The meta-entry of one part of a static delta.
///
/// The meta-entry names the checksum and the size of the part file. It also
/// names the size of what the part delivers, and the objects that the part
/// produces, in order. In the superblock it is a `(uayttay)` tuple. The object list holds
/// 33 bytes for each object: the object type byte, then the 32-byte checksum.
#[derive(Debug, Clone)]
pub struct DeltaPart {
    pub(crate) part_csum: Checksum,
    /// The on-disk size of the part file, with the compression byte. Before
    /// `part_csum` is verified, a part fetch takes at most this many bytes off
    /// the connection. A part read has the same limit.
    pub(crate) size: u64,
    /// The `usize` field: the sum of the sizes of the objects of the part.
    pub(crate) uncompressed_size: u64,
    pub(crate) objects: Vec<(ObjectType, Checksum)>,
}

impl DeltaPart {
    /// Returns the SHA-256 of the part file, with the compression byte.
    pub fn checksum(&self) -> &Checksum {
        &self.part_csum
    }

    /// Returns the size of the part file in bytes, with the compression byte.
    ///
    /// A part fetch and a part read take in at most this many bytes before
    /// they verify the [`checksum`](DeltaPart::checksum).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the `usize` field: the sum of the sizes of the part objects.
    ///
    /// The value is the one that the producer of the delta wrote.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// Returns the objects that the part produces, in the order of its operations.
    pub fn objects(&self) -> &[(ObjectType, Checksum)] {
        &self.objects
    }
}

/// An object that a static delta delivers as a loose object, outside its parts.
///
/// In the superblock a fallback is a `(yaytt)` tuple: the object type, the
/// checksum, and two sizes.
#[derive(Debug, Clone)]
pub struct DeltaFallback {
    pub(crate) objtype: ObjectType,
    pub(crate) checksum: Checksum,
    /// The size of the loose object in the repository that wrote the delta.
    pub(crate) size: u64,
    /// The content size of the object.
    pub(crate) uncompressed_size: u64,
}

impl DeltaFallback {
    /// Returns the type of the fallback object.
    pub fn object_type(&self) -> ObjectType {
        self.objtype
    }

    /// Returns the checksum of the fallback object.
    pub fn checksum(&self) -> &Checksum {
        &self.checksum
    }

    /// Returns the size of the loose object in the repository that wrote the delta.
    ///
    /// This is the compressed size field of the fallback.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the content size of the object: the uncompressed size field.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }
}

/// The byte order of the host-order size fields of a superblock.
///
/// The `ostree.endianness` metadata byte declares the order. It applies to the
/// `size` and `usize` fields of a meta-entry and to the two sizes of a
/// fallback. If a superblock has no such byte, or a byte other than `B`, the
/// fields read as little-endian. [`DeltaOptions::endianness`](crate::DeltaOptions::endianness)
/// selects the order that the generator writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaEndianness {
    /// Little-endian.
    ///
    /// A read gives this value if the byte is `l`, absent, or another value. A
    /// write puts the byte `l` and writes the four fields little-endian.
    Little,
    /// Big-endian.
    ///
    /// A read gives this value if the byte is `B`. A write puts the byte `B`
    /// and writes the four fields big-endian.
    Big,
}

/// The table sizes, the blob size, and the operation counts of one part.
///
/// [`DeltaSuperblock::part_stats`] reads these values and applies nothing.
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

/// The number of operations of each opcode in the operation stream of a part.
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

/// Methods that apply, verify, list, and delete static deltas.
impl Repo {
    /// Applies the static delta in `dir` and returns the target commit.
    ///
    /// The call reads `dir/superblock` and writes the target commit and its
    /// objects into the repository in one transaction. The transaction holds
    /// the repository lock shared ([`LockKind`](crate::LockKind)). The call
    /// sets no ref: the caller decides that.
    ///
    /// # Parts
    ///
    /// If the superblock carries part `<index>` inline, under the metadata key
    /// `<relative_dir>/<index>`, the call reads the part from the metadata.
    /// Otherwise it reads the file `dir/<index>`. If both are present, the call
    /// uses the inline part. An inline part gets the size and checksum checks
    /// of a part file before it is decompressed.
    ///
    /// # Prerequisites
    ///
    /// If a part patches against a source commit, the objects of the source
    /// commit must be in the repository. The fallback objects of the delta
    /// must be in the repository too, because an offline application does not
    /// fetch them.
    ///
    /// # Verification
    ///
    /// The call runs the operation stream of each part against the data-source
    /// blob of the part and the objects of the source commit. It verifies the
    /// checksum of each object as it writes the object. So a malformed or
    /// misapplied delta fails and commits no wrong object.
    ///
    /// # Memory
    ///
    /// The memory that an application uses has a limit, whatever the size of
    /// a part:
    ///
    /// - The call reads a part file under the size that its meta-entry
    ///   declares. It verifies the SHA-256 of the part against the checksum of
    ///   the meta-entry before it decompresses a byte. A body that passes the
    ///   declared size never gets to the decoder.
    /// - An xz body then decompresses through the xz decoder of
    ///   `async-compression` into the payload that the operations read.
    /// - A payload of 128 KiB or less stays on the heap. A larger payload goes
    ///   to a temp file in the staging directory, mapped read-only. It costs
    ///   address space and staging space, and no resident heap.
    /// - The output of a splice and of a bspatch streams through the content
    ///   writer of the transaction. The source object of a bspatch goes to a
    ///   temp file in the same way. So the call holds no whole object in
    ///   memory.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if `dir/superblock` cannot be read or is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) bytes.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if the superblock does not
    ///   parse, as [`DeltaSuperblock::parse`] states.
    /// - Each error of [`apply_static_delta`](Repo::apply_static_delta).
    pub async fn apply_static_delta_offline(&self, dir: &Path) -> Result<Checksum> {
        let sb = DeltaSuperblock::read(&dir.join("superblock")).await?;
        self.apply_static_delta(sb, dir).await
    }

    /// Applies a superblock that is already read and returns the target commit.
    ///
    /// The part files are in `parts_dir`. The call does not read the
    /// superblock again, so a caller that verifies it with
    /// [`DeltaSuperblock::verify`] applies the bytes that it verified. The
    /// superblock file can have any name and can be in any directory.
    ///
    /// The call reads a part that the superblock carries inline from the
    /// superblock, and each other part from the file `parts_dir/<index>`. The
    /// other rules of [`apply_static_delta_offline`](Repo::apply_static_delta_offline)
    /// apply: the call verifies no signature, the fallback objects must be in
    /// the repository, and the call sets no ref.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if a fallback object of the delta, or a
    ///   source object that a part reads, is not in the repository.
    /// - [`Error::InvalidFormat`] if a part breaks the format:
    ///   - an inline part that is not a `(yay)` variant
    ///   - a part that passes its declared size or fails its checksum
    ///   - an unknown compression byte or opcode
    ///   - an operand range outside the data, or a mode or xattr index outside
    ///     its table
    ///   - a write, a bspatch, or a close with no open object, or a bspatch
    ///     with no read source
    ///   - a malformed bspatch stream
    ///   - an object of the wrong size or count
    ///   - mode and xattr tables larger than 128 MiB together, or a metadata
    ///     object or a symlink target larger than 128 MiB
    ///   - a symlink target that is not UTF-8
    /// - [`Error::Core`] if a part payload, an operand, a checksum, or an xattr
    ///   set does not decode.
    /// - [`Error::ChecksumMismatch`] if an object that a part produces does not
    ///   hash to the checksum that the part names for it.
    /// - [`Error::Pull`] if the repository is `bare-user-only` and a content
    ///   object has an owner, xattrs, or mode bits that this mode does not store.
    /// - [`Error::InsufficientFreeSpace`] if a write makes the free space less
    ///   than the reserve of the repository.
    /// - [`Error::LockTimeout`] if the wait for the repository lock passes
    ///   `[core] lock-timeout-secs`.
    /// - [`Error::Io`] if the object store, a part file, a temp file, or the
    ///   staging directory cannot be read or written.
    /// - [`Error::Io`] if an xz body does not decode.
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`,
    ///   which this crate does not write, or if `[ex-integrity] fsverity` is
    ///   `yes` and the seal of an object fails.
    pub async fn apply_static_delta(
        &self,
        mut sb: DeltaSuperblock,
        parts_dir: &Path,
    ) -> Result<Checksum> {
        // Nothing here verifies a signature, so the payload and the signatures
        // of a signed superblock are dropped before the parts are applied.
        drop(std::mem::take(&mut sb.superblock_bytes));
        sb.signatures = None;

        // The fallback objects that the delta names but does not carry must be
        // present, because an offline application does not fetch them. The
        // check runs against the repository first, so a missing prerequisite
        // fails before an object is staged.
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

        // An offline application has no pull flags, so the checks are those of
        // the destination. A bare-user-only repository stores an object under a
        // name that covers the canonical form alone. This check states that
        // rule, because the checksum check of the content writer does not see it.
        let checks = ModeChecks::new(PullFlags::empty(), self.mode());
        for (i, entry) in sb.meta_entries.iter().enumerate() {
            // A part that the superblock carries inline is read from there,
            // also if a part file of the same number is present.
            match sb.inline_part(i)? {
                Some((compression, body)) => {
                    verify_inline_part(compression, body, entry)?;
                    let payload = decode_inline_part(compression, body, &staging).await?;
                    apply_part(&txn, payload.as_slice(), &entry.objects, &staging, checks).await?;
                }
                None => {
                    let blob = decode_part(parts_dir.join(i.to_string()), entry, &staging).await?;
                    apply_part(&txn, blob.as_slice(), &entry.objects, &staging, checks).await?;
                }
            }
        }

        txn.commit().await?;
        Ok(sb.to)
    }

    /// Verifies the signatures of the static delta in `dir` against `verifiers`.
    ///
    /// The call reads `dir/superblock` and verifies it as
    /// [`DeltaSuperblock::verify`] does.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if `dir/superblock` cannot be read or is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) bytes.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if the superblock does not
    ///   parse, as [`DeltaSuperblock::parse`] states.
    /// - [`Error::Signature`] if the delta is not signed.
    /// - An error that a verifier returns, as [`Error::Signature`],
    ///   [`Error::InvalidFormat`], or [`Error::Core`].
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

    /// Returns the names of the static deltas in `deltas/`, sorted.
    ///
    /// Each name is the name that the `ostree` command uses. A delta from
    /// scratch has the target commit in hex. A delta from a source commit has
    /// `<from-hex>-<to-hex>`. The `delta-indexes/` cache advertises these
    /// deltas to a fetcher. [`reindex_static_deltas`](Repo::reindex_static_deltas)
    /// writes the cache, and a pull reads it.
    ///
    /// # Entries
    ///
    /// An entry `deltas/<fanout>/<rest>` is a delta only if `<fanout>` and
    /// `<rest>` are directories and `<rest>/superblock` resolves. The call
    /// follows no symlink at `<fanout>` or at `<rest>`. It follows a symlink at
    /// `superblock` and at `deltas` itself. A dangling symlink at `deltas`
    /// holds no delta.
    ///
    /// The call skips each other entry, also if its name does not decode.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if an entry holds a superblock and its name does not
    ///   decode to a checksum.
    /// - [`Error::Io`] if `deltas/` or a fanout directory cannot be read.
    /// - [`Error::Io`] if the superblock check of an entry fails with an error
    ///   other than `ENOENT` or `ENOTDIR`.
    pub async fn list_static_deltas(&self) -> Result<Vec<String>> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || list_static_deltas_blocking(repo_fd.as_fd())).await
    }

    /// Removes the static delta from `from` to `to`.
    ///
    /// If `from` is `None`, the delta is the delta from scratch to `to`.
    ///
    /// The call removes the entry at the path `deltas/<fanout>/<rest>` of the
    /// delta and all entries under it. The entry can be a directory tree, a
    /// regular file, or a directory with no superblock. If the entry is a
    /// symlink, the call removes the link and keeps its target. It follows no
    /// symlink under the path.
    ///
    /// The fanout directory stays, also if it becomes empty. `delta-indexes/`
    /// and `summary` do not change, so they can still name the delta.
    /// [`reindex_static_deltas`](Repo::reindex_static_deltas) and a new summary
    /// update them.
    ///
    /// The call takes no repository lock. A concurrent generation of the same
    /// delta can fail, or can leave a partial directory. A removal that fails
    /// leaves the entries that it did not reach.
    ///
    /// # Errors
    ///
    /// - [`Error::StaticDeltaNotFound`] if nothing resolves at the path. The
    ///   check follows symlinks, so a dangling symlink at the path gives this
    ///   error, and the symlink stays.
    /// - [`Error::Io`] if an entry cannot be read or removed, or if a directory
    ///   moves during the removal.
    pub async fn delete_static_delta(&self, from: Option<&Checksum>, to: &Checksum) -> Result<()> {
        let (from, to) = (from.copied(), *to);
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || {
            delete_static_delta_blocking(repo_fd.as_fd(), from.as_ref(), &to)
        })
        .await
    }
}

/// Removes the entry at the path `deltas/<fanout>/<rest>` of one delta. It
/// follows no symlink at or under that path.
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
    // The existence check follows symlinks, as the check of the `ostree`
    // command does: a dangling symlink at the path is an absent delta.
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

/// Scans `deltas/<fanout>/<leaf>` and returns the name that the `ostree`
/// command gives each delta, sorted.
fn list_static_deltas_blocking(repo_fd: BorrowedFd<'_>) -> Result<Vec<String>> {
    let mut names = scan_deltas(repo_fd, delta_name)?;
    names.sort();
    Ok(names)
}

/// Scans `deltas/<fanout>/<leaf>` and returns the source and target commit of
/// each delta, for the index cache.
pub(crate) fn list_delta_targets(
    repo_fd: BorrowedFd<'_>,
) -> Result<Vec<(Option<Checksum>, Checksum)>> {
    scan_deltas(repo_fd, parse_delta_dir)
}

/// Removes each `deltas/<fanout>/<leaf>` delta whose target commit `remove`
/// selects, for the prune sweep.
///
/// The walk is the walk of [`scan_deltas`]. The name is parsed and `remove`
/// is asked before the superblock check, so only a selected entry costs a
/// `statat`. A name that does not decode names no commit, so the sweep skips
/// it and leaves the entry in place. A directory with no superblock is no
/// delta. The sweep leaves it, as the prune of the `ostree` command does.
///
/// The key of a delta is the commit that it produces, so a delta whose source
/// commit `remove` selects stays. A delta directory is removed whole, with
/// its nested directories, through the fanout descriptor that the walk holds.
/// No symlink at the fanout, at the delta path, or under it is followed.
///
/// An entry at the delta path that is not a directory stays. The fanout
/// directory stays, empty if the delta was its last entry. A directory that is
/// already gone is a success. The `delta-indexes/` cache does not change, as
/// with the prune of the `ostree` command.
pub(crate) fn prune_delta_dirs(
    repo_fd: BorrowedFd<'_>,
    remove: impl Fn(&Checksum) -> bool,
) -> Result<()> {
    use rustix::io::Errno;

    walk_deltas(repo_fd, |fan_fd, fanout, leaf| {
        let Ok((_, to)) = parse_delta_dir(fanout, leaf) else {
            return Ok(());
        };
        if !remove(&to) || !has_superblock(fan_fd, leaf)? {
            return Ok(());
        }
        let leaf = CString::new(leaf).expect("a directory entry name holds no NUL");
        // The no-follow directory open refuses a symlink and every other
        // non-directory at the delta path with `ENOTDIR` or `ELOOP`, and that
        // entry stays.
        match open_dir_nofollow(fan_fd, &leaf) {
            Ok(level) => remove_dir_tree(fan_fd, &leaf, level),
            Err(Errno::NOTDIR | Errno::LOOP | Errno::NOENT) => Ok(()),
            Err(e) => Err(Error::Io(e.into())),
        }
    })
}

/// Removes the directory `name` under `parent`, open as `dir`, and all entries
/// under it. It follows no symlink, and it unlinks a symlink under it as a link.
///
/// The removal is a loop over an explicit stack of levels. It holds at most
/// two directory descriptors of its own at a time, whatever the depth. These
/// are the level in hand, and the child or the `..` that it opens next. A descent
/// replaces the descriptor of the level with the descriptor of the child. An
/// ascent replaces it with the descriptor that `..` opens. That descriptor
/// names the parent, because the emptied level is still linked where it was
/// opened.
///
/// Each level keeps the device and inode of its directory. The descriptor
/// that `..` opens must match the recorded parent. So if a concurrent rename
/// moves a directory, the removal stops and does not follow the directory.
/// Depth costs a name and an entry list on the heap, so a tree deeper than
/// the process descriptor limit is removed whole.
///
/// A directory is read through the descriptor that opened it, which needs
/// read permission alone. A child directory with no entries is removed from
/// its parent at once, so an empty directory with no search permission goes
/// too. Names are kept as bytes, so a name that is not UTF-8 is removed too.
/// An entry that is gone before the removal gets to it is skipped.
fn remove_dir_tree(parent: BorrowedFd<'_>, name: &CStr, dir: OwnedFd) -> Result<()> {
    use rustix::fs::{AtFlags, Dir};
    use rustix::io::Errno;

    let io_err = |e: Errno| Error::Io(e.into());
    let identity = dir_identity(dir.as_fd())?;
    let mut level = Dir::new(dir).map_err(io_err)?;
    // One entry for each level on the path from `name` down to the level in
    // hand. An entry holds the name of the level, its device and inode, and
    // what is left to remove in it.
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

/// Unlinks `name` under `dir`. A name that is already gone is a success.
fn unlink_tree_entry(dir: BorrowedFd<'_>, name: &CStr, flags: rustix::fs::AtFlags) -> Result<()> {
    match rustix::fs::unlinkat(dir, name, flags) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Opens the directory `name` under `dir`. It follows no symlink.
fn open_dir_nofollow(dir: BorrowedFd<'_>, name: &CStr) -> rustix::io::Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, openat};

    openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Returns the device and inode of an open directory.
fn dir_identity(dir: BorrowedFd<'_>) -> Result<(u64, u64)> {
    let st = rustix::fs::fstat(dir).map_err(|e| Error::Io(e.into()))?;
    Ok((st.st_dev, st.st_ino))
}

/// Returns the entries of one directory level, each with a flag that is `true`
/// for a directory.
///
/// `getdents64` already carries the type. If a file system reports
/// [`FileType::Unknown`](rustix::fs::FileType::Unknown), one no-follow
/// `statat` for that name alone gives the type. A name that is gone when that
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

/// Walks the two-level `deltas/` tree and applies `parse` to the fanout and
/// leaf directory names of each delta. A repository with no `deltas/` gives
/// nothing.
///
/// A fanout and a leaf count only if they are directories, and no symlink at
/// either is followed. A symlink at `deltas` itself is followed, as the
/// `ostree` command follows it. A leaf counts as a delta only if
/// `<leaf>/superblock` resolves with symlinks followed, which is the rule of
/// the `ostree` command. Each other entry is skipped before its name is
/// parsed, so such an entry with a malformed name is skipped too.
///
/// The entry type comes from the directory read. Only a file system that
/// reports no type costs one more no-follow `statat` for each entry. No
/// superblock byte is read.
fn scan_deltas<T>(
    repo_fd: BorrowedFd<'_>,
    parse: impl Fn(&str, &str) -> Result<T>,
) -> Result<Vec<T>> {
    let mut out = Vec::new();
    walk_deltas(repo_fd, |fan_fd, fanout, leaf| {
        if has_superblock(fan_fd, leaf)? {
            out.push(parse(fanout, leaf)?);
        }
        Ok(())
    })?;
    Ok(out)
}

/// Walks the two-level `deltas/` tree and calls `visit` with the fanout
/// descriptor, the fanout name, and the leaf name of each leaf directory. A
/// repository with no `deltas/` visits nothing.
///
/// A fanout and a leaf count only if they are directories and their names
/// are UTF-8, and no symlink at either is followed. A symlink at `deltas`
/// itself is followed. The walk opens `deltas/` once and each fanout once. It
/// reads the leaves of a fanout in full before the first call, so `visit` can
/// remove a leaf through the descriptor that it gets.
fn walk_deltas(
    repo_fd: BorrowedFd<'_>,
    mut visit: impl FnMut(BorrowedFd<'_>, &str, &str) -> Result<()>,
) -> Result<()> {
    use rustix::fs::{Dir, Mode, OFlags, openat};
    use rustix::io::Errno;

    let io_err = |e: Errno| Error::Io(e.into());

    let deltas = match openat(
        repo_fd,
        "deltas",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(()),
        Err(e) => return Err(io_err(e)),
    };

    let mut deltas = Dir::new(deltas).map_err(io_err)?;
    for (fanout, is_dir) in read_tree_level(&mut deltas)? {
        // Delta directory names are base64, so a name that is not UTF-8 is
        // not a fanout.
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
            visit(fan_dir.fd().map_err(io_err)?, fanout_name, leaf_name)?;
        }
    }
    Ok(())
}

/// Returns `true` if `<leaf>/superblock` resolves under the fanout `fan_fd`,
/// with symlinks followed. This is the rule of the `ostree` command for a
/// delta.
fn has_superblock(fan_fd: BorrowedFd<'_>, leaf: &str) -> Result<bool> {
    use rustix::fs::{AtFlags, statat};
    use rustix::io::Errno;

    match statat(
        fan_fd,
        format!("{leaf}/superblock").as_str(),
        AtFlags::empty(),
    ) {
        Ok(_) => Ok(true),
        Err(Errno::NOENT | Errno::NOTDIR) => Ok(false),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Returns the child names of an open directory, without `.`, `..`, and names
/// that are not UTF-8. Delta directory names are base64, so they are UTF-8.
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

/// Returns the source and target commit of a delta from its
/// `deltas/<fanout>/<leaf>` directory names. The leaf holds a `-`, which
/// base64 never holds, if and only if the delta is from a source commit.
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

/// Returns the hex name of a delta from its `deltas/<fanout>/<leaf>` directory.
fn delta_name(fanout: &str, leaf: &str) -> Result<String> {
    let (from, to) = parse_delta_dir(fanout, leaf)?;
    Ok(delta_hex_name(from.as_ref(), &to))
}

/// Returns the hex name of a delta as the `ostree` command names it: the
/// target hex for a delta from scratch, and `<from-hex>-<to-hex>` otherwise.
pub(crate) fn delta_hex_name(from: Option<&Checksum>, to: &Checksum) -> String {
    match from {
        Some(from) => format!("{}-{}", from.to_hex(), to.to_hex()),
        None => to.to_hex(),
    }
}

impl DeltaSuperblock {
    /// Parses the bytes of a superblock file, signed or not.
    ///
    /// If the bytes start with the magic of the signed envelope, the call
    /// unwraps the envelope and keeps its signatures. The call verifies that
    /// the embedded commit object hashes to the target commit checksum.
    ///
    /// The call drops the file bytes after it decodes them. It moves the
    /// payload of a signed envelope out of the decoded envelope with no copy.
    /// So the parse holds at most two copies of the superblock at a time: the
    /// bytes and the tree decoded from them.
    ///
    /// A signed superblock keeps its payload after the parse, because
    /// [`verify`](DeltaSuperblock::verify) reads it. An unsigned superblock
    /// keeps no raw bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if the bytes are not a GVariant of the superblock type
    ///   or of the envelope type.
    /// - [`Error::Core`] if a checksum or an object type does not decode.
    /// - [`Error::InvalidFormat`] if a field has the wrong type, or if an
    ///   object list is not a multiple of 33 bytes.
    /// - [`Error::InvalidFormat`] if the embedded commit does not hash to the
    ///   target commit checksum.
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
        // Only a signature verification reads the raw bytes, so an unsigned
        // superblock drops them here.
        let superblock_bytes = if signatures.is_some() {
            payload
        } else {
            drop(payload);
            Vec::new()
        };
        let fields = tuple(&value)?;

        // The `ostree.endianness` metadata byte sets the order of the
        // meta-entry and fallback size fields. The byte is read here, and those
        // fields are swapped for a big-endian producer. The timestamp and the
        // `(uuu)` modes are always big-endian, and the embedded commit is
        // normal-form little-endian, so nothing else here depends on the byte.
        let big_endian = declares_big_endian(&fields[0]);
        // GVariant decodes the `t` little-endian. The field is big-endian.
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

        // Serialize the embedded commit again to its normal-form bytes, and
        // verify the target checksum on the commit that the delta carries.
        let commit_ty = Type::parse(COMMIT_SIG).map_err(ostrya_core::Error::from)?;
        let commit_bytes = to_bytes(&commit_ty, &fields[4]).map_err(ostrya_core::Error::from)?;
        if Checksum::sha256(&commit_bytes) != to {
            return Err(Error::InvalidFormat(
                "static delta embedded commit does not match the target checksum".to_owned(),
            ));
        }

        let meta_entries = parse_meta_entries(array(&fields[6])?, big_endian)?;
        let fallbacks = parse_fallbacks(array(&fields[7])?, big_endian)?;

        // The metadata dict moves out of the parsed tree with no copy, because
        // it can carry inline parts.
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

    /// Reads a superblock file and parses it.
    ///
    /// The file can be at most [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE)
    /// bytes. The read stops one byte past that limit, also for a device or a
    /// FIFO that states no length.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the file cannot be read or is larger than the limit.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if the bytes do not parse,
    ///   as [`parse`](DeltaSuperblock::parse) states.
    pub async fn read(path: &Path) -> Result<DeltaSuperblock> {
        DeltaSuperblock::parse(read_capped(path.to_owned()).await?)
    }

    /// Returns the source commit, or `None` for a delta from scratch.
    pub fn from_commit(&self) -> Option<&Checksum> {
        self.from.as_ref()
    }

    /// Returns the target commit.
    pub fn to_commit(&self) -> &Checksum {
        &self.to
    }

    /// Returns `true` if the superblock file is a signed envelope.
    pub fn is_signed(&self) -> bool {
        self.signatures.is_some()
    }

    /// Verifies the signatures of the signed envelope against `verifiers`.
    ///
    /// Each verifier gets the raw superblock bytes that the envelope wraps,
    /// which are the signed payload. It also gets the signature blobs that
    /// the envelope stores under its engine key. A verifier with no blob under its engine key
    /// examines no signature. The outcome is valid if any verifier reports a
    /// valid signature. The superblock file can have any name.
    ///
    /// # Signed envelope
    ///
    /// A signed superblock file is a GVariant of type `(taya{sv})`. Its fields
    /// are the magic, stored as the eight ASCII bytes `OSTSGNDT`, the raw
    /// superblock bytes, and the signatures under the key of each engine.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if the superblock has no signed envelope.
    /// - An error that a verifier returns, as [`Error::Signature`],
    ///   [`Error::InvalidFormat`], or [`Error::Core`].
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

    /// Returns the byte order that the `ostree.endianness` byte declares.
    pub fn endianness(&self) -> DeltaEndianness {
        if declares_big_endian(&self.metadata) {
            DeltaEndianness::Big
        } else {
            DeltaEndianness::Little
        }
    }

    /// Returns the generation timestamp, in seconds since the Unix epoch.
    ///
    /// The field is big-endian, whatever the `ostree.endianness` byte states.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Returns the parent count that `ostree static-delta show` reports.
    ///
    /// The count is the byte length of the recursion array, field 5, divided
    /// by 64 and rounded down.
    pub fn parent_count(&self) -> usize {
        self.recursion_len / 64
    }

    /// Returns the meta-entries of the parts, in part order.
    pub fn parts(&self) -> &[DeltaPart] {
        &self.meta_entries
    }

    /// Returns the fallback objects, in superblock order.
    pub fn fallbacks(&self) -> &[DeltaFallback] {
        &self.fallbacks
    }

    /// Returns the directory of the delta, relative to the repository root.
    ///
    /// The path is `deltas/<fanout>/<rest>`, built from the source and target
    /// commits.
    pub fn relative_dir(&self) -> String {
        crate::deltagen::delta_relative_dir(self.from.as_ref(), &self.to)
    }

    /// Returns part `index` as the superblock carries it inline: its
    /// compression byte and its body, borrowed from the metadata dict. `None`
    /// if the dict holds no key for it.
    pub(crate) fn inline_part(&self, index: usize) -> Result<Option<(u8, &[u8])>> {
        inline_part_at(&self.metadata, &self.inline_index, index, || {
            self.relative_dir()
        })
    }

    /// Reads what part `index` holds and does not apply it.
    ///
    /// If the superblock carries the part inline, under the metadata key
    /// `<relative_dir>/<index>`, the call reads it from the metadata.
    /// Otherwise it reads the file `dir/<index>`. The call needs no
    /// transaction, no staging directory, and no temp file, so it can report a
    /// delta in a read-only repository.
    ///
    /// # Passes
    ///
    /// The framing offsets of the payload are at its end, so the call reads
    /// the part in up to three passes:
    ///
    /// 1. The first pass verifies the part against the size and the checksum
    ///    of its meta-entry. It decompresses no byte.
    /// 2. The second pass finds the framing and keeps the last 1 MiB of the
    ///    payload. For an uncompressed part, the first pass keeps this tail,
    ///    and the second pass does not occur.
    /// 3. If the tail does not hold the operation stream and the xattr
    ///    framing, the third pass reads them.
    ///
    /// # Memory
    ///
    /// Each pass holds one fixed-size read buffer and the 1 MiB tail, whatever
    /// the payload size. A pass over a compressed part also holds the state of
    /// the xz decoder, with a limit of 128 MiB.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if the superblock has no part `index`.
    /// - [`Error::InvalidFormat`] if the part breaks the format:
    ///   - an inline part that is not a `(yay)` variant
    ///   - a part that passes its declared size or fails its checksum
    ///   - an unknown compression byte or opcode
    ///   - invalid framing
    ///   - an `S` payload range or an `r` checksum range outside the
    ///     data-source blob
    ///   - more objects than the object list holds
    ///   - a stream that ends inside an operation
    /// - [`Error::InvalidFormat`] if the xz stream states a dictionary that
    ///   needs more than 128 MiB of decoder memory.
    /// - [`Error::Core`] if an operand does not decode.
    /// - [`Error::Io`] if the part file cannot be opened or read, or if the xz
    ///   stream does not decode.
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

/// Finds, in one pass over a superblock metadata dict, the entry that carries
/// each of `parts` parts inline.
///
/// For part `index`, the result holds the position of the first entry with
/// the key `<dir>/<index>`, or `None` if the dict holds no such key. `dir` is
/// the directory of the delta, relative to the repository. A later entry
/// under the same key is not read, which is the rule of a lookup by key.
///
/// A key whose last component is not a part number in plain decimal, or is a
/// number that no meta-entry has, names no part. This function checks no
/// type: [`inline_part_at`] checks each value when its part is read.
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

/// Returns part `part` as a superblock metadata dict carries it inline, at
/// the position that [`index_inline_parts`] found for it.
///
/// The result is the compression byte and the body, borrowed from the dict,
/// or `None` if the dict does not carry the part. A value of a type other
/// than `(yay)` is refused, and the caller does not read the part file in its
/// place. `dir` gives the directory of the delta, relative to the repository,
/// for the refusal text alone.
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

/// Verifies an inline part against its meta-entry by the rules of a part file.
///
/// The compression byte and the body together must fit in the size that the
/// entry declares. Their SHA-256 must be the checksum that the entry names.
/// The compression byte must be one that the reader decodes. Nothing is
/// decompressed.
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

/// The payload of an inline part: the body itself if it is uncompressed, and
/// the decompressed [`Blob`] if it is xz.
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

/// Decodes the body of an inline part that [`verify_inline_part`] accepted.
///
/// An uncompressed body is used where it lies, with no copy. An xz body
/// decompresses through [`spill_to_blob`]: on the heap up to
/// [`MMAP_THRESHOLD`], and into a mapped temp file in `staging` if larger.
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

/// Parses the meta-entry array `a(uayttay)`.
///
/// The `size` field is the limit that a part is read under. The `usize` field
/// states the sum of the sizes of the part objects. Both are host order.
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

/// Returns `true` if the metadata dict of a superblock states big-endian host
/// order. A superblock with no `ostree.endianness` byte reads as
/// little-endian, which is what each producer of these deltas writes.
fn declares_big_endian(metadata: &Value) -> bool {
    metadata
        .dict_get(ENDIANNESS_KEY)
        .and_then(Value::as_variant)
        .and_then(|(_, value)| value.as_byte())
        == Some(ENDIANNESS_BIG)
}

/// Reads one host-order `t` field. GVariant decodes it little-endian, which is
/// the order of a little-endian producer. So the field of a big-endian
/// producer is swapped back.
fn size_field(value: &Value, what: &str, big_endian: bool) -> Result<u64> {
    let raw = value
        .as_u64()
        .ok_or_else(|| Error::InvalidFormat(format!("expected {what} to be a u64")))?;
    Ok(if big_endian { raw.swap_bytes() } else { raw })
}

/// Parses the stride-33 `objtype + 32-byte checksum` object array, which gives
/// the object order and types of a part.
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

/// Parses the fallback array `a(yaytt)`. The two sizes are host order.
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

/// Decodes a part file into a random-access [`Blob`]. It verifies the part
/// checksum over the whole on-disk file before it expands the payload.
async fn decode_part(part_path: PathBuf, entry: &DeltaPart, staging: &OwnedFd) -> Result<Blob> {
    let std_file = ostrya_rt::unblock(move || std::fs::File::open(&part_path))
        .await
        .map_err(Error::Io)?;
    decode_part_stream(
        FileReader::with_len_hint(std_file, entry.size),
        entry,
        staging,
    )
    .await
}

/// Decodes a part stream into a random-access [`Blob`]. It verifies the part
/// checksum over the whole stream before it decompresses a byte.
///
/// The `(yay)` part frame is a compression byte, then the body to EOF. It is
/// a tuple whose fixed `y` is at offset 0 and whose trailing `ay` runs to the
/// end. The stream is a part file for an offline application and a fetched
/// response body for a pull.
///
/// The body is taken in under the size that `entry` declares for the part
/// file, and hashed as it arrives. The part checksum is verified before the
/// decoder runs. So the payload comes from a stream that hashes to the
/// checksum that the superblock names. A body that grew, shrank, or was
/// swapped is refused after at most the declared size is written. A payload
/// that expands without a limit is one that the publisher of the delta wrote.
///
/// Both blobs go through [`spill_to_blob`], so the heap holds at most
/// [`MMAP_THRESHOLD`] of the body and of the payload.
pub(crate) async fn decode_part_stream<R: AsyncRead + Unpin>(
    mut stream: R,
    entry: &DeltaPart,
    staging: &OwnedFd,
) -> Result<Blob> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await.map_err(Error::Io)?;
    // The checksum covers the whole part file, so the framing byte goes into
    // the digest first, and the body streams into it after.
    let mut hasher = Sha256::new();
    hasher.update(first);
    let mut reader = HashingReader::new(hasher, stream);

    // The declared size, less the framing byte, is the limit of the body.
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

/// The type of a part that the superblock carries inline in its metadata dict:
/// the compression byte and the body, as in a part file on disk.
const INLINE_PART_SIG: &str = "(yay)";

/// The number of trailing payload bytes that [`part_stats_from`] keeps as it
/// reads a payload to its end. A payload whose operation stream and xattr
/// framing are in this tail is read once.
const PAYLOAD_TAIL: usize = 1024 * 1024;

/// The memory limit of the xz decoder that reads the statistics of a part.
///
/// The dictionary size that an xz stream states sets what the decoder
/// allocates, so a small part can state a dictionary of gigabytes. A part that
/// the generator of the `ostree` command or of ostrya writes states a 32 MiB
/// dictionary in its xz block header.
pub(crate) const STATS_XZ_MEM_LIMIT: u64 = 128 * 1024 * 1024;

/// How far [`part_stats_from`] read a payload after the pass that found its
/// framing. The tests check which reads a payload took.
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

/// Reads what one part source holds and does not apply it.
///
/// The framing offsets of the payload `(a(uuu)aa(ayay)ayay)` are at its end,
/// so one forward pass cannot find the operation stream. A payload has no
/// size limit, so it is never held whole. The source is read in up to three
/// passes:
///
/// 1. Verify: the body is hashed under the size that `entry` declares, and
///    the part checksum is verified. No byte is decompressed. These are the
///    rules of [`decode_part_stream`].
/// 2. Frame: the payload streams to its end. The pass keeps its length and
///    its last [`PAYLOAD_TAIL`] bytes, which end with the three framing
///    offsets of the tuple. An uncompressed body is the payload itself, so
///    pass 1 keeps the tail and this pass does not occur.
/// 3. Walk: the tail can lack the operation stream or the last framing
///    offset of the xattr table. If so, the payload is read again up to the
///    last of the two. An uncompressed body is read at those offsets through
///    a seek. A compressed body streams from its start.
///
/// Each pass holds one [`IO_CHUNK`] buffer and the tail. A compressed pass
/// also holds the state of the xz decoder. The dictionary that the stream
/// states sets its size, and [`STATS_XZ_MEM_LIMIT`] is its limit.
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
    // framing of the table starts. An empty table has none.
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

/// Streams `reader`, which is at payload offset `from`, up to payload offset
/// `upto`. It gives each chunk to `sink` with the payload offset of its start.
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

/// Runs pass 1 of [`part_stats_from`]: hashes the part source under the size
/// that `entry` declares, verifies the part checksum, and returns the
/// compression byte. No byte is decompressed. For an uncompressed part, whose
/// body is the payload, the result also holds the payload length and its last
/// [`PAYLOAD_TAIL`] bytes.
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

/// Returns the payload of an xz part source that is at the byte after its
/// compression byte. The read is under the body size that `entry` declares and
/// under [`STATS_XZ_MEM_LIMIT`] of decoder memory.
fn xz_payload<'a, R>(source: &'a mut R, entry: &DeltaPart) -> impl AsyncRead + Send + Unpin + 'a
where
    R: AsyncRead + Unpin + Send,
{
    let body = source.take(entry.size.saturating_sub(1));
    XzDecoder::with_mem_limit(BufReader::with_capacity(IO_CHUNK, body), STATS_XZ_MEM_LIMIT)
}

/// Maps a payload read error. The result names a stream that needs more
/// decoder memory than [`STATS_XZ_MEM_LIMIT`].
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
    /// Reads the framing of a payload of `len` bytes whose last 24 bytes are
    /// `tail`. The last offset ends the mode table, the offset before it ends
    /// the xattr table, and the offset before that ends the blob.
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

/// Returns the framing-offset width of a GVariant container of `len` bytes.
fn offset_size(len: u64) -> Result<usize> {
    let len = usize::try_from(len).map_err(|_| bad_frame())?;
    Ok(offset_size_for(len))
}

fn bad_frame() -> Error {
    Error::InvalidFormat("static delta part payload framing is invalid".to_owned())
}

/// Returns the operand count of `opcode`, by the rules that [`apply_part`]
/// decodes with. `meta` is `true` if the object at the current index is a
/// metadata object. `None` for a byte that is not an opcode.
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

/// The counter of the operations of a part stream, fed in chunks of any size.
///
/// The operands are decoded by the rules of [`apply_part`]. Two ranges into
/// the data-source blob are checked against the blob length. These are the two
/// that `ostree static-delta show` also refuses: the payload range of an `S`
/// and the checksum range of an `r`.
///
/// The ranges of `w` and `B` are counted with no check, as the `ostree`
/// command counts them. The mode and xattr indexes of an `o` are counted with
/// no check too. The `ostree` command aborts on them if they are outside the
/// tables. The rules that need the objects themselves -- an open object at
/// `c`, each object produced by the end -- belong to the application.
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
    /// The bytes of the operand in progress. Eleven bytes always hold a value
    /// that [`varint::decode`] refuses, so the buffer never needs to grow.
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

    /// Refuses a range `[off, off + len)` that goes outside the data-source blob.
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

/// Drains `reader` into a [`Blob`].
///
/// The bytes stay on the heap up to [`MMAP_THRESHOLD`]. Past it, they go to
/// an anonymous temp file that is mapped read-only. A blob larger than the heap
/// limit costs space on the staging file system and address space, and no
/// resident heap.
///
/// `limit` is the number of bytes that the stream can deliver, for a stream
/// whose length is declared before it. The body of a part file is read under
/// the size that its meta-entry states. So a body that grew is refused at
/// that limit, and it does not fill the staging file system.
///
/// A stream with no declared length takes `None`. Free disk space is its
/// limit, as for the `ostree` command: if a spill fills the file system, it
/// fails when the write returns `ENOSPC`.
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

/// Copies `slices`, in order, into one [`Blob`].
///
/// If they total [`MMAP_THRESHOLD`] or less, the blob is on the heap.
/// Otherwise it is one anonymous temp file in `staging`, mapped read-only. A
/// slice starts in the blob at the sum of the lengths before it. The heap held
/// after the call is [`MMAP_THRESHOLD`] at most, whatever the number of
/// slices.
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

/// Opens an anonymous read-write temp file on the staging file system.
///
/// The call uses `O_TMPFILE` if the file system supports it. Otherwise it
/// opens a named temp file and unlinks it at once. Both give a read-write
/// descriptor that needs no later cleanup.
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

/// Runs the operation stream of a part and writes its objects into `txn`.
///
/// The objects come in `objects` order. The object type at the current index
/// sets the operand form: file metadata (mode and xattr indexes), or a bare
/// metadata splice. Each object is written with its expected checksum, so a
/// misapply fails at the write and stores no wrong object.
///
/// The format bounds the mode and xattr tables, so they are collected first.
/// The data source and the operation stream borrow the part blob. Object
/// payloads stream to disk, and no whole object is buffered.
///
/// `checks` holds the mode checks for each content object of this part: what
/// the flags of the caller require and what the destination mode requires.
/// They run on the mode and xattr tables of the part, before the bytes of the
/// object are written. So a delta delivers no object that a loose fetch of
/// the same object refuses.
pub(crate) async fn apply_part(
    txn: &Transaction,
    payload: &[u8],
    objects: &[(ObjectType, Checksum)],
    staging: &OwnedFd,
    checks: ModeChecks,
) -> Result<()> {
    let view: PartView<'_> = GvDecode::decode(payload).map_err(ostrya_core::Error::from)?;
    let (mode_it, xattr_it, data_source, ops) = view;

    // The (uuu) mode triples are big-endian on the wire, whatever the
    // endianness byte of the superblock states, so they are swapped here to
    // host order. The mode and xattr tables are bounded metadata (a few
    // distinct triples and xattr sets), so they go onto the heap. Their
    // combined size has the metadata limit, so a hostile part cannot force an
    // unbounded table copy.
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
                    // A spliced metadata object is buffered whole (it hashes
                    // again to its checksum), so the metadata limit applies.
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
                // A metadata object or a symlink target is buffered whole on
                // the heap ([`Sink::Buffer`]), so the metadata limit applies to
                // its declared size. A regular file streams to the content
                // writer, so the staging file system is the limit of its size.
                // `close_object` checks that the produced size is `out_size`,
                // and the content writer verifies the checksum.
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
                // object, read at `offset` in the current source. The current
                // source is the read-source object if one is set, and the data
                // source of the part otherwise. The `ostree` command emits it
                // for from->to deltas of larger objects. It copies the unchanged
                // runs from the source object, and the payload carries only the
                // changed runs.
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

/// The state of an object that `open` opened and `close` finishes.
struct OpenState<'t> {
    objtype: ObjectType,
    csum: Checksum,
    out_size: usize,
    /// The file metadata of a content object, or `None` for a metadata object.
    meta: Option<FileMeta>,
    sink: Sink<'t>,
}

/// The output sink of an open object: a bounded memory buffer for a metadata
/// object or a symlink target, or the streaming content writer for a regular
/// file.
enum Sink<'t> {
    Buffer(Vec<u8>),
    Content {
        // Boxed, because a `ContentWriter` is much larger than the buffer
        // variant.
        writer: Box<ContentWriter<'t>>,
        written: usize,
    },
}

impl Sink<'_> {
    /// Returns the number of object bytes produced so far.
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

/// Opens the sink of the object at the current index.
///
/// The sink is a content writer for a regular file. It is a buffer for a
/// metadata object (`meta` is `None`) or a symlink.
async fn open_object<'t>(
    txn: &'t Transaction,
    objtype: ObjectType,
    csum: Checksum,
    out_size: usize,
    meta: Option<FileMeta>,
) -> Result<OpenState<'t>> {
    let sink = match &meta {
        Some(m) if m.mode & S_IFMT != S_IFLNK => Sink::Content {
            writer: Box::new(txn.content_writer(Some(&csum), m).await?.uncounted()),
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

/// Finishes an open object: checks its produced size and writes it out. The
/// `finish` of the content writer, or the metadata or symlink write, verifies
/// the checksum.
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

/// Writes a content object (a regular file or a symlink) spliced from
/// `content`, with the mode and xattrs from the tables of the part. A regular
/// file streams to disk in bounded chunks. A symlink takes the bytes as its
/// target.
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
        let mut writer = txn.content_writer(Some(expected), &meta).await?.uncounted();
        for chunk in content.chunks(IO_CHUNK) {
            writer.write_all(chunk).await.map_err(Error::Io)?;
        }
        writer.finish().await?;
    }
    Ok(())
}

/// Returns the file metadata of the object at `mode_idx` and `xattr_idx`.
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

/// The read source that the `r` and `R` ops select. It holds the loaded object
/// across the pairs that name it.
///
/// A part sets and unsets the read source once for each contiguous run that
/// it copies from the source object. So an object with many changes names the
/// same source many times: the 4 MiB object of a delta with forty scattered
/// edits carries forty-one `r` ops. A reload at each `r` reads and spills the
/// whole object again each time. So the loaded blob outlives the `R` that ends
/// a run, and a later `r` that names the same checksum uses it again.
///
/// Objects are content-addressed, so equal checksums mean identical bytes,
/// and the reuse needs no second check. At most one source object is held. A
/// different checksum drops the previous blob, with its temp file and mapping,
/// before the next one loads.
#[derive(Default)]
struct SourceCache {
    loaded: Option<(Checksum, Blob)>,
    /// `true` while an `r` op selects the loaded source. `R` clears it and
    /// keeps the blob, so a `write` op with no read source reads the data
    /// source of the part, as the format requires.
    active: bool,
}

impl SourceCache {
    /// Selects `checksum` as the read source, and loads it if it is not
    /// already held.
    async fn set(
        &mut self,
        txn: &Transaction,
        checksum: &Checksum,
        staging: &OwnedFd,
    ) -> Result<()> {
        if !matches!(&self.loaded, Some((held, _)) if held == checksum) {
            // Drop the source that is held first, so the peak cost is the temp
            // file and mapping of one source object.
            self.loaded = None;
            self.loaded = Some((*checksum, load_source_blob(txn, checksum, staging).await?));
        }
        self.active = true;
        Ok(())
    }

    /// Clears the read source selection, and keeps the object loaded for a
    /// later `r`.
    fn unset(&mut self) {
        self.active = false;
    }

    /// Returns the bytes of the selected read source, or `None` if no `r` op is
    /// in effect.
    fn active(&self) -> Option<&[u8]> {
        self.active
            .then_some(self.loaded.as_ref())
            .flatten()
            .map(|(_, blob)| blob.as_slice())
    }
}

/// Loads a content object as a random-access [`Blob`], the source of a
/// bspatch or rollsum op.
///
/// The call looks in the staged objects of the current transaction before the
/// repository. The object streams through its reader into the spill path of a
/// part payload. So a large source object is a memory map, and it is not held
/// on the heap.
async fn load_source_blob(
    txn: &Transaction,
    checksum: &Checksum,
    staging: &OwnedFd,
) -> Result<Blob> {
    let file = txn.load_file_staged_first(checksum).await?;
    let reader = file.reader().await?;
    spill_to_blob(reader, staging, None).await
}

/// Reads a whole file into a size-bounded buffer, off the async thread. The
/// superblock read uses it, because the superblock is bounded metadata.
///
/// The read stops one byte past the limit, whatever the file is. A device or
/// a FIFO states no length, so the limit applies to the bytes read. For a
/// regular file, the length of the open file sets the buffer size, up to the
/// limit. So the buffer does not grow during the read.
pub(crate) async fn read_capped(path: PathBuf) -> Result<Vec<u8>> {
    read_under(path, MAX_SUPERBLOCK).await
}

/// Runs [`read_capped`] under a limit of `cap` bytes.
async fn read_under(path: PathBuf, cap: u64) -> Result<Vec<u8>> {
    ostrya_rt::unblock(move || {
        use std::io::Read;
        let file = std::fs::File::open(&path)?;
        let meta = file.metadata()?;
        let hint = if meta.is_file() {
            meta.len().min(cap) + 1
        } else {
            0
        };
        let mut bytes = Vec::with_capacity(usize::try_from(hint).unwrap_or(0));
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

/// Decodes one LEB128 operand from `ops` at `*cur` and moves the cursor past it.
fn take_leb(ops: &[u8], cur: &mut usize) -> Result<u64> {
    let (value, consumed) = varint::decode(&ops[*cur..])?;
    *cur += consumed;
    Ok(value)
}

/// Borrows `data[off..off + len]`. It fails if the range is out of bounds.
fn slice(data: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    let end = off
        .checked_add(len)
        .ok_or_else(|| op_error("data-source range overflow"))?;
    data.get(off..end)
        .ok_or_else(|| op_error("data-source range out of bounds"))
}

/// Returns the object at `index`. It fails if the stream runs past the list.
fn object_at(objects: &[(ObjectType, Checksum)], index: usize) -> Result<(ObjectType, Checksum)> {
    objects
        .get(index)
        .copied()
        .ok_or_else(|| op_error("operation stream produced more objects than declared"))
}

fn op_error(msg: &str) -> Error {
    Error::InvalidFormat(format!("static delta: {msg}"))
}

/// Adds `n` bytes to the running size of the mode and xattr tables. It fails
/// if the combined tables become larger than [`MAX_TABLE_BYTES`].
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

    /// A directory descriptor for the spill path. Every part here is much
    /// smaller than [`MMAP_THRESHOLD`], so no temp file is opened through it.
    fn staging_fd() -> OwnedFd {
        use rustix::fs::{Mode, OFlags, open};
        open(
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    /// A meta-entry that names a part file of `file` bytes and declares `size`
    /// for it.
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

    /// An uncompressed part reads back as its payload. A body longer than the
    /// meta-entry declares is refused at that limit. Here the checksum covers
    /// the longer body, so the size is what stops it.
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

    /// The part checksum is verified before the decoder runs. A part that
    /// declares xz and whose body is not an xz stream fails the checksum, and
    /// the decoder never sees the body.
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

    /// One of every opcode against a 64-byte blob. The stream holds a metadata
    /// splice and a content splice. Then it builds an object from a payload
    /// write, a read source, a write against it, and a bspatch.
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

    /// Operands split across feeds decode the same as a stream fed whole. A
    /// multi-byte operand can start in one chunk and end in the next.
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
        // `(1, 2)` then `(3, 4)`: two metadata splices. The second `S` byte is
        // the opcode read from the third byte of the stream.
        let mut two = OpCounter::new(&meta, 64);
        two.feed(&[OP_OPEN_SPLICE_CLOSE, 1, 2, OP_OPEN_SPLICE_CLOSE, 3, 4])
            .unwrap();
        assert_eq!(two.finish().unwrap().open_splice_close, 2);

        let file = [(ObjectType::File, Checksum::from_bytes([0x03; 32]))];
        let mut one = OpCounter::new(&file, 64);
        one.feed(&stream).unwrap();
        assert_eq!(one.finish().unwrap().open_splice_close, 1);
    }

    /// The counter refuses the streams that `ostree static-delta show` refuses
    /// on their bytes alone. It counts the `w`, `B`, and `o` operands that the
    /// `ostree` command counts with no check.
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
        // A close with no open object is a refusal of the application. The
        // counter accepts it.
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

    /// An inline part is borrowed from the dict under its own key. An absent
    /// key reads as no inline part. A value of another type is refused.
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

    /// The one-pass index reads the keys that a lookup by key reads. The first
    /// entry under a key wins. A part number written with a sign, a leading
    /// zero, or a trailing character is another key.
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

    /// An inline part is held to the rules that a part file is read under. The
    /// checks of the declared size, the checksum, and the compression byte
    /// each run before any decoder runs.
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

        // A swapped body that declares xz fails at the checksum, before the
        // decoder.
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

    /// A superblock file past the limit is refused on the bytes read. A file
    /// at the limit is read whole. A device that states no length is read only
    /// up to one byte past the limit.
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
    /// swapped. Under `l` none is.
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
