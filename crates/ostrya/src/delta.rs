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
//! Phase 13 signing engines over the raw superblock bytes.
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
const ENDIANNESS_BIG: u8 = b'B';

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
    /// The raw superblock bytes: the payload signatures cover.
    pub(crate) superblock_bytes: Vec<u8>,
    /// The leading `a{sv}`: `ostree.endianness`, a copy of the target commit's
    /// detached metadata, and any part carried inline.
    pub(crate) metadata: Value,
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
/// fields of a superblock. A superblock carrying no such byte, or any byte
/// other than `B`, reads as little-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaEndianness {
    /// The byte is `l`, absent, or another value.
    Little,
    /// The byte is `B`.
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
    /// The delta's source objects (for parts that patch against a source commit)
    /// must already be present in the repository. Every produced object's
    /// checksum is asserted as it is written. Fallback objects the delta
    /// references must already be present; offline application does not fetch
    /// them. The target commit's ref is not set: the caller decides that.
    pub async fn apply_static_delta_offline(&self, dir: &Path) -> Result<Checksum> {
        let sb_bytes = read_capped(dir.join("superblock")).await?;
        let sb = DeltaSuperblock::parse(sb_bytes)?;

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
            let blob = decode_part(dir.join(i.to_string()), entry, &staging).await?;
            apply_part(&txn, &blob, &entry.objects, &staging, checks).await?;
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
        let sb_bytes = read_capped(dir.join("superblock")).await?;
        let sb = DeltaSuperblock::parse(sb_bytes)?;
        let signatures = sb
            .signatures
            .ok_or_else(|| Error::Signature("static delta carries no signatures".to_owned()))?;
        let mut outcome = VerifyOutcome::default();
        for verifier in verifiers {
            let blobs = signatures_for(&signatures, verifier.metadata_key());
            let result = verifier.verify(&sb.superblock_bytes, &blobs).await?;
            outcome.valid |= result.valid;
            outcome.signatures.extend(result.signatures);
        }
        Ok(outcome)
    }

    /// List the static deltas stored in the repository under `deltas/`.
    ///
    /// Each is named as the tool names it: the target commit hex for a
    /// from-scratch delta, or `<from-hex>-<to-hex>` for a delta against a source
    /// commit. The `delta-indexes/` cache that advertises these deltas to a
    /// fetcher is written by
    /// [`reindex_static_deltas`](Repo::reindex_static_deltas) and read by a pull.
    pub async fn list_static_deltas(&self) -> Result<Vec<String>> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || list_static_deltas_blocking(repo_fd.as_fd())).await
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
/// alongside the commit it produces.
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

/// Remove one `deltas/<fanout>/<leaf>` directory and every file in it.
///
/// A delta directory holds a `superblock` and its numbered part files and no
/// subdirectory. The fanout directory above it is left in place, empty where
/// this was its last entry, which is what a prune by the `ostree` tool leaves.
/// A directory that is already gone is success.
pub(crate) fn remove_delta_dir(repo_fd: BorrowedFd<'_>, dir: &DeltaDir) -> Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags, openat, unlinkat};

    let path = format!("deltas/{}/{}", dir.fanout, dir.leaf);
    let fd = match openat(
        repo_fd,
        path.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(e) => return Err(Error::Io(e.into())),
    };
    for name in dir_child_names(&fd)? {
        match unlinkat(&fd, name.as_str(), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(Error::Io(e.into())),
        }
    }
    drop(fd);
    match unlinkat(repo_fd, path.as_str(), AtFlags::REMOVEDIR) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Walk the two-level `deltas/` tree, applying `parse` to each delta's fanout
/// and leaf directory names. A repository with no `deltas/` yields nothing.
fn scan_deltas<T>(
    repo_fd: BorrowedFd<'_>,
    parse: impl Fn(&str, &str) -> Result<T>,
) -> Result<Vec<T>> {
    use rustix::fs::{Mode, OFlags, openat};

    let deltas = match openat(
        repo_fd,
        "deltas",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e.into())),
    };

    let mut out = Vec::new();
    for fanout in dir_child_names(&deltas)? {
        let fan_fd = openat(
            &deltas,
            fanout.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| Error::Io(e.into()))?;
        for leaf in dir_child_names(&fan_fd)? {
            out.push(parse(&fanout, &leaf)?);
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
    match parse_delta_dir(fanout, leaf)? {
        (Some(from), to) => Ok(format!("{}-{}", from.to_hex(), to.to_hex())),
        (None, to) => Ok(to.to_hex()),
    }
}

impl DeltaSuperblock {
    /// Parse a superblock file's bytes, detecting and unwrapping the signed
    /// envelope.
    pub fn parse(bytes: Vec<u8>) -> Result<DeltaSuperblock> {
        let (superblock_bytes, signatures) = if bytes.starts_with(SIGNED_MAGIC) {
            let ty = Type::parse(SIGNED_SIG).map_err(ostrya_core::Error::from)?;
            let value = from_bytes(&ty, &bytes).map_err(ostrya_core::Error::from)?;
            let fields = tuple(&value)?;
            let inner = bytes_field(&fields[1], "signed superblock payload")?.to_vec();
            (inner, Some(fields[2].clone()))
        } else {
            (bytes, None)
        };

        let ty = Type::parse(SUPERBLOCK_SIG).map_err(ostrya_core::Error::from)?;
        let value = from_bytes(&ty, &superblock_bytes).map_err(ostrya_core::Error::from)?;
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

        Ok(DeltaSuperblock {
            from,
            to,
            commit_bytes,
            meta_entries,
            fallbacks,
            signatures,
            superblock_bytes,
            metadata,
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
        let key = format!("{}/{index}", self.relative_dir());
        match self.metadata.dict_get(&key) {
            Some(inline) => {
                let (ty, value) = inline
                    .as_variant()
                    .filter(|(ty, _)| ty.signature() == INLINE_PART_SIG)
                    .ok_or_else(|| {
                        Error::InvalidFormat(format!(
                            "static delta inline part {key} is not a {INLINE_PART_SIG} variant"
                        ))
                    })?;
                let bytes = to_bytes(ty, value).map_err(ostrya_core::Error::from)?;
                part_stats_from(Cursor::new(bytes), entry).await
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
    blob: &Blob,
    objects: &[(ObjectType, Checksum)],
    staging: &OwnedFd,
    checks: ModeChecks,
) -> Result<()> {
    let view: PartView<'_> = GvDecode::decode(blob.as_slice()).map_err(ostrya_core::Error::from)?;
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
