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

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use async_compression::futures::bufread::XzDecoder;
use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::Cursor;
use futures_lite::{AsyncReadExt, AsyncWriteExt};
use ostrya_core::{
    ArrayIter, Checksum, GvDecode, ObjectType, Type, Value, Xattrs, from_bytes, to_bytes, varint,
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

/// A parsed static-delta superblock.
pub(crate) struct Superblock {
    /// The source commit checksum, `None` for a from-scratch delta.
    pub(crate) from: Option<Checksum>,
    /// The target commit checksum.
    pub(crate) to: Checksum,
    /// The normal-form bytes of the embedded target commit object.
    pub(crate) commit_bytes: Vec<u8>,
    /// The per-part meta-entries, in part order.
    pub(crate) meta_entries: Vec<MetaEntry>,
    /// The fallback objects the delta references but does not carry.
    pub(crate) fallbacks: Vec<Fallback>,
    /// The detached signatures when the delta is signed.
    pub(crate) signatures: Option<Value>,
    /// The raw superblock bytes: the payload signatures cover.
    pub(crate) superblock_bytes: Vec<u8>,
}

/// One part's meta-entry: its part-file checksum, the part file's size, and the
/// ordered list of objects the part produces.
pub(crate) struct MetaEntry {
    pub(crate) part_csum: Checksum,
    /// The part file's on-disk size, the compression byte included. It bounds
    /// what a part fetch takes off the connection and what a part read takes in
    /// before the checksum above is asserted.
    pub(crate) size: u64,
    pub(crate) objects: Vec<(ObjectType, Checksum)>,
}

/// A fallback object: one delivered outside the parts (as a plain loose object).
pub(crate) struct Fallback {
    pub(crate) objtype: ObjectType,
    pub(crate) checksum: Checksum,
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
        let sb = Superblock::parse(sb_bytes)?;

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
        let sb = Superblock::parse(sb_bytes)?;
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

impl Superblock {
    /// Parse a superblock file's bytes, detecting and unwrapping the signed
    /// envelope.
    pub(crate) fn parse(bytes: Vec<u8>) -> Result<Superblock> {
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

        // The `ostree.endianness` metadata byte gates the superblock timestamp
        // and the meta-entry/fallback size fields. Application reads one of
        // them, a part's declared size, so the byte is read here and that field
        // is swapped for a big-endian producer. The `(uuu)` modes are always
        // big-endian and the embedded commit is normal-form little-endian, so
        // nothing else here turns on it.
        let big_endian = declares_big_endian(&fields[0]);
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
        let fallbacks = parse_fallbacks(array(&fields[7])?)?;

        Ok(Superblock {
            from,
            to,
            commit_bytes,
            meta_entries,
            fallbacks,
            signatures,
            superblock_bytes,
        })
    }
}

/// Parse the meta-entry array `a(uayttay)`. The `size` field is the ceiling a
/// part is read under; the `usize` field states what the part's objects add up
/// to, which application does not need, so it is skipped.
fn parse_meta_entries(entries: &[Value], big_endian: bool) -> Result<Vec<MetaEntry>> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = tuple(entry)?;
        let part_csum = Checksum::from_ay(bytes_field(&fields[1], "part checksum")?)?;
        let size = size_field(&fields[2], "part size", big_endian)?;
        let objects = parse_object_array(bytes_field(&fields[4], "object array")?)?;
        out.push(MetaEntry {
            part_csum,
            size,
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

/// Parse the fallback array `a(yaytt)`.
fn parse_fallbacks(entries: &[Value]) -> Result<Vec<Fallback>> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = tuple(entry)?;
        let objtype = ObjectType::from_u32(u32::from(byte_field(&fields[0], "fallback objtype")?))?;
        let checksum = Checksum::from_ay(bytes_field(&fields[1], "fallback checksum")?)?;
        out.push(Fallback { objtype, checksum });
    }
    Ok(out)
}

/// Decode a part file into a random-access [`Blob`], verifying the part
/// checksum over the whole on-disk file before the payload is expanded.
async fn decode_part(part_path: PathBuf, entry: &MetaEntry, staging: &OwnedFd) -> Result<Blob> {
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
    entry: &MetaEntry,
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
pub(crate) async fn read_capped(path: PathBuf) -> Result<Vec<u8>> {
    ostrya_rt::unblock(move || {
        let meta = std::fs::metadata(&path)?;
        if meta.len() > MAX_SUPERBLOCK {
            return Err(std::io::Error::other(format!(
                "static delta file {} exceeds the size ceiling",
                path.display()
            )));
        }
        std::fs::read(&path)
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
    fn meta_entry(file: &[u8], size: u64) -> MetaEntry {
        MetaEntry {
            part_csum: Checksum::sha256(file),
            size,
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
}
