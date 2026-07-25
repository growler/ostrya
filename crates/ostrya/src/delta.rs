//! Static-delta reading and offline application (Phase 15a).
//!
//! A static delta is a compact description of the objects that make up a target
//! commit, optionally expressed as a patch against a source commit. The format
//! this module reads was recovered by observing the `ostree` tool as a black box
//! (see `format-reference.md`, "Static delta wire format"). This module reads a
//! delta the tool wrote and applies it offline, producing the target commit's
//! objects into the repository; generating deltas is a later phase.
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
//! Application is memory-bounded. A part decompresses through
//! `async-compression`'s xz codec straight into an anonymous temp file in the
//! repository; the decompressed payload stays on the heap when it is at or below
//! [`MMAP_THRESHOLD`] and is read-only mmapped otherwise, so a large part costs
//! address space rather than resident heap. Splice and bspatch output streams
//! through the transaction's content writer, and a bspatch source object is
//! spilled to a temp file the same way, so no whole object is materialized.
//!
//! Signed deltas wrap the superblock in a magic-prefixed envelope carrying the
//! detached signatures; [`Repo::verify_static_delta`] checks them with the
//! Phase 13 signing engines over the raw superblock bytes.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use async_compression::futures::bufread::XzDecoder;
use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::BufReader;
use futures_lite::{AsyncReadExt, AsyncWriteExt};
use ostrya_core::{
    ArrayIter, Checksum, GvDecode, ObjectType, Type, Value, Xattrs, from_bytes, to_bytes, varint,
};
use ostrya_rt::File as RtFile;
use sha2::{Digest, Sha256};

use crate::bspatch::bspatch;
use crate::error::{Error, Result};
use crate::hashing::HashingReader;
use crate::repo::Repo;
use crate::sign::{Verifier, VerifyOutcome, signatures_for};
use crate::transaction::Transaction;
use crate::write::{ContentWriter, FileMeta};

/// The superblock GVariant type: metadata, timestamp, from/to checksums, the
/// embedded target commit, an (always empty) recursion array, the per-part
/// meta-entry array, and the fallback array.
const SUPERBLOCK_SIG: &str = "(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))";
/// The signed-delta envelope type: magic, raw superblock bytes, signatures.
const SIGNED_SIG: &str = "(taya{sv})";
/// The commit object type, used to re-serialize the embedded target commit.
const COMMIT_SIG: &str = "(a{sv}aya(say)sstayay)";
/// The signed-delta magic. Stored as the eight ASCII bytes "OSTSGNDT".
const SIGNED_MAGIC: &[u8; 8] = b"OSTSGNDT";

/// No compression: the part body is the payload verbatim.
const COMPRESSION_NONE: u8 = 0;
/// xz compression: the part body is a standard `.xz` stream.
const COMPRESSION_XZ: u8 = b'x';

const OP_OPEN_SPLICE_CLOSE: u8 = b'S';
const OP_OPEN: u8 = b'o';
const OP_WRITE: u8 = b'w';
const OP_SET_READ_SOURCE: u8 = b'r';
const OP_UNSET_READ_SOURCE: u8 = b'R';
const OP_CLOSE: u8 = b'c';
const OP_BSPATCH: u8 = b'B';

/// The file-type mask of an `st_mode`.
const S_IFMT: u32 = 0o170000;
/// The symlink file-type bits.
const S_IFLNK: u32 = 0o120000;

/// The largest superblock accepted. The superblock is read whole onto the heap,
/// since it is parsed as one GVariant tree, so it is capped at the metadata
/// ceiling: it holds the embedded target commit (a metadata object) plus the
/// per-part and fallback tables, all bounded metadata.
const MAX_SUPERBLOCK: u64 = crate::object::MAX_METADATA_SIZE;

/// A decompressed part payload or source object at or below this size is kept on
/// the heap; a larger one is spilled to a temp file and read-only mmapped, so it
/// costs address space and demand-paged file cache rather than resident heap.
const MMAP_THRESHOLD: usize = 128 * 1024;

/// The chunk size for streaming object payloads to and from disk.
const IO_CHUNK: usize = 128 * 1024;

/// The largest combined heap footprint accepted for a part's mode and xattr
/// tables. They are bounded metadata, so they are collected onto the heap and
/// capped at the metadata ceiling, turning a hostile table size into a
/// bounded-size failure rather than an unbounded copy.
const MAX_TABLE_BYTES: usize = crate::object::MAX_METADATA_SIZE as usize;

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
struct Superblock {
    /// The target commit checksum.
    to: Checksum,
    /// The normal-form bytes of the embedded target commit object.
    commit_bytes: Vec<u8>,
    /// The per-part meta-entries, in part order.
    meta_entries: Vec<MetaEntry>,
    /// The fallback objects the delta references but does not carry.
    fallbacks: Vec<Fallback>,
    /// The detached signatures when the delta is signed.
    signatures: Option<Value>,
    /// The raw superblock bytes: the payload signatures cover.
    superblock_bytes: Vec<u8>,
}

/// One part's meta-entry: its part-file checksum and the ordered list of objects
/// the part produces.
struct MetaEntry {
    part_csum: Checksum,
    objects: Vec<(ObjectType, Checksum)>,
}

/// A fallback object: one delivered outside the parts (as a plain loose object).
struct Fallback {
    objtype: ObjectType,
    checksum: Checksum,
}

/// Random-access backing for a decompressed part payload or a source object: on
/// the heap when small, a read-only memory map of a temp file when large.
enum Blob {
    Ram(Vec<u8>),
    Mapped(ostrya_sys::Mmap),
}

impl Blob {
    fn as_slice(&self) -> &[u8] {
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

        for (i, entry) in sb.meta_entries.iter().enumerate() {
            let blob = decode_part(dir.join(i.to_string()), &entry.part_csum, &staging).await?;
            apply_part(&txn, &blob, &entry.objects, &staging).await?;
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
    /// commit. Reading the `delta-indexes/` cache used for remote discovery
    /// lands with pull.
    pub async fn list_static_deltas(&self) -> Result<Vec<String>> {
        let repo_fd = self.repo_fd().try_clone_to_owned()?;
        ostrya_rt::unblock(move || list_static_deltas_blocking(repo_fd.as_fd())).await
    }
}

/// Scan `deltas/<fanout>/<leaf>` and reconstruct each delta's tool name.
fn list_static_deltas_blocking(repo_fd: BorrowedFd<'_>) -> Result<Vec<String>> {
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

    let mut names = Vec::new();
    for fanout in dir_child_names(&deltas)? {
        let fan_fd = openat(
            &deltas,
            fanout.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| Error::Io(e.into()))?;
        for leaf in dir_child_names(&fan_fd)? {
            names.push(delta_name(&fanout, &leaf)?);
        }
    }
    names.sort();
    Ok(names)
}

/// Collect the child names of an open directory, dropping `.` and `..` and any
/// non-UTF-8 name (delta directory names are base64, so always UTF-8).
fn dir_child_names(dir: &OwnedFd) -> Result<Vec<String>> {
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

/// Reconstruct a delta's hex name from its `deltas/<fanout>/<leaf>` directory.
/// The leaf carries a `-` (which never occurs in base64) exactly when the delta
/// is from a source commit.
fn delta_name(fanout: &str, leaf: &str) -> Result<String> {
    match leaf.split_once('-') {
        Some((from_rest, to_b64)) => {
            let from = Checksum::from_base64_modified(&format!("{fanout}{from_rest}"))?;
            let to = Checksum::from_base64_modified(to_b64)?;
            Ok(format!("{}-{}", from.to_hex(), to.to_hex()))
        }
        None => {
            let to = Checksum::from_base64_modified(&format!("{fanout}{leaf}"))?;
            Ok(to.to_hex())
        }
    }
}

impl Superblock {
    /// Parse a superblock file's bytes, detecting and unwrapping the signed
    /// envelope.
    fn parse(bytes: Vec<u8>) -> Result<Superblock> {
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

        // The `ostree.endianness` metadata byte gates only the superblock
        // timestamp and the meta-entry/fallback size fields, none of which
        // application reads: parts are read by name and checked by checksum, the
        // `(uuu)` modes are always big-endian, and the embedded commit is
        // normal-form little-endian. A big-endian delta therefore applies
        // through the same path with no byte-order handling here.
        let to = Checksum::from_ay(bytes_field(&fields[3], "superblock to")?)?;

        // Re-serialize the embedded commit to its normal-form bytes and assert
        // the target checksum, closing the loop on the commit the delta carries.
        let commit_ty = Type::parse(COMMIT_SIG).map_err(ostrya_core::Error::from)?;
        let commit_bytes = to_bytes(&commit_ty, &fields[4]).map_err(ostrya_core::Error::from)?;
        if Checksum::sha256(&commit_bytes) != to {
            return Err(Error::InvalidFormat(
                "static delta embedded commit does not match the target checksum".to_owned(),
            ));
        }

        let meta_entries = parse_meta_entries(array(&fields[6])?)?;
        let fallbacks = parse_fallbacks(array(&fields[7])?)?;

        Ok(Superblock {
            to,
            commit_bytes,
            meta_entries,
            fallbacks,
            signatures,
            superblock_bytes,
        })
    }
}

/// Parse the meta-entry array `a(uayttay)`. The `size`/`usize` fields are not
/// needed to apply a delta (each part is read by name and checked by its
/// checksum), so the host-order size fields are skipped and the endianness byte
/// does not affect application.
fn parse_meta_entries(entries: &[Value]) -> Result<Vec<MetaEntry>> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = tuple(entry)?;
        let part_csum = Checksum::from_ay(bytes_field(&fields[1], "part checksum")?)?;
        let objects = parse_object_array(bytes_field(&fields[4], "object array")?)?;
        out.push(MetaEntry { part_csum, objects });
    }
    Ok(out)
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
/// checksum over the whole on-disk file as it streams.
///
/// The `(yay)` part frame is a compression byte followed by the body to EOF (a
/// tuple whose fixed `y` sits at offset 0 and whose trailing `ay` runs to the
/// end). The whole file feeds a SHA-256 as it is read, and the decompressed
/// payload spills through [`spill_to_blob`], so neither the compressed part nor
/// the payload is buffered beyond the streaming window and [`MMAP_THRESHOLD`].
async fn decode_part(part_path: PathBuf, expected: &Checksum, staging: &OwnedFd) -> Result<Blob> {
    let std_file = ostrya_rt::unblock(move || std::fs::File::open(&part_path))
        .await
        .map_err(Error::Io)?;
    let mut reader = HashingReader::new(Sha256::new(), RtFile::from(std_file));

    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await.map_err(Error::Io)?;
    let compression = first[0];

    let blob = match compression {
        COMPRESSION_NONE => spill_to_blob(&mut reader, staging).await?,
        COMPRESSION_XZ => {
            let decoder = XzDecoder::new(BufReader::new(&mut reader));
            spill_to_blob(decoder, staging).await?
        }
        other => {
            return Err(Error::InvalidFormat(format!(
                "static delta part compression byte {other:#x} is not supported"
            )));
        }
    };

    // Draw any bytes the decoder left unread so the part checksum covers the
    // whole on-disk file, then assert it.
    let mut scratch = [0u8; 4096];
    while reader.read(&mut scratch).await.map_err(Error::Io)? != 0 {}
    let (part_csum, _size) = reader.finalize();
    if part_csum != *expected {
        return Err(Error::InvalidFormat(
            "static delta part checksum mismatch".to_owned(),
        ));
    }
    Ok(blob)
}

/// Drain `reader` into a [`Blob`], keeping bytes on the heap until they exceed
/// [`MMAP_THRESHOLD`], then spilling to an anonymous temp file that is mmapped
/// read-only. A blob past the heap threshold costs staging-filesystem space and
/// address space, not resident heap, so the size it accepts is bounded by free
/// disk the way the reference tool is: a spill that would exhaust the filesystem
/// fails when the write returns `ENOSPC`, not at a fixed ceiling.
async fn spill_to_blob<R: AsyncRead + Unpin>(mut reader: R, staging: &OwnedFd) -> Result<Blob> {
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
fn open_rw_temp(staging: BorrowedFd<'_>) -> Result<OwnedFd> {
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
async fn apply_part(
    txn: &Transaction,
    blob: &Blob,
    objects: &[(ObjectType, Checksum)],
    staging: &OwnedFd,
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
                    write_content_slice(txn, &modes, &xattrs, mode_idx, xattr_idx, bytes, &csum)
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
                    Some(file_meta(&modes, &xattrs, mode_idx, xattr_idx)?)
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
async fn write_content_slice(
    txn: &Transaction,
    modes: &[(u32, u32, u32)],
    xattrs: &[Xattrs],
    mode_idx: usize,
    xattr_idx: usize,
    content: &[u8],
    expected: &Checksum,
) -> Result<()> {
    let meta = file_meta(modes, xattrs, mode_idx, xattr_idx)?;
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
    spill_to_blob(reader, staging).await
}

/// Read a whole file into a size-bounded buffer, off the async thread. Used for
/// the superblock, which is bounded metadata.
async fn read_capped(path: PathBuf) -> Result<Vec<u8>> {
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

fn tuple(value: &Value) -> Result<&[Value]> {
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

fn bytes_field<'a>(value: &'a Value, what: &str) -> Result<&'a [u8]> {
    value
        .as_bytes()
        .ok_or_else(|| Error::InvalidFormat(format!("expected {what} to be a byte array")))
}

fn byte_field(value: &Value, what: &str) -> Result<u8> {
    value
        .as_byte()
        .ok_or_else(|| Error::InvalidFormat(format!("expected {what} to be a byte")))
}
