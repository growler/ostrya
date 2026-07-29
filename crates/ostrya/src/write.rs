//! The object-store write layer: streaming content ingestion and staging.
//!
//! This module holds the pieces a [`Transaction`](crate::Transaction) uses to
//! ingest objects into its staging directory: the logical metadata a writer
//! consumes ([`FileMeta`]), the push-style streaming primitive
//! ([`ContentWriter`]), and the per-mode on-disk application plus staging
//! syscalls the writers finish with.
//!
//! Ingestion goes into an unnamed temp file (`O_TMPFILE` in the staging
//! directory, materialized with `linkat`) where the filesystem allows it, and a
//! named temp file otherwise. A regular file's payload streams through an
//! `rt::File` in bounded chunks and is hashed on the way down; in archive mode
//! the same pass feeds a raw-DEFLATE encoder. The object identity is the
//! SHA-256 of the framed uncompressed header followed by the raw payload, so it
//! is complete when the stream ends regardless of how the bytes are stored.
//!
//! Per-mode inode application is always by explicit `fchmod`/`fchown`, never the
//! umask, reproducing the modes recovered from the `ostree` tool (see
//! `format-reference.md`, "Write path: loose-object inode modes and
//! durability").

use std::future::poll_fn;
use std::io::{self, SeekFrom};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use async_compression::Level;
use async_compression::futures::write::DeflateEncoder;
use futures_io::{AsyncRead, AsyncSeek, AsyncWrite};
use ostrya_core::filehdr::frame;
use ostrya_core::{Checksum, FileHeader, ObjectType, RepoMode, Xattrs, loose_path};
use ostrya_rt::File as RtFile;
use rustix::fs::{AtFlags, Gid, Mode, OFlags, Uid, XattrFlags};
use sha2::{Digest, Sha256};

use crate::config::Tristate;
use crate::error::{Error, Result};
use crate::transaction::Transaction;

/// The regular-file mode bit.
const S_IFREG: u32 = 0o100000;
/// The symlink mode bit.
const S_IFLNK: u32 = 0o120000;
/// The full symlink `st_mode` a content object records for a symlink.
const SYMLINK_MODE: u32 = S_IFLNK | 0o777;
/// The permission-bit mask of an `st_mode`.
const PERM_MASK: u32 = 0o7777;
/// The fixed inode mode metadata objects and archive/shared content take.
const FIXED_MODE: u32 = 0o644;
/// The chunk size for the streaming copy in [`Transaction::write_content`].
const COPY_CHUNK: usize = 64 * 1024;
/// Attempts made at an `ETXTBSY` fs-verity enable before it is reported. The
/// kernel refuses to seal an inode any writable descriptor still holds, and
/// `fork` copies the file descriptor table, so a child carries a copy of the
/// writable staging descriptor until its `exec` closes it. The retry outlasts
/// that fork-to-exec window while a genuine refusal still fails inside 50 ms.
const SEAL_ATTEMPTS: u32 = 50;
/// The pause between fs-verity enable attempts.
const SEAL_PAUSE: std::time::Duration = std::time::Duration::from_millis(1);

/// The logical metadata a content writer applies to an object.
///
/// This is the uid, gid, `st_mode`, and xattr set the object header records.
/// For a regular file the mode carries the `S_IFREG` bits; a symlink's mode is
/// fixed by the object model, so [`Transaction::write_symlink`] ignores
/// `mode` here.
#[derive(Debug, Clone)]
pub struct FileMeta {
    /// The logical owning user id.
    pub uid: u32,
    /// The logical owning group id.
    pub gid: u32,
    /// The full logical `st_mode`.
    pub mode: u32,
    /// The logical extended attributes.
    pub xattrs: Xattrs,
}

impl FileMeta {
    /// Metadata for a regular file with the given owner, permission bits, and
    /// no xattrs. The `S_IFREG` bit is added to `perm`.
    pub fn regular(uid: u32, gid: u32, perm: u32) -> FileMeta {
        FileMeta {
            uid,
            gid,
            mode: S_IFREG | (perm & PERM_MASK),
            xattrs: Xattrs::empty(),
        }
    }

    /// The header for a regular-file content object built from this metadata.
    pub(crate) fn regular_header(&self) -> FileHeader {
        FileHeader {
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
            symlink_target: String::new(),
            xattrs: self.xattrs.clone(),
        }
    }

    /// The header for a symlink content object with the given target. The mode
    /// is fixed to `S_IFLNK | 0o777` by the object model.
    fn symlink_header(&self, target: &str) -> FileHeader {
        FileHeader {
            uid: self.uid,
            gid: self.gid,
            mode: SYMLINK_MODE,
            symlink_target: target.to_owned(),
            xattrs: self.xattrs.clone(),
        }
    }
}

/// How a staged temp file is materialized under its final staging name.
#[derive(Debug)]
pub(crate) enum TempKind {
    /// An `O_TMPFILE` anonymous inode, linked into place via `/proc/self/fd`.
    Anonymous,
    /// A named temp file, renamed into place.
    Named(String),
}

/// A writer that streams one regular file's payload into a transaction.
///
/// Bytes written pass through a SHA-256 digester seeded with the framed
/// uncompressed header, so the object identity is complete at
/// [`finish`](ContentWriter::finish). In archive mode the same bytes feed a
/// raw-DEFLATE encoder whose output, prefixed by the framed archive header,
/// becomes the stored `.filez`; the uncompressed size is patched into the
/// reserved header region at finish. Dropping a writer without `finish`
/// abandons the staged temporary, which the transaction reaps.
///
/// Implements [`futures_io::AsyncWrite`] unconditionally and the tokio
/// `AsyncWrite` under the `tokio` feature.
pub struct ContentWriter<'txn> {
    txn: &'txn Transaction,
    hasher: Sha256,
    uncompressed: u64,
    header: FileHeader,
    expected: Option<Checksum>,
    temp: TempKind,
    sink: Sink,
}

/// The disk sink under a [`ContentWriter`].
enum Sink {
    /// The temp file receives the raw payload (bare family).
    Plain(RtFile),
    /// The temp file receives a framed archive header then DEFLATE output.
    Archive(DeflateEncoder<NoClose<RtFile>>),
}

impl ContentWriter<'_> {
    /// Finish the object: finalize the digest, verify it against the caller's
    /// expectation, apply per-mode metadata, and stage it under its loose name.
    /// A dedup hit (the object already in `objects/` or this transaction's
    /// staging set) returns the existing identity without restaging.
    pub async fn finish(self) -> Result<Checksum> {
        let ContentWriter {
            txn,
            hasher,
            uncompressed,
            header,
            expected,
            temp,
            sink,
        } = self;

        let file = match sink {
            Sink::Plain(mut file) => {
                flush(&mut file).await?;
                file
            }
            Sink::Archive(mut enc) => {
                close(&mut enc).await?;
                let mut file = enc.into_inner().into_inner();
                // Patch the reserved uncompressed-size field: the archive header
                // begins after the 4-byte length prefix and 4-byte NUL pad, and
                // its first member is the big-endian `t` size.
                seek(&mut file, SeekFrom::Start(8)).await?;
                write_all(&mut file, &uncompressed.to_be_bytes()).await?;
                flush(&mut file).await?;
                file
            }
        };

        let checksum = Checksum::from_bytes(hasher.finalize().into());
        if let Some(expected) = expected
            && expected != checksum
        {
            return Err(Error::ChecksumMismatch {
                expected,
                actual: checksum,
            });
        }

        let std_file = file.into_std().await;
        txn.stage_regular(checksum, header, std_file, temp, uncompressed)
            .await
    }
}

impl AsyncWrite for ContentWriter<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let n = match &mut me.sink {
            Sink::Plain(file) => std::task::ready!(Pin::new(file).poll_write(cx, buf))?,
            Sink::Archive(enc) => std::task::ready!(Pin::new(enc).poll_write(cx, buf))?,
        };
        me.hasher.update(&buf[..n]);
        me.uncompressed += n as u64;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().sink {
            Sink::Plain(file) => Pin::new(file).poll_flush(cx),
            Sink::Archive(enc) => Pin::new(enc).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A ContentWriter is finished through `finish`, not by closing the
        // stream; closing just flushes so a stray close does not truncate.
        self.poll_flush(cx)
    }
}

#[cfg(feature = "tokio")]
impl ostrya_rt::tokio_io::AsyncWrite for ContentWriter<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_close(self, cx)
    }
}

impl Transaction {
    /// A streaming writer for one regular-file payload.
    ///
    /// `meta` carries the logical uid/gid/mode/xattrs the object header records;
    /// `mode` must name a regular file. `expected`, when given, is checked
    /// against the computed identity at [`finish`](ContentWriter::finish).
    pub async fn content_writer(
        &self,
        expected: Option<&Checksum>,
        meta: &FileMeta,
    ) -> Result<ContentWriter<'_>> {
        let mode = self.repo().mode();
        if mode == RepoMode::BareSplitXattrs {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }
        let header = meta.regular_header();
        // Validate the regular-file mode up front and seed the identity with
        // the framed uncompressed header.
        let framed = frame(&header.serialize()?)?;
        let mut hasher = Sha256::new();
        hasher.update(&framed);

        let staging = self.staging_fd().try_clone_to_owned()?;
        let (fd, temp) = ostrya_rt::unblock(move || open_temp(staging.as_fd())).await?;
        let mut file = RtFile::from(fd);

        let sink = if mode.is_archive() {
            // Reserve the archive header region; the uncompressed size is
            // patched in at finish. Its byte length is independent of the
            // payload, so the length prefix written here is final.
            let placeholder = frame(&header.serialize_archive(0)?)?;
            write_all(&mut file, &placeholder).await?;
            let level = archive_level(self.repo().config().zlib_level()?);
            Sink::Archive(DeflateEncoder::with_quality(NoClose::new(file), level))
        } else {
            Sink::Plain(file)
        };

        Ok(ContentWriter {
            txn: self,
            hasher,
            uncompressed: 0,
            header,
            expected: expected.copied(),
            temp,
            sink,
        })
    }

    /// Stream a regular file's payload from `reader` into a new content object.
    pub async fn write_content(
        &self,
        expected: Option<&Checksum>,
        meta: &FileMeta,
        reader: impl AsyncRead + Unpin,
    ) -> Result<Checksum> {
        let mut writer = self.content_writer(expected, meta).await?;
        copy_stream(reader, &mut writer).await?;
        writer.finish().await
    }

    /// Write a regular file whose content the caller already holds. The general
    /// path is [`write_content`](Transaction::write_content), which streams.
    pub async fn write_regfile_inline(
        &self,
        expected: Option<&Checksum>,
        meta: &FileMeta,
        data: &[u8],
    ) -> Result<Checksum> {
        let mut writer = self.content_writer(expected, meta).await?;
        write_all(&mut writer, data).await?;
        writer.finish().await
    }

    /// Write a symlink content object. The identity is the framed header alone
    /// (no payload); storage follows the repository mode.
    pub async fn write_symlink(
        &self,
        target: &str,
        meta: &FileMeta,
        expected: Option<&Checksum>,
    ) -> Result<Checksum> {
        let mode = self.repo().mode();
        if mode == RepoMode::BareSplitXattrs {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }
        let header = meta.symlink_header(target);
        let checksum = Checksum::from_bytes(Sha256::digest(frame(&header.serialize()?)?).into());
        if let Some(expected) = expected
            && *expected != checksum
        {
            return Err(Error::ChecksumMismatch {
                expected: *expected,
                actual: checksum,
            });
        }
        self.stage_symlink(checksum, header).await
    }

    /// Write a metadata object from its normal-form serialized bytes. The
    /// identity is the SHA-256 of those bytes.
    pub async fn write_metadata(
        &self,
        ty: ObjectType,
        expected: Option<&Checksum>,
        bytes: &[u8],
    ) -> Result<Checksum> {
        if self.repo().mode() == RepoMode::BareSplitXattrs {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }
        if !ty.is_meta() {
            return Err(Error::Unsupported(format!(
                "write_metadata does not handle {ty:?} objects"
            )));
        }
        let checksum = Checksum::from_bytes(Sha256::digest(bytes).into());
        if let Some(expected) = expected
            && *expected != checksum
        {
            return Err(Error::ChecksumMismatch {
                expected: *expected,
                actual: checksum,
            });
        }
        self.stage_metadata(checksum, ty, bytes.to_vec()).await
    }
}

/// The raw-DEFLATE encoder level for an `[archive] zlib-level` value, clamped to
/// the 1-9 range the tool accepts.
fn archive_level(zlib_level: i64) -> Level {
    Level::Precise(zlib_level.clamp(1, 9) as i32)
}

/// Open an ingestion temp file in the staging directory: `O_TMPFILE` where the
/// filesystem allows it, a named temp file otherwise. Reused by the checkout
/// copy path, which opens its temporaries in the destination directory the same
/// way.
pub(crate) fn open_temp(staging_fd: BorrowedFd<'_>) -> Result<(OwnedFd, TempKind)> {
    match rustix::fs::openat(
        staging_fd,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(FIXED_MODE),
    ) {
        Ok(fd) => Ok((fd, TempKind::Anonymous)),
        // Any failure of the O_TMPFILE attempt falls back to a named temp; a
        // genuine error (ENOSPC and the like) resurfaces from that open.
        Err(_) => {
            let name = temp_name();
            let fd = rustix::fs::openat(
                staging_fd,
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_raw_mode(FIXED_MODE),
            )?;
            Ok((fd, TempKind::Named(name)))
        }
    }
}

/// The uid and gid an object freshly staged in `staging_fd` takes, measured by
/// creating a temporary there the way every staged object is created and reading
/// its inode.
///
/// Measured rather than derived: the group a created inode receives is the
/// directory's group when the directory is setgid and the process's effective
/// group otherwise, and a filesystem mounted with group inheritance gives the
/// directory's group either way. Creating one costs the same syscalls as reading
/// the rule's inputs and answers for the filesystem the staging directory is
/// actually on.
pub(crate) fn probe_fresh_owner(staging_fd: BorrowedFd<'_>) -> Result<(u32, u32)> {
    let (fd, temp) = open_temp(staging_fd)?;
    let stat = rustix::fs::fstat(&fd);
    cleanup_temp(staging_fd, &temp);
    let stat = stat?;
    Ok((stat.st_uid, stat.st_gid))
}

/// A per-process-unique ingestion temp file name.
fn temp_name() -> String {
    format!(".ostrya-tmp-{}-{}", std::process::id(), unique())
}

/// A per-process-unique counter value for temp file names. Every temp-name
/// helper in the crate draws from this single counter, so the suffixes they
/// format stay unique within the process.
pub(crate) fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The shared context for the blocking staging helpers: the directory fds, the
/// repository mode, and the durability settings.
pub(crate) struct StageCtx<'a> {
    /// The repository `objects/` directory, for the dedup check and fanout.
    pub(crate) objects_fd: BorrowedFd<'a>,
    /// The transaction's staging directory, where objects are ingested.
    pub(crate) staging_fd: BorrowedFd<'a>,
    /// The repository storage mode.
    pub(crate) mode: RepoMode,
    /// Whether durability syncs run at all.
    pub(crate) fsync: bool,
    /// Whether each object is fsynced individually at ingest.
    pub(crate) per_object_fsync: bool,
    /// The effective `[ex-integrity] fsverity` setting. Each freshly staged
    /// regular-file object is sealed with fs-verity unless this is
    /// [`Tristate::No`].
    pub(crate) verity: Tristate,
}

/// How a staged object's bytes reached the staging directory, which decides
/// whether the object consumes free space on the repository filesystem.
#[derive(Clone, Copy)]
pub(crate) enum Blocks {
    /// Data blocks freshly allocated: a fresh ingest, or a byte copy of another
    /// repository's object where a reflink was refused. Charged against the
    /// transaction's free-space budget.
    Written,
    /// The source inode shared by hardlink, which allocates no blocks and no
    /// inode.
    Linked,
    /// The source extents shared by a `FICLONE` reflink, which allocates no
    /// data blocks. Writing to either copy would allocate then, which no path
    /// in the port does: a loose object is content-addressed and never
    /// rewritten in place.
    Reflinked,
}

/// The outcome of staging one object.
pub(crate) struct StageOutcome {
    /// Whether the object was already present in `objects/` (a dedup hit).
    pub(crate) deduped: bool,
    /// The staged file's on-disk size in bytes, when freshly staged. In archive
    /// mode this is the compressed `.filez` storage size.
    pub(crate) on_disk_size: u64,
    /// How the staged bytes reached the staging directory. Read when the
    /// transaction records the object, which charges its free-space budget for
    /// the objects that allocate blocks and not for the ones that share them.
    pub(crate) blocks: Blocks,
    /// The logical (unpacked) content size in bytes: a regular file's
    /// pre-compression payload length, a symlink's target length, and zero for
    /// a metadata object (whose size the caller fills from `on_disk_size`).
    /// This is the `st_size` the tool records for the object in `ostree.sizes`.
    /// Carried into the archive size map.
    pub(crate) unpacked: u64,
    /// The flat staging name the object was linked under, when freshly staged.
    pub(crate) staging_name: String,
    /// The loose path the object publishes to, when freshly staged.
    pub(crate) dest: String,
}

/// Apply per-mode metadata to a content object's inode and materialize it into
/// the staging directory under its flat loose name. Runs synchronous syscalls.
pub(crate) fn stage_content_blocking(
    ctx: &StageCtx<'_>,
    checksum: &Checksum,
    header: &FileHeader,
    file: std::fs::File,
    temp: TempKind,
    unpacked: u64,
) -> Result<StageOutcome> {
    let dest = loose_path(checksum, ObjectType::File, ctx.mode);
    if crate::object::object_exists(ctx.objects_fd, &dest)? {
        cleanup_temp(ctx.staging_fd, &temp);
        return Ok(dedup(dest));
    }

    apply_content_metadata(file.as_fd(), ctx.mode, header)?;
    if ctx.fsync && ctx.per_object_fsync {
        rustix::fs::fsync(file.as_fd())?;
    }
    let on_disk_size = size_of(file.as_fd())?;
    let staging_name = flat_name(checksum, ObjectType::File, ctx.mode);
    // Seal with fs-verity while the inode is still anonymous, then link it from
    // the descriptor that owns it: with verity off, the writable one; with
    // verity on, a fresh read-only reopen after the writable descriptor closes.
    let link_fd = if ctx.verity == Tristate::No {
        OwnedFd::from(file)
    } else {
        let ro = reopen_ro(file.as_fd())?;
        drop(file);
        if let Err(e) = seal_regular(ro.as_fd(), ctx.verity) {
            cleanup_temp(ctx.staging_fd, &temp);
            return Err(e);
        }
        ro
    };
    materialize(ctx.staging_fd, link_fd.as_fd(), &temp, &staging_name)?;
    drop(link_fd);
    Ok(StageOutcome {
        deduped: false,
        on_disk_size,
        // The payload arrived in the temp file the caller opened. A caller that
        // filled it by reflink says so on the outcome it returns.
        blocks: Blocks::Written,
        unpacked,
        staging_name,
        dest,
    })
}

/// Stage a symlink content object: a real symlink in the bare family, a regular
/// file holding the target plus a NUL in the bare-user family, and a payloadless
/// framed archive header in archive mode.
pub(crate) fn stage_symlink_blocking(
    ctx: &StageCtx<'_>,
    checksum: &Checksum,
    header: &FileHeader,
) -> Result<StageOutcome> {
    let staging_fd = ctx.staging_fd;
    let dest = loose_path(checksum, ObjectType::File, ctx.mode);
    if crate::object::object_exists(ctx.objects_fd, &dest)? {
        return Ok(dedup(dest));
    }
    let staging_name = flat_name(checksum, ObjectType::File, ctx.mode);
    let target = &header.symlink_target;
    let do_fsync = ctx.fsync && ctx.per_object_fsync;

    let on_disk_size = match ctx.mode {
        RepoMode::Bare => {
            // A concurrent writer of the identical symlink may win the race; its
            // content is the same, so an existing entry is not an error.
            if stage_symlink_inode(staging_fd, target, &staging_name)? {
                rustix::fs::chownat(
                    staging_fd,
                    staging_name.as_str(),
                    Some(uid(header.uid)),
                    Some(gid(header.gid)),
                    AtFlags::SYMLINK_NOFOLLOW,
                )?;
                for (name, value) in header.xattrs.iter() {
                    set_link_xattr(staging_fd, &staging_name, name, value)?;
                }
            }
            target.len() as u64
        }
        RepoMode::BareUserOnly => {
            stage_symlink_inode(staging_fd, target, &staging_name)?;
            target.len() as u64
        }
        RepoMode::BareUser | RepoMode::BareUserShared => {
            // Stored as a regular file: content is the target plus one NUL, the
            // logical metadata lives in user.ostreemeta, and the inode is 0644.
            let mut content = target.clone().into_bytes();
            content.push(0);
            stage_named_regular(
                staging_fd,
                &staging_name,
                &content,
                FIXED_MODE,
                Some(&header.serialize_stat_metadata()?),
                do_fsync,
                ctx.verity,
            )?
        }
        RepoMode::Archive => {
            // A payloadless framed archive header.
            let body = frame(&header.serialize_archive(0)?)?;
            stage_named_regular(
                staging_fd,
                &staging_name,
                &body,
                FIXED_MODE,
                None,
                do_fsync,
                ctx.verity,
            )?
        }
        RepoMode::BareSplitXattrs => {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }
    };
    Ok(StageOutcome {
        deduped: false,
        on_disk_size,
        blocks: Blocks::Written,
        // The logical (unpacked) size of a symlink object is its target length,
        // matching the `st_size` the tool records for it in `ostree.sizes`.
        unpacked: target.len() as u64,
        staging_name,
        dest,
    })
}

/// Stage a metadata object: write the bytes to a temp file, `fchmod` 0644, and
/// materialize under the flat loose name.
pub(crate) fn stage_metadata_blocking(
    ctx: &StageCtx<'_>,
    checksum: &Checksum,
    ty: ObjectType,
    bytes: &[u8],
) -> Result<StageOutcome> {
    let dest = loose_path(checksum, ty, ctx.mode);
    if crate::object::object_exists(ctx.objects_fd, &dest)? {
        return Ok(dedup(dest));
    }
    let staging_name = flat_name(checksum, ty, ctx.mode);
    let on_disk_size = stage_named_regular(
        ctx.staging_fd,
        &staging_name,
        bytes,
        FIXED_MODE,
        None,
        ctx.fsync && ctx.per_object_fsync,
        ctx.verity,
    )?;
    Ok(StageOutcome {
        deduped: false,
        on_disk_size,
        blocks: Blocks::Written,
        unpacked: 0,
        staging_name,
        dest,
    })
}

/// Import one loose object from another repository's `objects/` directory into
/// the staging directory by sharing the source inode, without reading its
/// payload.
///
/// The object is hardlinked, which carries the source inode's mode, ownership,
/// and xattrs unchanged. A link is therefore admitted only where that inode is
/// the inode a write into this repository would have produced, which holds in two
/// cases: a content object into a bare destination, whose uid, gid, permission
/// bits, and xattrs are all a function of the header the object's checksum covers;
/// and a source inode already owned by `fresh_owner`, the uid and gid an object
/// freshly staged here takes. In every other mode the permission bits and xattrs
/// stay a function of the header while the ownership becomes a function of the
/// writer, which is what the second case tests.
///
/// The gate reads the source inode's ownership alone. The permission bits and the
/// xattrs are trusted to match the object's header rather than checked, since for
/// a content object outside bare mode the header is the read this path exists to
/// avoid. An inode rewritten out of band therefore carries its state across, and
/// so do attributes the destination's environment assigns rather than its writer
/// -- a default POSIX ACL on its directories, a security label -- which a fresh
/// write inherits and a link keeps the source's copy of.
///
/// `link_owner` is the uid and gid an object freshly staged here takes, the pair
/// the second case tests against, or `None` where no link is to be attempted at
/// all. The caller passes `None` for a forced copy and for a repository sealing
/// its objects, so the pair, which costs a probe of the staging directory to
/// measure, is measured only where the gate reads it.
///
/// `Ok(None)` reports a content object that is not staged -- its link refused by
/// the ownership gate, by an absent `link_owner`, or by the filesystem (the two
/// repositories on different filesystems, the source inode at its link limit, a
/// filesystem with no hardlinks, the kernel's protected-hardlink rules) --
/// leaving the caller to import it through its logical header, the one path that
/// applies this repository's own inode policy. A link that fails for any other
/// reason -- no space, a quota, an I/O error -- fails the import with that errno
/// rather than falling back to a copy that would fail the same way and report a
/// less specific cause.
///
/// A metadata object has no header, so its refused link is served here: the
/// bytes are copied with a `FICLONE` reflink where the filesystem supports one
/// and byte by byte otherwise, and the copy carries this repository's own
/// metadata-object inode -- 0644, no xattrs, and the writing process's
/// ownership.
///
/// The caller guarantees the two repositories store this object identically:
/// metadata objects are mode-independent, and a content object is imported this
/// way only between repositories that store it the same way.
///
/// A link is taken only where `[ex-integrity] fsverity` is [`Tristate::No`],
/// which the caller expresses by withholding `link_owner`. fs-verity is a
/// per-inode property, so sealing a hardlinked object would seal the source
/// repository's copy of it as well and make that copy immutable there; leaving it
/// unsealed would break this repository's own rule that every object stored as a
/// regular file is sealed. A repository that seals its writes therefore copies
/// every object instead, and the copy is sealed as any fresh write is.
pub(crate) fn stage_import_blocking(
    ctx: &StageCtx<'_>,
    src_objects_fd: BorrowedFd<'_>,
    checksum: &Checksum,
    ty: ObjectType,
    src_mode: RepoMode,
    link_owner: Option<(u32, u32)>,
) -> Result<Option<StageOutcome>> {
    // An import is a write like any other: a bare-split-xattrs destination needs
    // the `.file-xattrs` and `.file-xattrs-link` sidecars, which no import path
    // produces.
    if ctx.mode == RepoMode::BareSplitXattrs {
        return Err(Error::Unsupported(
            "bare-split-xattrs is read-only; the port does not write it".into(),
        ));
    }
    let dest = loose_path(checksum, ty, ctx.mode);
    if crate::object::object_exists(ctx.objects_fd, &dest)? {
        return Ok(Some(dedup(dest)));
    }
    let src_path = loose_path(checksum, ty, src_mode);
    let staging_name = flat_name(checksum, ty, ctx.mode);

    if let Some(fresh_owner) = link_owner {
        // The source stat decides whether the link is admissible and supplies the
        // staged object's size, since a hardlink is the inode it stats.
        let stat = match rustix::fs::statat(
            src_objects_fd,
            src_path.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => {
                return Err(Error::ObjectNotFound {
                    checksum: *checksum,
                    ty,
                });
            }
            Err(e) => return Err(e.into()),
        };
        let owned_as_written = (ty == ObjectType::File && ctx.mode == RepoMode::Bare)
            || (stat.st_uid, stat.st_gid) == fresh_owner;
        if owned_as_written {
            match rustix::fs::linkat(
                src_objects_fd,
                src_path.as_str(),
                ctx.staging_fd,
                staging_name.as_str(),
                AtFlags::empty(),
            ) {
                // An entry already under this name is the same object staged
                // earlier in this transaction.
                Ok(()) | Err(rustix::io::Errno::EXIST) => {
                    return Ok(Some(StageOutcome {
                        deduped: false,
                        on_disk_size: stat.st_size.max(0) as u64,
                        blocks: Blocks::Linked,
                        unpacked: 0,
                        staging_name,
                        dest,
                    }));
                }
                Err(rustix::io::Errno::NOENT) => {
                    return Err(Error::ObjectNotFound {
                        checksum: *checksum,
                        ty,
                    });
                }
                // A refusal the filesystem or the kernel imposes -- the two
                // repositories on different filesystems, the source inode at its
                // link limit, a filesystem that has no hardlinks, the kernel's
                // protected-hardlink rules -- leaves the object unstaged, to be
                // copied below or reported to the caller. Any other failure is
                // the import's own and carries its errno out: the copy that
                // follows would fail the same way and report a less specific
                // cause.
                Err(
                    rustix::io::Errno::XDEV
                    | rustix::io::Errno::MLINK
                    | rustix::io::Errno::OPNOTSUPP
                    | rustix::io::Errno::PERM,
                ) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    // A content object's inode metadata is the destination mode's to decide, and
    // the header it is decided from is what the caller reads.
    if ty == ObjectType::File {
        return Ok(None);
    }

    let (on_disk_size, blocks) = clone_metadata(ctx, src_objects_fd, &src_path, &staging_name)?;
    Ok(Some(StageOutcome {
        deduped: false,
        on_disk_size,
        blocks,
        unpacked: 0,
        staging_name,
        dest,
    }))
}

/// Import one regular-file content object between two repositories that store
/// its payload identically and its inode metadata differently, which is any two
/// modes of the bare family.
///
/// The payload is cloned -- a `FICLONE` reflink where the filesystem supports
/// one, a byte copy otherwise -- and the destination's own inode policy applied
/// from the object's logical header, so nothing of the source inode carries
/// over. The payload is neither read into memory nor re-hashed; a caller that
/// needs the checksum checked reads the object before calling.
pub(crate) fn stage_clone_content_blocking(
    ctx: &StageCtx<'_>,
    src_objects_fd: BorrowedFd<'_>,
    checksum: &Checksum,
    src_mode: RepoMode,
    header: &FileHeader,
    unpacked: u64,
) -> Result<StageOutcome> {
    // An import is a write like any other, and a content object crossing modes
    // reaches this path without passing through `stage_import_blocking`: a
    // bare-split-xattrs destination needs the `.file-xattrs` and
    // `.file-xattrs-link` sidecars, which no import path produces. Refused before
    // the source is opened and its payload cloned.
    if ctx.mode == RepoMode::BareSplitXattrs {
        return Err(Error::Unsupported(
            "bare-split-xattrs is read-only; the port does not write it".into(),
        ));
    }
    let src_path = loose_path(checksum, ObjectType::File, src_mode);
    let src = match rustix::fs::openat(
        src_objects_fd,
        src_path.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(src) => src,
        // A source object that vanished between the plan and the import is
        // reported as the missing object it is, as the link path reports it.
        Err(rustix::io::Errno::NOENT) => {
            return Err(Error::ObjectNotFound {
                checksum: *checksum,
                ty: ObjectType::File,
            });
        }
        Err(e) => return Err(e.into()),
    };
    let (file, temp, blocks) = clone_payload(ctx.staging_fd, src.as_fd())?;
    let mut outcome = stage_content_blocking(ctx, checksum, header, file, temp, unpacked)?;
    outcome.blocks = blocks;
    Ok(outcome)
}

/// Move a regular-file object's bytes into a fresh temp file in the staging
/// directory, applying no metadata: a `FICLONE` reflink where the filesystem
/// supports one, a byte copy otherwise. Returns the open temp file, the handle
/// it materializes under, and which of the two moved the bytes, cleaning the
/// temp up if the copy fails.
///
/// The byte copy is `std::io::copy`, which for a `File` to `File` transfer on
/// Linux specializes to `copy_file_range` and moves the payload inside the
/// kernel, falling back to a fixed stack buffer where the kernel refuses that.
/// The payload is therefore never buffered whatever its size, which is the
/// property that matters, and a reflink-less filesystem still gets a kernel-side
/// copy. The cost of the choice is that the transfer holds one blocking-pool
/// thread for its duration and cannot be cancelled: dropping the future that
/// awaits it leaves the copy running to completion, writing into a staging temp
/// the reaper collects.
fn clone_payload(
    staging_fd: BorrowedFd<'_>,
    src: BorrowedFd<'_>,
) -> Result<(std::fs::File, TempKind, Blocks)> {
    let (fd, temp) = open_temp(staging_fd)?;
    let mut dst = std::fs::File::from(fd);
    // A reflink shares the source extents outright; on any refusal (a
    // filesystem without reflink, a cross-filesystem source) nothing is
    // written, so the byte copy starts from an empty file.
    let copy = |dst: &mut std::fs::File| -> Result<Blocks> {
        if rustix::fs::ioctl_ficlone(dst.as_fd(), src).is_ok() {
            return Ok(Blocks::Reflinked);
        }
        let mut reader = std::fs::File::from(src.try_clone_to_owned()?);
        std::io::copy(&mut reader, dst)?;
        Ok(Blocks::Written)
    };
    match copy(&mut dst) {
        Ok(blocks) => Ok((dst, temp, blocks)),
        Err(e) => {
            cleanup_temp(staging_fd, &temp);
            Err(e)
        }
    }
}

/// Copy one loose metadata object into the staging directory under
/// `staging_name`. The bytes move by `FICLONE` reflink where the filesystem
/// allows and byte by byte otherwise; the copy carries the inode a metadata
/// object written into this repository carries in every mode -- 0644, no
/// xattrs, and the writing process's uid and gid, which the staging temporary
/// holds by construction. Returns the on-disk size and which of the two moves
/// the bytes took.
fn clone_metadata(
    ctx: &StageCtx<'_>,
    src_dir: BorrowedFd<'_>,
    src_path: &str,
    staging_name: &str,
) -> Result<(u64, Blocks)> {
    let src = rustix::fs::openat(
        src_dir,
        src_path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let (dst, temp, blocks) = clone_payload(ctx.staging_fd, src.as_fd())?;
    let apply = || -> Result<(u64, Blocks)> {
        rustix::fs::fchmod(dst.as_fd(), Mode::from_raw_mode(FIXED_MODE))?;
        if ctx.fsync && ctx.per_object_fsync {
            rustix::fs::fsync(dst.as_fd())?;
        }
        let on_disk_size = size_of(dst.as_fd())?;
        let link_fd = if ctx.verity == Tristate::No {
            OwnedFd::from(dst)
        } else {
            let ro = reopen_ro(dst.as_fd())?;
            drop(dst);
            seal_regular(ro.as_fd(), ctx.verity)?;
            ro
        };
        materialize(ctx.staging_fd, link_fd.as_fd(), &temp, staging_name)?;
        Ok((on_disk_size, blocks))
    };
    apply().inspect_err(|_| cleanup_temp(ctx.staging_fd, &temp))
}

/// Publish staged objects into `objects/` per the durability contract: with
/// fsync on, `syncfs` the repository, rename each object into `objects/<xx>/`,
/// then `fsync` each touched fanout directory and `objects/` itself.
pub(crate) fn publish_blocking(
    repo_fd: BorrowedFd<'_>,
    objects_fd: BorrowedFd<'_>,
    staging_fd: BorrowedFd<'_>,
    objects: &[(String, String)],
    fsync: bool,
) -> Result<()> {
    if fsync {
        rustix::fs::syncfs(repo_fd)?;
    }
    let mut fanouts: Vec<String> = Vec::new();
    for (staging_name, dest) in objects {
        let fanout = &dest[..2];
        ensure_fanout(objects_fd, fanout)?;
        rustix::fs::renameat(staging_fd, staging_name.as_str(), objects_fd, dest.as_str())?;
        if !fanouts.iter().any(|f| f == fanout) {
            fanouts.push(fanout.to_owned());
        }
    }
    if fsync {
        for fanout in &fanouts {
            let dir = rustix::fs::openat(
                objects_fd,
                fanout.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            rustix::fs::fsync(&dir)?;
        }
        rustix::fs::fsync(objects_fd)?;
    }
    Ok(())
}

/// Create a fanout directory `objects/<xx>/` on demand, ignoring a race that
/// already created it. The request mode is `0777` reduced by the umask. A
/// group-shared repository is arranged at the filesystem level, not here: an
/// operator sets the repository directory setgid `2775` with a default group
/// ACL (`setfacl -d -m g::rwx`) before `init`, and the OS propagates the group,
/// setgid bit, and permissions to every directory created underneath.
fn ensure_fanout(objects_fd: BorrowedFd<'_>, fanout: &str) -> Result<()> {
    match rustix::fs::mkdirat(objects_fd, fanout, Mode::from_raw_mode(0o777)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// A [`StageOutcome`] for an object already present in `objects/`.
fn dedup(dest: String) -> StageOutcome {
    StageOutcome {
        deduped: true,
        on_disk_size: 0,
        // Nothing was staged, so nothing moved bytes; the record path returns on
        // `deduped` before it reads either field.
        blocks: Blocks::Written,
        unpacked: 0,
        staging_name: String::new(),
        dest,
    }
}

/// The flat staging name for an object: its full hex checksum plus the loose
/// extension, holding the whole object in one staging-directory entry.
pub(crate) fn flat_name(checksum: &Checksum, ty: ObjectType, mode: RepoMode) -> String {
    format!("{}.{}", checksum.to_hex(), ty.extension(mode))
}

/// Apply the per-mode inode metadata of a regular-file content object.
fn apply_content_metadata(fd: BorrowedFd<'_>, mode: RepoMode, header: &FileHeader) -> Result<()> {
    let perm = header.mode & PERM_MASK;
    match mode {
        RepoMode::Bare => {
            // The xattrs go on before the chown and the mode: the kernel checks
            // a `user.*` xattr against the inode's write permission, which a
            // logical mode without an owner-write bit (0444, 0555) does not
            // grant, and a chown to another uid takes the ability away as well.
            for (name, value) in header.xattrs.iter() {
                set_inode_xattr(fd, name, value)?;
            }
            rustix::fs::fchown(fd, Some(uid(header.uid)), Some(gid(header.gid)))?;
            rustix::fs::fchmod(fd, Mode::from_raw_mode(perm))?;
        }
        RepoMode::BareUser => {
            // The xattr goes on before the mode: the kernel checks a `user.*`
            // xattr against the inode's write permission, and this mode's
            // canonical inode mode leaves no owner-write bit for a logical mode
            // that has none (0444, 0555).
            set_ostreemeta(fd, header)?;
            rustix::fs::fchmod(fd, Mode::from_raw_mode((perm & 0o775) | 0o400))?;
        }
        RepoMode::BareUserShared => {
            rustix::fs::fchmod(fd, Mode::from_raw_mode(FIXED_MODE))?;
            set_ostreemeta(fd, header)?;
        }
        RepoMode::BareUserOnly => {
            // Canonical mode: owner bits preserved, group- and other-write
            // dropped (recovered by observation, see format-reference.md).
            rustix::fs::fchmod(fd, Mode::from_raw_mode(perm & 0o755))?;
        }
        RepoMode::Archive => {
            rustix::fs::fchmod(fd, Mode::from_raw_mode(FIXED_MODE))?;
        }
        RepoMode::BareSplitXattrs => {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }
    }
    Ok(())
}

/// Write the `user.ostreemeta` xattr holding the logical `(uuua(ayay))`.
fn set_ostreemeta(fd: BorrowedFd<'_>, header: &FileHeader) -> Result<()> {
    let meta = header.serialize_stat_metadata()?;
    rustix::fs::fsetxattr(fd, "user.ostreemeta", &meta, XattrFlags::empty())?;
    Ok(())
}

/// Set one inode xattr, stripping the stored name's terminating NUL. Reused by
/// the checkout copy path to apply a file object's logical xattrs.
pub(crate) fn set_inode_xattr(fd: BorrowedFd<'_>, name: &[u8], value: &[u8]) -> Result<()> {
    let name = name.strip_suffix(&[0]).unwrap_or(name);
    let name = std::str::from_utf8(name)
        .map_err(|_| Error::InvalidFormat("xattr name is not valid UTF-8".into()))?;
    rustix::fs::fsetxattr(fd, name, value, XattrFlags::empty())?;
    Ok(())
}

/// Set one xattr on a staged symlink inode, stripping the stored name's
/// terminating NUL. A symlink cannot be opened for an fd, so the attribute is
/// set no-follow through the `/proc/self/fd` path of the directory. Reused by
/// the checkout path to apply a symlink object's link xattrs.
pub(crate) fn set_link_xattr(
    dir: BorrowedFd<'_>,
    staging_name: &str,
    name: &[u8],
    value: &[u8],
) -> Result<()> {
    let name = name.strip_suffix(&[0]).unwrap_or(name);
    let name = std::str::from_utf8(name)
        .map_err(|_| Error::InvalidFormat("xattr name is not valid UTF-8".into()))?;
    let link = format!("/proc/self/fd/{}/{}", dir.as_raw_fd(), staging_name);
    rustix::fs::lsetxattr(link.as_str(), name, value, XattrFlags::empty())?;
    Ok(())
}

/// Write `content` into a fresh named temp file, `fchmod` it, optionally set
/// `user.ostreemeta`, optionally fsync it, seal it with fs-verity per `verity`,
/// and rename it to `staging_name`. Returns the on-disk size. Used for small
/// caller-held bodies (symlinks stored as regular files and metadata objects).
fn stage_named_regular(
    staging_fd: BorrowedFd<'_>,
    staging_name: &str,
    content: &[u8],
    perm: u32,
    ostreemeta: Option<&[u8]>,
    do_fsync: bool,
    verity: Tristate,
) -> Result<u64> {
    use std::io::Write;

    let tmp = temp_name();
    let fd = rustix::fs::openat(
        staging_fd,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(perm),
    )?;
    let mut file = std::fs::File::from(fd);
    file.write_all(content)?;
    file.flush()?;
    rustix::fs::fchmod(file.as_fd(), Mode::from_raw_mode(perm))?;
    if let Some(meta) = ostreemeta {
        rustix::fs::fsetxattr(file.as_fd(), "user.ostreemeta", meta, XattrFlags::empty())?;
    }
    if do_fsync {
        rustix::fs::fsync(file.as_fd())?;
    }
    let size = size_of(file.as_fd())?;
    // Seal with fs-verity before the rename, once the writable descriptor is
    // closed. On any failure the named temp is removed so nothing is left
    // behind.
    if verity != Tristate::No {
        let ro = match reopen_ro(file.as_fd()) {
            Ok(ro) => ro,
            Err(e) => {
                let _ = rustix::fs::unlinkat(staging_fd, tmp.as_str(), AtFlags::empty());
                return Err(e);
            }
        };
        drop(file);
        if let Err(e) = seal_regular(ro.as_fd(), verity) {
            let _ = rustix::fs::unlinkat(staging_fd, tmp.as_str(), AtFlags::empty());
            return Err(e);
        }
    } else {
        drop(file);
    }
    match rustix::fs::renameat(staging_fd, tmp.as_str(), staging_fd, staging_name) {
        Ok(()) => {}
        Err(e) => {
            let _ = rustix::fs::unlinkat(staging_fd, tmp.as_str(), AtFlags::empty());
            return Err(e.into());
        }
    }
    Ok(size)
}

/// Reopen an open file read-only through `/proc/self/fd`, so the writable
/// descriptor to the same inode can be closed before `FS_IOC_ENABLE_VERITY`,
/// which the kernel refuses while any writable descriptor to the inode is open.
/// The reopened descriptor also links an anonymous `O_TMPFILE` inode into place.
fn reopen_ro(fd: BorrowedFd<'_>) -> Result<OwnedFd> {
    let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    Ok(rustix::fs::open(
        proc_path.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Enable fs-verity on a read-only descriptor per the configured tri-state.
/// [`Tristate::Maybe`] is best effort and swallows every enable error (a
/// filesystem without verity returns `ENOTTY`); [`Tristate::Yes`] fails the
/// write. Never called for [`Tristate::No`].
fn seal_regular(fd: BorrowedFd<'_>, verity: Tristate) -> Result<()> {
    let mut attempts = 0;
    let err = loop {
        attempts += 1;
        match ostrya_sys::enable_verity(fd) {
            Ok(()) => return Ok(()),
            Err(rustix::io::Errno::TXTBSY) if attempts < SEAL_ATTEMPTS => {
                std::thread::sleep(SEAL_PAUSE);
            }
            Err(e) => break e,
        }
    };
    if verity == Tristate::Maybe {
        return Ok(());
    }
    Err(Error::Unsupported(format!(
        "fsverity required but could not be enabled: {err}"
    )))
}

/// Materialize an ingestion temp file under `staging_name` in the staging
/// directory: link the anonymous inode (referenced through `link_fd`) into
/// place, or rename the named temp. For a named temp `link_fd` is unused.
fn materialize(
    staging_fd: BorrowedFd<'_>,
    link_fd: BorrowedFd<'_>,
    temp: &TempKind,
    staging_name: &str,
) -> Result<()> {
    match temp {
        TempKind::Anonymous => {
            let proc_path = format!("/proc/self/fd/{}", link_fd.as_raw_fd());
            match rustix::fs::linkat(
                rustix::fs::CWD,
                proc_path.as_str(),
                staging_fd,
                staging_name,
                AtFlags::SYMLINK_FOLLOW,
            ) {
                // A concurrent writer of the identical object linked it first;
                // the bytes are the same, so treat it as staged.
                Ok(()) | Err(rustix::io::Errno::EXIST) => Ok(()),
                Err(e) => Err(e.into()),
            }
        }
        TempKind::Named(name) => {
            rustix::fs::renameat(staging_fd, name.as_str(), staging_fd, staging_name)?;
            Ok(())
        }
    }
}

/// Create a real symlink object in the staging directory. Returns whether it
/// was freshly created; an existing entry (a concurrent writer of the identical
/// symlink) is not an error, since the content is the same.
fn stage_symlink_inode(
    staging_fd: BorrowedFd<'_>,
    target: &str,
    staging_name: &str,
) -> Result<bool> {
    match rustix::fs::symlinkat(target, staging_fd, staging_name) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::EXIST) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Discard an ingestion temp file after a dedup hit: an anonymous inode
/// vanishes when its fd closes, a named temp is unlinked.
fn cleanup_temp(staging_fd: BorrowedFd<'_>, temp: &TempKind) {
    if let TempKind::Named(name) = temp {
        let _ = rustix::fs::unlinkat(staging_fd, name.as_str(), AtFlags::empty());
    }
}

/// The on-disk size of an open file.
fn size_of(fd: BorrowedFd<'_>) -> Result<u64> {
    Ok(rustix::fs::fstat(fd)?.st_size.max(0) as u64)
}

fn uid(value: u32) -> Uid {
    Uid::from_raw(value)
}

fn gid(value: u32) -> Gid {
    Gid::from_raw(value)
}

/// A writer wrapper whose `poll_close` only flushes, so an inner file survives
/// the DEFLATE encoder finalizing its stream and can be recovered for the
/// header size-patch.
struct NoClose<W> {
    inner: W,
}

impl<W> NoClose<W> {
    fn new(inner: W) -> NoClose<W> {
        NoClose { inner }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for NoClose<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
}

// --- minimal poll_fn combinators, so the write path needs no futures-lite ---

async fn write_all<W: AsyncWrite + Unpin>(w: &mut W, mut buf: &[u8]) -> io::Result<()> {
    poll_fn(move |cx| {
        while !buf.is_empty() {
            match Pin::new(&mut *w).poll_write(cx, buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write returned zero",
                    )));
                }
                Poll::Ready(Ok(n)) => buf = &buf[n..],
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    })
    .await
}

pub(crate) async fn flush<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *w).poll_flush(cx)).await
}

async fn close<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *w).poll_close(cx)).await
}

async fn seek<S: AsyncSeek + Unpin>(s: &mut S, pos: SeekFrom) -> io::Result<u64> {
    poll_fn(|cx| Pin::new(&mut *s).poll_seek(cx, pos)).await
}

async fn read_some<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    poll_fn(|cx| Pin::new(&mut *r).poll_read(cx, buf)).await
}

/// Stream `reader` into `writer` in bounded chunks; no whole blob is buffered.
/// Reused by the checkout copy path to stream a file object's payload into a
/// destination temp file.
pub(crate) async fn copy_stream<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    writer: &mut W,
) -> io::Result<()> {
    let mut buf = vec![0u8; COPY_CHUNK];
    loop {
        let n = read_some(&mut reader, &mut buf).await?;
        if n == 0 {
            break;
        }
        write_all(writer, &buf[..n]).await?;
    }
    Ok(())
}

/// `ContentWriter` moves freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ContentWriter<'static>>();
    assert_send_sync::<FileMeta>();
};

#[cfg(feature = "tokio")]
const _: fn() = || {
    fn assert_tokio_write<T: ostrya_rt::tokio_io::AsyncWrite>() {}
    assert_tokio_write::<ContentWriter<'static>>();
};

#[cfg(test)]
mod verity_tests {
    use crate::{CreateOptions, FileMeta, Repo};
    use ostrya_composefs::FsVerityHasher;
    use ostrya_core::{ObjectType, RepoMode, loose_path};
    use ostrya_rt::block_on;
    use std::os::fd::AsFd;

    /// The kernel's measured fs-verity digest of a written content object equals
    /// the port's `FsVerityHasher` over the same payload, confirming the digest
    /// parameters (SHA-256, 4096-byte blocks, zero salt) the two share. A
    /// bare-user-shared `.file` stores the raw payload on disk, so the object's
    /// digest is the digest of the payload bytes. Skips where the filesystem
    /// does not support fs-verity.
    #[test]
    fn kernel_digest_matches_fsverity_hasher() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-verity-measure-{}-{}",
            std::process::id(),
            super::unique()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = dir.join("repo");
        // A payload spanning several verity blocks (> 4096 bytes).
        let payload = b"fs-verity measure cross-check payload\n".repeat(300);

        block_on(async {
            drop(
                Repo::create(&root, CreateOptions::new(RepoMode::BareUserShared))
                    .await
                    .unwrap(),
            );
            let cfg = root.join("config");
            let mut text = std::fs::read_to_string(&cfg).unwrap();
            text.push_str("[ex-integrity]\nfsverity=maybe\n");
            std::fs::write(&cfg, text).unwrap();
            let repo = Repo::open(&root).await.unwrap();

            let txn = repo.transaction().await.unwrap();
            let checksum = txn
                .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o644), &payload)
                .await
                .unwrap();
            txn.commit().await.unwrap();

            let object = root.join("objects").join(loose_path(
                &checksum,
                ObjectType::File,
                RepoMode::BareUserShared,
            ));
            let file = std::fs::File::open(&object).unwrap();
            match ostrya_sys::measure_verity(file.as_fd()) {
                Ok(measured) => assert_eq!(
                    measured,
                    FsVerityHasher::hash(&payload),
                    "kernel-measured digest equals the FsVerityHasher digest"
                ),
                // A filesystem without fs-verity sealed nothing to measure.
                Err(_) => eprintln!("skipping digest check: filesystem lacks fs-verity"),
            }
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
