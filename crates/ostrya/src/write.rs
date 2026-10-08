//! The write layer of the object store: content streams and staging.
//!
//! The public items are [`FileMeta`], [`ContentWriter`], and the object
//! writers of [`Transaction`]. [`ContentWriter`] holds the
//! storage and identity facts. The staging functions in this module run the
//! per-mode syscalls that the writers end with.
//!
//! The payload of a regular file streams through an `rt::File`. In archive
//! mode the encoder is `ostrya_core::DeflateSink`.
//!
//! The stager seals a regular-file content object with fs-verity before it
//! applies the logical mode and owner, because `FS_IOC_ENABLE_VERITY` needs
//! write permission on the inode. In bare mode the logical xattrs go on after
//! the seal, between the owner and the mode.

use std::future::poll_fn;
use std::io::{self, SeekFrom};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use async_compression::futures::write::DeflateDecoder;
use futures_io::{AsyncRead, AsyncSeek, AsyncWrite};
use ostrya_core::filehdr::frame;
use ostrya_core::{
    Checksum, ContentHasher, DeflateSink, DirMeta, FileHeader, ObjectType, RepoMode, Xattrs,
    loose_path,
};
use ostrya_rt::File as RtFile;
use rustix::fs::{AtFlags, Gid, Mode, OFlags, Uid, XattrFlags};
use sha2::{Digest, Sha256};

use crate::config::Tristate;
use crate::error::{Error, Result};
use crate::perm;
use crate::transaction::Transaction;

/// The regular-file mode bit.
const S_IFREG: u32 = 0o100000;
/// The symlink mode bit.
const S_IFLNK: u32 = 0o120000;
/// The full symlink `st_mode` a content object records for a symlink.
const SYMLINK_MODE: u32 = S_IFLNK | 0o777;
/// The permission-bit mask of an `st_mode`.
const PERM_MASK: u32 = 0o7777;
/// The file-type mask of an `st_mode`.
const S_IFMT: u32 = 0o170000;
/// The permission bits that `bare-user-only` keeps: the owner bits, and the
/// read and execute bits of the group and of others.
const CANONICAL_PERM_MASK: u32 = 0o755;
/// The fixed inode mode of metadata objects, and of archive and
/// `bare-user-shared` content objects.
const FIXED_MODE: u32 = 0o644;
/// The chunk size of a streaming pass over the payload of a content object.
///
/// [`Transaction::write_content`] copies in chunks of this size, and
/// `Repo::fsck` hashes in them.
pub(crate) const COPY_CHUNK: usize = 64 * 1024;
/// The number of attempts to enable fs-verity before an `ETXTBSY` error is
/// reported.
///
/// The kernel refuses to seal an inode while a writable descriptor to it is
/// open. `fork` copies the file descriptor table, so a child process holds a
/// copy of the writable staging descriptor until its `exec` closes it. The
/// retries outlast this window between `fork` and `exec`. A refusal that stays
/// still fails within 50 ms.
const SEAL_ATTEMPTS: u32 = 50;
/// The pause between fs-verity enable attempts.
const SEAL_PAUSE: std::time::Duration = std::time::Duration::from_millis(1);

/// The logical metadata that a writer records for a content object.
///
/// The fields are the uid, the gid, the `st_mode`, and the xattrs of the
/// object header. For a regular file, `mode` holds the `S_IFREG` bits. For a
/// symlink, [`Transaction::write_symlink`] states how it records `mode`.
///
/// A `bare-user-only` repository records no ownership and no xattrs. It
/// reduces the permission bits of a regular file to `perm & 0o755`. The
/// identity of the object covers this reduced header.
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
    /// Creates the metadata of a regular file with an owner, permission bits,
    /// and no xattrs.
    ///
    /// The `mode` field is `S_IFREG` plus the permission bits of `perm`
    /// (`perm & 0o7777`).
    pub fn regular(uid: u32, gid: u32, perm: u32) -> FileMeta {
        FileMeta {
            uid,
            gid,
            mode: S_IFREG | (perm & PERM_MASK),
            xattrs: Xattrs::empty(),
        }
    }

    /// Returns `true` if the mode names a symlink.
    pub(crate) fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }

    /// Returns the header of a regular-file content object for this metadata.
    pub(crate) fn regular_header(&self) -> FileHeader {
        FileHeader {
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
            symlink_target: String::new(),
            xattrs: self.xattrs.clone(),
        }
    }

    /// Returns the header of a symlink content object with the target `target`.
    ///
    /// If the mode names a symlink, the header records it unchanged, with its
    /// permission bits. A `--statoverride` entry on a symlink needs this, and
    /// so does a symlink object copied from another repository. If the mode
    /// names a regular file or no file type, the header records
    /// `S_IFLNK | 0o777`. A caller that states only permission bits builds
    /// these forms.
    ///
    /// The header records any other file type unchanged, and the check of the
    /// header refuses it. If a `--statoverride` value gives a symlink a type
    /// that the object model does not hold, the write fails. The write records
    /// no mode that the entry did not ask for.
    fn symlink_header(&self, target: &str) -> FileHeader {
        FileHeader {
            uid: self.uid,
            gid: self.gid,
            mode: match self.mode & S_IFMT {
                0 | S_IFREG => SYMLINK_MODE,
                _ => self.mode,
            },
            symlink_target: target.to_owned(),
            xattrs: self.xattrs.clone(),
        }
    }
}

/// Returns the logical header that a repository of mode `mode` records for a
/// content object.
///
/// Each mode except `bare-user-only` records the header unchanged.
/// `bare-user-only` stores no ownership and no xattrs, and it reduces the
/// permission bits of a regular file to `perm & 0o755`. The header that it
/// records is this reduced form, and the identity of the object covers the
/// reduced header. The object model fixes the mode of a symlink, so the
/// function keeps that mode. A symlink loses its ownership and xattrs as a
/// regular file does.
pub(crate) fn canonical_header(mode: RepoMode, mut header: FileHeader) -> FileHeader {
    if mode == RepoMode::BareUserOnly {
        header.uid = 0;
        header.gid = 0;
        header.xattrs = Xattrs::empty();
        if header.mode & S_IFMT != S_IFLNK {
            header.mode = (header.mode & S_IFMT) | (header.mode & CANONICAL_PERM_MASK);
        }
    }
    header
}

/// Returns the directory metadata that `bare-user-only` records.
///
/// The metadata has no ownership and no xattrs, and its permission bits are
/// reduced as for a regular file.
fn canonical_dirmeta(meta: &DirMeta) -> DirMeta {
    DirMeta {
        uid: 0,
        gid: 0,
        mode: (meta.mode & S_IFMT) | (meta.mode & CANONICAL_PERM_MASK),
        xattrs: Xattrs::empty(),
    }
}

/// How a staged temp file gets its final staging name.
#[derive(Debug)]
pub(crate) enum TempKind {
    /// An `O_TMPFILE` anonymous inode, linked into place through
    /// `/proc/self/fd`.
    Anonymous,
    /// A named temp file, renamed into place.
    Named(String),
}

/// An ingestion temp file that is not staged yet.
///
/// A drop removes the temp. An anonymous inode goes away when its descriptor
/// closes, and the drop unlinks a named temp.
/// [`into_inner`](PendingTemp::into_inner) hands the temp on for staging.
struct PendingTemp<'a> {
    staging_fd: BorrowedFd<'a>,
    temp: Option<TempKind>,
}

impl<'a> PendingTemp<'a> {
    fn new(staging_fd: BorrowedFd<'a>, temp: TempKind) -> PendingTemp<'a> {
        PendingTemp {
            staging_fd,
            temp: Some(temp),
        }
    }

    /// Returns the temp and stops its removal on drop.
    fn into_inner(mut self) -> TempKind {
        self.temp
            .take()
            .expect("a pending temp holds its temp until handed on")
    }
}

impl Drop for PendingTemp<'_> {
    fn drop(&mut self) {
        // One unlink of one name. A dedup hit costs the same.
        if let Some(temp) = &self.temp {
            cleanup_temp(self.staging_fd, temp);
        }
    }
}

/// A writer that streams the payload of one regular file into a transaction.
///
/// [`Transaction::content_writer`] creates the writer, and
/// [`finish`](ContentWriter::finish) stages the object. The writer implements
/// `futures_io::AsyncWrite`. With the `tokio` feature, it also implements the
/// tokio `AsyncWrite`.
///
/// If the caller drops the writer before `finish`, or if `finish` fails before
/// it stages the object, the writer removes its temp file.
///
/// # Identity
///
/// The identity of a content object is the SHA-256 of the framed uncompressed
/// header, followed by the raw payload. The writer seeds the hash with the
/// framed header and hashes each byte that it receives. The identity is
/// complete when the stream ends, for each storage form.
///
/// # Storage
///
/// - The payload goes into a temp file in the staging directory. If the file
///   system supports `O_TMPFILE`, the temp file is an unnamed inode that
///   `linkat` gives a name. Otherwise it is a named temp file.
/// - In the bare modes, the temp file receives the raw payload.
/// - In archive mode, the bytes go through a raw-DEFLATE encoder at the level
///   of `[archive] zlib-level`, clamped to the range 1-9. The stored `.filez`
///   is the framed archive header, followed by the DEFLATE output.
///   [`finish`](ContentWriter::finish) writes the uncompressed size into the
///   reserved field of the header.
/// - The inode mode comes from an explicit `fchmod` call, and never from the
///   umask. It is the mode observed on the objects that the `ostree` command
///   writes. In `bare` mode, the owner comes from an explicit `fchown` call.
pub struct ContentWriter<'txn> {
    txn: &'txn Transaction,
    hasher: Sha256,
    uncompressed: u64,
    header: FileHeader,
    expected: Option<Checksum>,
    temp: PendingTemp<'txn>,
    sink: Sink,
    /// `true` if the payload adds to
    /// [`content_bytes_unpacked`](crate::TransactionStats::content_bytes_unpacked).
    counted: bool,
}

/// The disk sink under a [`ContentWriter`].
enum Sink {
    /// The temp file receives the raw payload (bare family).
    Plain(RtFile),
    /// The temp file receives a framed archive header then DEFLATE output.
    Archive(DeflateSink<RtFile>),
}

impl ContentWriter<'_> {
    /// Returns the same writer, with a payload that adds nothing to
    /// [`content_bytes_unpacked`](crate::TransactionStats::content_bytes_unpacked).
    ///
    /// A static delta writes its objects through such a writer.
    pub(crate) fn uncounted(mut self) -> Self {
        self.counted = false;
        self
    }

    /// Finishes the object and returns its checksum.
    ///
    /// The call finalizes the digest. If the caller gave an expected checksum,
    /// the call verifies the digest against it. Then it applies the metadata of
    /// the repository mode and stages the object under its loose name.
    ///
    /// If `objects/` already holds the object, the call removes its temp file
    /// and stages nothing. If the staging set of the transaction already holds
    /// the object, the call keeps the staged copy and adds no second one.
    ///
    /// # Errors
    ///
    /// - [`Error::ChecksumMismatch`] if the computed checksum differs from the
    ///   expected checksum.
    /// - [`Error::InsufficientFreeSpace`] if the object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Unsupported`] if `[ex-integrity] fsverity` is `yes` and the
    ///   fs-verity seal fails.
    /// - [`Error::Core`] if `[core] fsync` or `[core] per-object-fsync` in the
    ///   repository config is malformed.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` or
    ///   `[ex-integrity] composefs` in the repository config is malformed.
    /// - [`Error::InvalidFormat`] if the repository is in `bare` mode and an
    ///   xattr name in the header is not valid UTF-8.
    /// - [`Error::Io`] if a write, a sync, or a syscall of the staging step
    ///   fails.
    pub async fn finish(self) -> Result<Checksum> {
        let ContentWriter {
            txn,
            hasher,
            uncompressed,
            header,
            expected,
            temp,
            sink,
            counted,
        } = self;

        let file = match sink {
            Sink::Plain(mut file) => {
                flush(&mut file).await?;
                file
            }
            Sink::Archive(mut enc) => {
                close(&mut enc).await?;
                let mut file = enc.into_inner();
                // Write the reserved uncompressed-size field. The archive header
                // starts after the 4-byte length prefix and the 4-byte NUL pad.
                // Its first member is the big-endian `t` size.
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
        txn.stage_regular(
            checksum,
            header,
            std_file,
            temp.into_inner(),
            uncompressed,
            counted,
        )
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
        // `finish` ends a ContentWriter. A close only flushes, so a stray
        // close does not truncate the object.
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

/// Methods that stage objects.
impl Transaction {
    /// Creates a streaming writer for the payload of one regular file.
    ///
    /// `meta` holds the logical uid, gid, mode, and xattrs that the object
    /// header records. `meta.mode` must name a regular file. The call refuses
    /// only a mode that names neither a regular file nor a symlink.
    ///
    /// If `expected` is given, [`finish`](ContentWriter::finish) verifies the
    /// computed identity against it. [`ContentWriter`] states the identity and
    /// the storage form.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`,
    ///   which ostrya does not write.
    /// - [`Error::Core`] if the file-type bits of `meta.mode` name neither a
    ///   regular file nor a symlink.
    /// - [`Error::Core`] if the repository is in archive mode and
    ///   `[archive] zlib-level` in the repository config is malformed.
    /// - [`Error::Io`] if the temp file cannot be created or written.
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
        let header = canonical_header(mode, meta.regular_header());
        // Check the regular-file mode first, and seed the identity with the
        // framed uncompressed header.
        let framed = frame(&header.serialize()?)?;
        let mut hasher = Sha256::new();
        hasher.update(&framed);

        let staging = self.staging_fd().try_clone_to_owned()?;
        let (fd, temp) = ostrya_rt::unblock(move || open_temp(staging.as_fd())).await?;
        let temp = PendingTemp::new(self.staging_fd(), temp);
        let mut file = RtFile::from(fd);

        let sink = if mode.is_archive() {
            // Reserve the region of the archive header. `finish` writes the
            // uncompressed size into it. The byte length of the region does
            // not depend on the payload, so the length prefix written here is
            // final.
            let placeholder = frame(&header.serialize_archive(0)?)?;
            write_all(&mut file, &placeholder).await?;
            let level = archive_level(self.repo().config().zlib_level()?);
            Sink::Archive(DeflateSink::new(file, level))
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
            counted: true,
        })
    }

    /// Streams the payload of a regular file from `reader` into a content
    /// object.
    ///
    /// The call copies `reader` into a [`ContentWriter`] in chunks of 64 KiB,
    /// so it never holds the whole payload in memory. `meta` and `expected`
    /// are as for [`content_writer`](Transaction::content_writer). The call
    /// returns the checksum of the object.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`,
    ///   or if `[ex-integrity] fsverity` is `yes` and the fs-verity seal fails.
    /// - [`Error::ChecksumMismatch`] if `expected` is given and differs from
    ///   the computed checksum.
    /// - [`Error::InsufficientFreeSpace`] if the object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] if the file-type bits of `meta.mode` name neither a
    ///   regular file nor a symlink.
    /// - [`Error::Core`] if a `[core]` or `[archive]` value in the repository
    ///   config is malformed.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` or
    ///   `[ex-integrity] composefs` in the repository config is malformed.
    /// - [`Error::InvalidFormat`] if the repository is in `bare` mode and an
    ///   xattr name in `meta` is not valid UTF-8.
    /// - [`Error::Io`] if a read from `reader` fails, or if a file system
    ///   operation fails.
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

    /// Writes a regular file whose content the caller holds in memory.
    ///
    /// [`write_content`](Transaction::write_content) streams a payload from a
    /// reader. `meta` and `expected` are as for
    /// [`content_writer`](Transaction::content_writer). The call returns the
    /// checksum of the object.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`,
    ///   or if `[ex-integrity] fsverity` is `yes` and the fs-verity seal fails.
    /// - [`Error::ChecksumMismatch`] if `expected` is given and differs from
    ///   the computed checksum.
    /// - [`Error::InsufficientFreeSpace`] if the object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] if the file-type bits of `meta.mode` name neither a
    ///   regular file nor a symlink.
    /// - [`Error::Core`] if a `[core]` or `[archive]` value in the repository
    ///   config is malformed.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` or
    ///   `[ex-integrity] composefs` in the repository config is malformed.
    /// - [`Error::InvalidFormat`] if the repository is in `bare` mode and an
    ///   xattr name in `meta` is not valid UTF-8.
    /// - [`Error::Io`] if a file system operation fails.
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

    /// Stores a content object whose payload arrives DEFLATE-compressed in the
    /// archive wire form.
    ///
    /// The payload is the `.filez` bytes of an archive remote. The call writes
    /// the fetched bytes to the staging file unchanged. It does not inflate
    /// and compress them again.
    ///
    /// The call stores `framed_header` exactly as given, with the uncompressed
    /// size that it declares. It does not change that size to the size that
    /// `payload` inflates to. A second branch inflates the payload and
    /// discards the output, to feed the digest that gives the identity of the
    /// object.
    ///
    /// The inflated byte count must be exactly `declared`. The call refuses a
    /// header that states a size larger or smaller than its payload, so it
    /// stores no object with a wrong size.
    ///
    /// The repository must be in archive mode. `header` must not be the
    /// header of a symlink, which has no payload (see
    /// [`write_symlink`](Transaction::write_symlink)).
    pub(crate) async fn write_archive_payload<R: AsyncRead + Unpin>(
        &self,
        expected: &Checksum,
        header: &FileHeader,
        framed_header: &[u8],
        declared: u64,
        payload: R,
        buf: &mut Vec<u8>,
    ) -> Result<Checksum> {
        if !self.repo().mode().is_archive() {
            return Err(Error::Unsupported(
                "write_archive_payload stores an archive-form payload; the destination is not \
                 archive"
                    .into(),
            ));
        }

        let staging = self.staging_fd().try_clone_to_owned()?;
        let (fd, temp) = ostrya_rt::unblock(move || open_temp(staging.as_fd())).await?;
        let temp = PendingTemp::new(self.staging_fd(), temp);
        let mut file = RtFile::from(fd);
        write_all(&mut file, framed_header).await?;

        feed_archive_payload(expected, header, declared, payload, buf, Some(&mut file)).await?;

        flush(&mut file).await?;
        let std_file = file.into_std().await;
        self.stage_regular(
            *expected,
            header.clone(),
            std_file,
            temp.into_inner(),
            declared,
            true,
        )
        .await
    }

    /// Writes a symlink content object and returns its checksum.
    ///
    /// A symlink object has no payload, so its identity is the SHA-256 of the
    /// framed header alone. The storage form follows the repository mode:
    ///
    /// - In `bare` and `bare-user-only`, a symlink.
    /// - In `bare-user` and `bare-user-shared`, a regular file with mode
    ///   `0644` that holds the target and one NUL. The `user.ostreemeta` xattr
    ///   holds the logical metadata.
    /// - In `archive`, a framed archive header with no payload.
    ///
    /// # Mode
    ///
    /// If `meta.mode` names a symlink, the object records it unchanged, with
    /// its permission bits. If `meta.mode` names a regular file or no file
    /// type, the object records `S_IFLNK | 0o777`. Any other file type fails
    /// the write.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`,
    ///   which ostrya does not write.
    /// - [`Error::Unsupported`] if `[ex-integrity] fsverity` is `yes`, the
    ///   object is stored as a regular file, and the fs-verity seal fails.
    /// - [`Error::ChecksumMismatch`] if `expected` is given and differs from
    ///   the computed checksum.
    /// - [`Error::InsufficientFreeSpace`] if the object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] if `meta.mode` names a file type other than a
    ///   symlink or a regular file, or if `target` holds a NUL byte.
    /// - [`Error::Core`] if `[core] fsync` or `[core] per-object-fsync` in the
    ///   repository config is malformed.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` or
    ///   `[ex-integrity] composefs` in the repository config is malformed.
    /// - [`Error::InvalidFormat`] if the repository is in `bare` mode and an
    ///   xattr name in `meta` is not valid UTF-8.
    /// - [`Error::Io`] if a file system operation fails.
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
        let header = canonical_header(mode, meta.symlink_header(target));
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

    /// Writes a directory-metadata object for `meta` and returns its checksum.
    ///
    /// The object records what the repository mode stores for a directory.
    /// `bare-user-only` discards the ownership and the xattrs, and it reduces
    /// the permission bits as for a regular file. A commit into such a
    /// repository records this canonical form, and the identity of the
    /// dirmeta covers it. Each other mode records `meta` unchanged.
    ///
    /// A commit uses this path for its own directories. A caller that builds a
    /// tree uses it too.
    ///
    /// A caller can serialize a [`DirMeta`] and give the bytes to
    /// [`write_metadata`](Transaction::write_metadata). The object then stores
    /// the form that `meta` states, with the checksum of that form. In a
    /// `bare-user-only` repository, this checksum differs from the checksum
    /// that the repository records for the same directory.
    ///
    /// A dirmeta from another source, for example a pull or a static delta,
    /// keeps the bytes that its checksum names. It goes through
    /// [`write_metadata`](Transaction::write_metadata).
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`,
    ///   or if `[ex-integrity] fsverity` is `yes` and the fs-verity seal fails.
    /// - [`Error::InsufficientFreeSpace`] if the object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] if the file-type bits of `meta.mode` are not the
    ///   directory type, or if a `[core]` value in the repository config is
    ///   malformed.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` or
    ///   `[ex-integrity] composefs` in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
    pub async fn write_dirmeta(&self, meta: &DirMeta) -> Result<Checksum> {
        let bytes = self.dirmeta_bytes(meta)?;
        self.write_metadata(ObjectType::DirMeta, None, &bytes).await
    }

    /// Returns the serialized bytes that
    /// [`write_dirmeta`](Transaction::write_dirmeta) records for `meta` under
    /// the mode of this repository.
    fn dirmeta_bytes(&self, meta: &DirMeta) -> Result<Vec<u8>> {
        Ok(if self.repo().mode() == RepoMode::BareUserOnly {
            canonical_dirmeta(meta).serialize()?
        } else {
            meta.serialize()?
        })
    }

    /// Returns the checksum that [`write_dirmeta`](Transaction::write_dirmeta)
    /// records for `meta`, and stages no object.
    ///
    /// A caller compares it with a recorded dirmeta before it decides to
    /// stage.
    pub(crate) fn dirmeta_checksum(&self, meta: &DirMeta) -> Result<Checksum> {
        let bytes = self.dirmeta_bytes(meta)?;
        Ok(Checksum::from_bytes(Sha256::digest(&bytes).into()))
    }

    /// Writes a metadata object from its serialized bytes in normal form.
    ///
    /// The identity is the SHA-256 of `bytes`. The call returns the checksum
    /// of the object.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository mode is `bare-split-xattrs`,
    ///   or if `ty` is not a metadata object type.
    /// - [`Error::Unsupported`] if `[ex-integrity] fsverity` is `yes` and the
    ///   fs-verity seal fails.
    /// - [`Error::ChecksumMismatch`] if `expected` is given and differs from
    ///   the computed checksum.
    /// - [`Error::InsufficientFreeSpace`] if the object needs more space than
    ///   the free-space budget of the transaction holds.
    /// - [`Error::Core`] if `[core] fsync` or `[core] per-object-fsync` in the
    ///   repository config is malformed.
    /// - [`Error::InvalidFormat`] if `[ex-integrity] fsverity` or
    ///   `[ex-integrity] composefs` in the repository config is malformed.
    /// - [`Error::Io`] if a file system operation fails.
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

/// Reads the archive-form payload of a content object to its end and checks
/// it.
///
/// The function stores nothing. The payload must inflate to exactly
/// `declared` bytes, with no bytes after its DEFLATE end. It must hash to
/// `expected` under `header`. This is the check of an object whose bytes are
/// discarded because the repository already holds the object.
#[cfg(feature = "receive")]
pub(crate) async fn check_archive_payload<R: AsyncRead + Unpin>(
    expected: &Checksum,
    header: &FileHeader,
    declared: u64,
    payload: R,
    buf: &mut Vec<u8>,
) -> Result<()> {
    feed_archive_payload(expected, header, declared, payload, buf, None).await
}

/// Reads an archive-form payload to its end, and writes the compressed bytes
/// to `file` if `file` is given.
///
/// A discarded branch inflates the payload to check its size and its
/// checksum.
async fn feed_archive_payload<R: AsyncRead + Unpin>(
    expected: &Checksum,
    header: &FileHeader,
    declared: u64,
    mut payload: R,
    buf: &mut Vec<u8>,
    mut file: Option<&mut RtFile>,
) -> Result<()> {
    let mut inflate = DeflateDecoder::new(InflatedDigest::new(header, *expected, declared)?);
    if buf.len() < COPY_CHUNK {
        buf.resize(COPY_CHUNK, 0);
    }
    // A short write from the decoder means that its DEFLATE stream ended in
    // this chunk. The decoder takes no more input. The loop gives it no more
    // bytes, and only drains the rest to return the connection to the pool.
    // Each byte that stays unconsumed, here or later in the stream, trails
    // the object. A write error is a different case: the sink refused the
    // payload (an inflated-size overrun). `?` passes the message of that
    // failure to the caller.
    let mut trailing = false;
    loop {
        let n = read_some(&mut payload, buf).await?;
        if n == 0 {
            break;
        }
        if let Some(file) = file.as_deref_mut() {
            write_all(file, &buf[..n]).await?;
        }
        if !trailing && write_up_to(&mut inflate, &buf[..n]).await? < n {
            trailing = true;
        }
    }
    if trailing {
        return Err(Error::InvalidFormat(format!(
            "content object {expected}: bytes follow the deflated payload"
        )));
    }
    close(&mut inflate).await?;

    let digest = inflate.into_inner();
    if digest.seen != declared {
        return Err(Error::InvalidFormat(format!(
            "content object {expected}: the payload inflates to {} byte(s), not the \
             {declared} its header declares",
            digest.seen
        )));
    }
    let checksum = digest.hasher.finish();
    if checksum != *expected {
        return Err(Error::ChecksumMismatch {
            expected: *expected,
            actual: checksum,
        });
    }
    Ok(())
}

/// Returns the raw-DEFLATE encoder level for an `[archive] zlib-level` value.
///
/// The level is clamped to the range 1-9 that the `ostree` command accepts.
pub(crate) fn archive_level(zlib_level: i64) -> u8 {
    zlib_level.clamp(1, 9) as u8
}

/// Opens an ingestion temp file in the staging directory.
///
/// The function uses `O_TMPFILE` if the file system supports it, and a named
/// temp file otherwise. The checkout copy path also uses this function, to
/// open its temp files in the destination directory.
pub(crate) fn open_temp(staging_fd: BorrowedFd<'_>) -> Result<(OwnedFd, TempKind)> {
    match rustix::fs::openat(
        staging_fd,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(FIXED_MODE),
    ) {
        Ok(fd) => Ok((fd, TempKind::Anonymous)),
        // Each failure of the O_TMPFILE attempt falls back to a named temp. A
        // real error, for example ENOSPC, comes back from that open.
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

/// Returns the uid and gid that a newly staged object in `staging_fd` gets.
///
/// The function creates a temp file there, as for each staged object, and
/// reads its inode.
///
/// The function measures the pair, because the rule has more than one input.
/// If the directory is setgid, a created inode gets the group of the
/// directory. Otherwise it gets the effective group of the process. A file
/// system mounted with group inheritance gives the group of the directory in
/// both cases.
///
/// One create costs the same syscalls as a read of the inputs of the rule. It
/// also gives the answer for the file system that holds the staging directory.
pub(crate) fn probe_fresh_owner(staging_fd: BorrowedFd<'_>) -> Result<(u32, u32)> {
    let (fd, temp) = open_temp(staging_fd)?;
    let stat = rustix::fs::fstat(&fd);
    cleanup_temp(staging_fd, &temp);
    let stat = stat?;
    Ok((stat.st_uid, stat.st_gid))
}

/// Returns an ingestion temp file name that is unique in the process.
fn temp_name() -> String {
    format!(".ostrya-tmp-{}-{}", std::process::id(), unique())
}

/// Returns the next value of the process-wide counter for temp file names.
///
/// Each temp-name helper of the crate draws from this one counter, so the
/// suffixes of the names stay unique in the process.
pub(crate) fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The shared context of the blocking staging helpers: the directory
/// descriptors, the repository mode, and the durability settings.
pub(crate) struct StageCtx<'a> {
    /// The `objects/` directory of the repository, for the dedup check and
    /// the fanout.
    pub(crate) objects_fd: BorrowedFd<'a>,
    /// The staging directory of the transaction, where the helpers stage
    /// objects.
    pub(crate) staging_fd: BorrowedFd<'a>,
    /// The storage mode of the repository.
    pub(crate) mode: RepoMode,
    /// `true` if durability syncs run at all.
    pub(crate) fsync: bool,
    /// `true` if the file of each content object is synced at ingest.
    ///
    /// If `sync_metadata` is not set, metadata objects are not synced.
    pub(crate) per_object_fsync: bool,
    /// `true` if the file of a metadata object is synced at ingest, with fsync
    /// on.
    ///
    /// A transaction sets it for an object that it stages after a `syncfs`
    /// made the earlier objects durable. Then the publication step needs no
    /// second `syncfs`.
    pub(crate) sync_metadata: bool,
    /// The effective `[ex-integrity] fsverity` setting.
    ///
    /// If this is not [`Tristate::No`], each newly staged regular-file object
    /// is sealed with fs-verity.
    pub(crate) verity: Tristate,
}

/// How the bytes of a staged object reached the staging directory.
///
/// The kind decides if the object uses free space on the file system of the
/// repository.
#[derive(Clone, Copy)]
pub(crate) enum Blocks {
    /// Newly allocated data blocks: a new ingest, or a byte copy of an object
    /// of another repository after a refused reflink.
    ///
    /// The transaction charges them against its free-space budget.
    Written,
    /// The source inode, shared by a hardlink, which allocates no blocks and
    /// no inode.
    Linked,
    /// The source extents, shared by a `FICLONE` reflink, which allocates no
    /// data blocks.
    ///
    /// A write to either copy allocates blocks. No path in ostrya does such a
    /// write, because a loose object is content-addressed and never rewritten
    /// in place.
    Reflinked,
}

/// The outcome of the staging of one object.
pub(crate) struct StageOutcome {
    /// `true` if `objects/` already holds the object (a dedup hit).
    pub(crate) deduped: bool,
    /// The size on disk of the staged file in bytes, if the object is newly
    /// staged.
    ///
    /// In archive mode this is the compressed storage size of the `.filez`.
    pub(crate) on_disk_size: u64,
    /// How the staged bytes reached the staging directory.
    ///
    /// The transaction reads it when it records the object. It charges its
    /// free-space budget for the objects that allocate blocks, and not for the
    /// objects that share them.
    pub(crate) blocks: Blocks,
    /// The logical (unpacked) content size in bytes.
    ///
    /// - For a regular file, the length of the payload before compression.
    /// - For a symlink, the length of the target.
    /// - For a metadata object, zero. The caller fills the size from
    ///   `on_disk_size`.
    ///
    /// This is the `st_size` that the `ostree` command records for the object
    /// in `ostree.sizes`. It goes into the archive size map.
    pub(crate) unpacked: u64,
    /// The flat staging name that the object is linked under, if the object
    /// is newly staged.
    pub(crate) staging_name: String,
    /// The loose path that the object is published to, if the object is newly
    /// staged.
    pub(crate) dest: String,
}

/// Applies the per-mode metadata to a content object and links it under its
/// flat loose name.
///
/// The function runs synchronous syscalls, in this order:
///
/// 1. The metadata that needs write permission on the inode goes on, on the
///    writable descriptor.
/// 2. The function seals the inode per `ctx.verity`.
/// 3. The mode and the owner go on, on the descriptor that is linked. In bare
///    mode the logical xattrs also go on, between the owner and the mode.
/// 4. The per-object sync runs.
/// 5. The function links the inode into the staging directory.
///
/// Until the link, the inode is an anonymous or staging temp, so no reader
/// sees the intermediate mode. Each failure after the dedup check removes a
/// named temp.
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

    let staging_name = flat_name(checksum, ObjectType::File, ctx.mode);
    let stage = |file: std::fs::File| -> Result<u64> {
        // The size does not change with the mode, owner, or xattrs, so one
        // stat gives the create mode and the on-disk size.
        let stat = rustix::fs::fstat(file.as_fd())?;
        apply_content_pre_seal(file.as_fd(), ctx.mode, ctx.verity, stat.st_mode, header)?;
        let on_disk_size = stat.st_size.max(0) as u64;
        // Seal with fs-verity while the inode is still anonymous. Then link
        // it from the descriptor that owns it. With verity off, this is the
        // writable descriptor. With verity on, it is a new read-only reopen
        // after the writable descriptor closes. The mode and the owner, and in
        // bare mode the xattrs, go on after the seal, on the linked
        // descriptor.
        let link_fd = if ctx.verity == Tristate::No {
            OwnedFd::from(file)
        } else {
            let ro = reopen_ro(file.as_fd())?;
            drop(file);
            seal_regular(ro.as_fd(), ctx.verity)?;
            ro
        };
        apply_content_post_seal(link_fd.as_fd(), ctx.mode, header)?;
        if ctx.fsync && ctx.per_object_fsync {
            rustix::fs::fsync(link_fd.as_fd())?;
        }
        materialize(ctx.staging_fd, link_fd.as_fd(), &temp, &staging_name)?;
        Ok(on_disk_size)
    };
    let on_disk_size = stage(file).inspect_err(|_| cleanup_temp(ctx.staging_fd, &temp))?;
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

/// Stages a symlink content object.
///
/// - In `bare` and `bare-user-only`, the object is a symlink.
/// - In `bare-user` and `bare-user-shared`, it is a regular file that holds
///   the target and one NUL.
/// - In archive mode, it is a framed archive header with no payload.
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
            // A concurrent writer of the same symlink can win the race. Its
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
            // A regular file: the content is the target and one NUL, the
            // logical metadata is in user.ostreemeta, and the inode is 0644.
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
            // A framed archive header with no payload.
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
        // The logical (unpacked) size of a symlink object is the length of
        // its target. This is the `st_size` that the `ostree` command records
        // for it in `ostree.sizes`.
        unpacked: target.len() as u64,
        staging_name,
        dest,
    })
}

/// Stages a metadata object.
///
/// The function writes the bytes to a temp file, sets the mode 0644 with
/// `fchmod`, and renames the file to the flat loose name.
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
        // The `syncfs` at the start of publication makes a metadata object
        // durable. The per-object sync covers content objects only. If the
        // transaction ran that `syncfs` before it staged this object, the
        // object is synced here.
        ctx.fsync && ctx.sync_metadata,
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

/// Imports one loose object of another repository into the staging directory.
///
/// The function does not read the payload. It hardlinks the object, so the
/// source inode keeps its mode, ownership, and xattrs. A link is allowed only
/// if the source inode is the inode that a write into this repository makes.
/// This is true in two cases:
///
/// - A content object into a `bare` destination, because the header that the
///   checksum covers sets its uid, gid, permission bits, and xattrs.
/// - A source inode that `fresh_owner` already owns, the uid and gid that a
///   newly staged object here gets.
///
/// In each other mode, the header sets the permission bits and the xattrs, and
/// the writer sets the ownership. The second case checks the ownership.
///
/// # Trust in the source inode
///
/// The gate reads only the ownership of the source inode. It trusts the
/// permission bits and the xattrs to match the header of the object, and does
/// not check them. For a content object outside bare mode, this path does not
/// read the header. So an inode changed out of band carries its state across.
///
/// Attributes that the environment of the destination assigns also carry
/// across, for example a default POSIX ACL on its directories or a security
/// label. A new write inherits the attributes of the destination, and a link
/// keeps the attributes of the source.
///
/// # Link owner
///
/// `link_owner` is the uid and gid that a newly staged object here gets, the
/// pair that the second case compares. If it is `None`, the function makes no
/// link attempt. The caller passes `None` for a forced copy and for a
/// repository that seals its objects. The measure of the pair costs a probe of
/// the staging directory, so the caller measures it only where the gate reads
/// it.
///
/// # Return value
///
/// `Ok(None)` reports a content object that is not staged, for one of these
/// causes:
///
/// - The ownership gate refused the link.
/// - `link_owner` is `None`.
/// - The file system refused the link, for one of these causes:
///   - The two repositories are on different file systems.
///   - The source inode is at its link limit.
///   - The file system has no hardlinks.
///   - The protected-hardlink rules of the kernel apply.
///
/// The caller then imports the object through its logical header, the one
/// path that applies the inode policy of this repository. If a link fails for
/// another cause, for example no space, a quota, or an I/O error, the import
/// fails with that errno. A fallback copy fails the same way and reports a
/// less specific cause, so the function makes no copy.
///
/// A metadata object has no header, so this function serves its refused link.
/// It copies the bytes with a `FICLONE` reflink if the file system supports
/// one, and byte by byte otherwise. The copy gets the metadata-object inode of
/// this repository: 0644, no xattrs, and the ownership of the writing process.
///
/// The caller guarantees that the two repositories store this object
/// identically. Metadata objects do not depend on the mode. A content object
/// comes this way only between repositories that store it the same way.
///
/// # fs-verity
///
/// The function makes a link only if `[ex-integrity] fsverity` is
/// [`Tristate::No`]. The caller states this when it gives no `link_owner`.
/// fs-verity is a property of the inode. So a seal of a hardlinked object also
/// seals the copy in the source repository, and that copy becomes immutable
/// there. An unsealed link breaks the rule of this repository that each object
/// stored as a regular file is sealed. For this reason, a repository that
/// seals its writes copies each object, and seals the copy as it seals each
/// new write.
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
        // The stat of the source decides if the link is allowed. It also gives
        // the size of the staged object, because a hardlink is the inode that
        // it stats.
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
                // A refusal from the file system or the kernel leaves the
                // object unstaged. The causes are the same as in the
                // `# Return value` list of this function. The code after this
                // match copies the object or reports it to the caller. Each
                // other failure belongs to the import and carries its errno
                // out. A copy fails the same way and reports a less specific
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

    // The destination mode decides the inode metadata of a content object. The
    // caller reads the header that this decision uses.
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

/// Imports one regular-file content object between two modes of the bare
/// family.
///
/// Two modes of the bare family store the payload identically and the inode
/// metadata differently. The function clones the payload: a `FICLONE` reflink
/// if the file system supports one, and a byte copy otherwise. It applies the
/// inode policy of the destination from the logical header of the object, so
/// nothing of the source inode carries over.
///
/// The function does not read the payload into memory and does not hash it
/// again. A caller that needs a checksum check reads the object before the
/// call.
pub(crate) fn stage_clone_content_blocking(
    ctx: &StageCtx<'_>,
    src_objects_fd: BorrowedFd<'_>,
    checksum: &Checksum,
    src_mode: RepoMode,
    header: &FileHeader,
    unpacked: u64,
) -> Result<StageOutcome> {
    // An import is a write like any other. A content object that crosses modes
    // comes to this path without `stage_import_blocking`. A bare-split-xattrs
    // destination needs the `.file-xattrs` and `.file-xattrs-link` sidecars,
    // which no import path produces. The refusal comes before the source is
    // opened and its payload cloned.
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
        // If the source object disappeared between the plan and the import,
        // report it as a missing object, as the link path does.
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

/// Moves the bytes of a regular-file object into a new temp file in the
/// staging directory, and applies no metadata.
///
/// The function uses a `FICLONE` reflink if the file system supports one, and
/// a byte copy otherwise. It returns the open temp file, the handle that the
/// file is linked under, and the method that moved the bytes. If the copy
/// fails, it removes the temp file.
///
/// The byte copy is `std::io::copy`. On Linux, a `File` to `File` transfer
/// uses `copy_file_range` and moves the payload in the kernel. If the kernel
/// refuses that, the copy uses a fixed stack buffer.
///
/// In both cases the payload is never buffered, whatever its size. A file
/// system without reflink still gets a copy in the kernel. The cost is that
/// the transfer holds one thread of the blocking pool until it ends, and it
/// cannot be cancelled. If the future that awaits it is dropped, the copy runs
/// to completion and writes into a staging temp that the reaper collects.
fn clone_payload(
    staging_fd: BorrowedFd<'_>,
    src: BorrowedFd<'_>,
) -> Result<(std::fs::File, TempKind, Blocks)> {
    let (fd, temp) = open_temp(staging_fd)?;
    let mut dst = std::fs::File::from(fd);
    // A reflink shares the source extents fully. If the reflink is refused
    // (a file system without reflink, a source on another file system), it
    // writes nothing. So the byte copy starts from an empty file.
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

/// Copies one loose metadata object into the staging directory under
/// `staging_name`.
///
/// The bytes move by `FICLONE` reflink if the file system supports it, and
/// byte by byte otherwise. The copy gets the inode of a metadata object that
/// this repository writes, in each mode. That inode has the mode 0644, no
/// xattrs, and the uid and gid of the writing process. The staging temp file has this uid and
/// gid by construction. The function returns the size on disk and the method
/// that moved the bytes.
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
        // The `syncfs` at the start of publication makes a metadata object
        // durable. The per-object sync covers content objects only.
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

/// Publishes staged objects into `objects/` in the order of the durability
/// rules.
///
/// 1. If `syncfs` is set, the function runs `syncfs` on the repository.
/// 2. It renames each object into `objects/<xx>/`.
/// 3. If `fsync` is set, it runs `fsync` on each fanout directory that it
///    changed, and on `objects/`.
///
/// A caller clears `syncfs` with fsync on only if a `syncfs` after the staging
/// of the last object already made the objects durable.
pub(crate) fn publish_blocking(
    repo_fd: BorrowedFd<'_>,
    objects_fd: BorrowedFd<'_>,
    staging_fd: BorrowedFd<'_>,
    objects: &[(String, String)],
    syncfs: bool,
    fsync: bool,
    repo_mode: RepoMode,
) -> Result<()> {
    if syncfs {
        rustix::fs::syncfs(repo_fd)?;
    }
    let mut fanouts: Vec<String> = Vec::new();
    for (staging_name, dest) in objects {
        let fanout = &dest[..2];
        ensure_fanout(objects_fd, fanout, repo_mode)?;
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

/// Creates the fanout directory `objects/<xx>/` if it does not exist.
///
/// If a race created the directory first, the function ignores the race. The
/// requested mode is `0777`, reduced by the umask. In a `bare-user-shared`
/// repository, a fanout that this call creates then gets
/// [`perm::SHARED_DIR_MODE`]. So each member of the repository group can add
/// an object to it. A fanout that exists keeps its mode and its group.
fn ensure_fanout(objects_fd: BorrowedFd<'_>, fanout: &str, repo_mode: RepoMode) -> Result<()> {
    match rustix::fs::mkdirat(objects_fd, fanout, Mode::from_raw_mode(0o777)) {
        Ok(()) => Ok(perm::force_created_dir(objects_fd, fanout, repo_mode)?),
        Err(rustix::io::Errno::EXIST) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Returns a [`StageOutcome`] for an object that `objects/` already holds.
fn dedup(dest: String) -> StageOutcome {
    StageOutcome {
        deduped: true,
        on_disk_size: 0,
        // Nothing was staged, so nothing moved bytes. The record path returns
        // on `deduped` before it reads either field.
        blocks: Blocks::Written,
        unpacked: 0,
        staging_name: String::new(),
        dest,
    }
}

/// Returns the flat staging name of an object: its full hex checksum and the
/// loose extension.
///
/// The name holds the whole object in one entry of the staging directory.
pub(crate) fn flat_name(checksum: &Checksum, ty: ObjectType, mode: RepoMode) -> String {
    format!("{}.{}", checksum.to_hex(), ty.extension(mode))
}

/// Applies the inode metadata of a regular-file content object that needs
/// write permission on the inode.
///
/// The function runs on the writable descriptor, before the seal.
/// `FS_IOC_ENABLE_VERITY` and a `user.*` xattr both need write permission on
/// the inode. `create_mode` is the inode mode of the temp file.
///
/// In the modes that store the logical mode (`bare`, `bare-user`,
/// `bare-user-only`), the function can first set the inode to 0600. It does so
/// if `verity` is on and `create_mode` has no owner read or no owner write.
/// Then a umask without owner write does not block the seal, the reopen, or
/// the xattrs. [`apply_content_post_seal`] sets the final mode, and in bare mode
/// the xattrs.
fn apply_content_pre_seal(
    fd: BorrowedFd<'_>,
    mode: RepoMode,
    verity: Tristate,
    create_mode: u32,
    header: &FileHeader,
) -> Result<()> {
    if verity != Tristate::No
        && create_mode & 0o600 != 0o600
        && matches!(
            mode,
            RepoMode::Bare | RepoMode::BareUser | RepoMode::BareUserOnly
        )
    {
        // Owner write for the seal and the xattrs, owner read for the
        // read-only reopen. In bare mode the xattrs go on after the seal.
        rustix::fs::fchmod(fd, Mode::from_raw_mode(0o600))?;
    }
    match mode {
        RepoMode::Bare => {}
        RepoMode::BareUser => {
            // The xattr goes on before the mode. The kernel checks a `user.*`
            // xattr against the write permission of the inode. The canonical
            // inode mode of this repository mode has no owner-write bit if the
            // logical mode has none (0444, 0555).
            set_ostreemeta(fd, header)?;
        }
        RepoMode::BareUserShared => {
            rustix::fs::fchmod(fd, Mode::from_raw_mode(FIXED_MODE))?;
            set_ostreemeta(fd, header)?;
        }
        RepoMode::BareUserOnly => {}
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

/// Applies the inode mode and the owner of a regular-file content object after
/// the seal.
///
/// In bare mode, the function also applies the logical xattrs. It runs on the
/// descriptor that is linked, which is the read-only descriptor if verity is
/// on. The kernel checks the inode owner for `fchmod` and `fchown`, and the
/// inode permission for an xattr. It does not check the access mode of the
/// descriptor. A sealed inode accepts xattr changes.
fn apply_content_post_seal(fd: BorrowedFd<'_>, mode: RepoMode, header: &FileHeader) -> Result<()> {
    let perm = header.mode & PERM_MASK;
    match mode {
        RepoMode::Bare => {
            // The owner goes on first. A chown of a regular file removes
            // `security.capability` and clears the set-user-ID bit, also if
            // the ids do not change. If group execute is set, it also clears
            // the set-group-ID bit. The xattrs go on before the mode. The
            // kernel checks a `user.*` xattr against the write permission of
            // the inode. A logical mode without an owner-write bit (0444,
            // 0555) does not give that permission.
            rustix::fs::fchown(fd, Some(uid(header.uid)), Some(gid(header.gid)))?;
            for (name, value) in header.xattrs.iter() {
                set_inode_xattr(fd, name, value)?;
            }
            rustix::fs::fchmod(fd, Mode::from_raw_mode(perm))?;
        }
        RepoMode::BareUser => {
            rustix::fs::fchmod(fd, Mode::from_raw_mode((perm & 0o775) | 0o400))?;
        }
        RepoMode::BareUserOnly => {
            // Canonical mode: the owner bits stay, and the group-write and
            // other-write bits are removed. Observed on the objects that the
            // `ostree` command writes.
            rustix::fs::fchmod(fd, Mode::from_raw_mode(perm & 0o755))?;
        }
        RepoMode::BareUserShared | RepoMode::Archive => {}
        RepoMode::BareSplitXattrs => {
            return Err(Error::Unsupported(
                "bare-split-xattrs is read-only; the port does not write it".into(),
            ));
        }
    }
    Ok(())
}

/// Writes the `user.ostreemeta` xattr that holds the logical `(uuua(ayay))`.
fn set_ostreemeta(fd: BorrowedFd<'_>, header: &FileHeader) -> Result<()> {
    let meta = header.serialize_stat_metadata()?;
    rustix::fs::fsetxattr(fd, "user.ostreemeta", &meta, XattrFlags::empty())?;
    Ok(())
}

/// Sets one inode xattr, without the terminating NUL of the stored name.
///
/// The checkout copy path also uses this function, to apply the logical xattrs
/// of a file object.
pub(crate) fn set_inode_xattr(fd: BorrowedFd<'_>, name: &[u8], value: &[u8]) -> Result<()> {
    let name = name.strip_suffix(&[0]).unwrap_or(name);
    let name = std::str::from_utf8(name)
        .map_err(|_| Error::InvalidFormat("xattr name is not valid UTF-8".into()))?;
    rustix::fs::fsetxattr(fd, name, value, XattrFlags::empty())?;
    Ok(())
}

/// Sets one xattr on a staged symlink inode, without the terminating NUL of
/// the stored name.
///
/// A symlink cannot be opened for a descriptor. The function sets the
/// attribute with no-follow, through the `/proc/self/fd` path of the
/// directory. The checkout path also uses this function, to apply the link
/// xattrs of a symlink object.
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

/// Writes `content` into a new named temp file and renames it to
/// `staging_name`.
///
/// Before the rename, the function does these steps:
///
/// 1. It sets the mode `perm` with `fchmod`.
/// 2. If `ostreemeta` is given, it sets `user.ostreemeta`.
/// 3. If `do_fsync` is set, it runs `fsync` on the file.
/// 4. It seals the file with fs-verity per `verity`.
///
/// The function returns the size on disk. It is for small bodies that the
/// caller holds: symlinks stored as regular files, and metadata objects.
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
    // Seal with fs-verity before the rename, after the writable descriptor
    // closes. On a failure, remove the named temp so that nothing stays
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

/// Reopens an open file read-only through `/proc/self/fd`.
///
/// Then the writable descriptor to the same inode can close before
/// `FS_IOC_ENABLE_VERITY`. The kernel refuses that ioctl while a writable
/// descriptor to the inode is open. The reopened descriptor also links an
/// anonymous `O_TMPFILE` inode into place.
fn reopen_ro(fd: BorrowedFd<'_>) -> Result<OwnedFd> {
    let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    Ok(rustix::fs::open(
        proc_path.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Enables fs-verity on a read-only descriptor per the configured tri-state.
///
/// [`Tristate::Maybe`] is best effort and ignores each enable error. A file
/// system without verity returns `ENOTTY`. With [`Tristate::Yes`], an enable
/// error fails the write. The function is never called for [`Tristate::No`].
/// It tries again after an `ETXTBSY` error, up to [`SEAL_ATTEMPTS`] attempts
/// with a pause of [`SEAL_PAUSE`].
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

/// Links an ingestion temp file into the staging directory under
/// `staging_name`.
///
/// For an anonymous inode, the function links it through `link_fd`. For a
/// named temp, it renames the temp and does not use `link_fd`.
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
                // A concurrent writer of the same object linked it first. The
                // bytes are the same, so treat it as staged.
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

/// Creates a symlink object in the staging directory.
///
/// The function returns `true` if it created the symlink. An existing entry
/// comes from a concurrent writer of the same symlink. The content is the
/// same, so the entry is not an error.
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

/// Removes an ingestion temp file after a dedup hit, or a temp file abandoned
/// before staging.
///
/// An anonymous inode goes away when its descriptor closes. The function
/// unlinks a named temp.
fn cleanup_temp(staging_fd: BorrowedFd<'_>, temp: &TempKind) {
    if let TempKind::Named(name) = temp {
        let _ = rustix::fs::unlinkat(staging_fd, name.as_str(), AtFlags::empty());
    }
}

/// Returns the size on disk of an open file.
fn size_of(fd: BorrowedFd<'_>) -> Result<u64> {
    Ok(rustix::fs::fstat(fd)?.st_size.max(0) as u64)
}

fn uid(value: u32) -> Uid {
    Uid::from_raw(value)
}

fn gid(value: u32) -> Gid {
    Gid::from_raw(value)
}

/// The write-side sink into which an archive pass-through inflates its
/// payload.
///
/// The sink hashes and counts the inflated bytes, and stores none of them.
/// When the count passes `declared`, the sink refuses more bytes. This limit
/// stops a payload that inflates past its declared size before it does
/// unbounded work. [`write_archive_payload`](Transaction::write_archive_payload)
/// then checks the final count against `declared`.
struct InflatedDigest {
    hasher: ContentHasher,
    checksum: Checksum,
    declared: u64,
    seen: u64,
}

impl InflatedDigest {
    fn new(header: &FileHeader, checksum: Checksum, declared: u64) -> Result<InflatedDigest> {
        Ok(InflatedDigest {
            hasher: ContentHasher::new(header)?,
            checksum,
            declared,
            seen: 0,
        })
    }
}

impl AsyncWrite for InflatedDigest {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        me.seen += buf.len() as u64;
        if me.seen > me.declared {
            return Poll::Ready(Err(io::Error::other(Error::InvalidFormat(format!(
                "content object {}: the payload outgrew the {} byte(s) its header declares",
                me.checksum, me.declared
            )))));
        }
        me.hasher.update(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
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

/// Writes as much of `buf` into `w` as `w` accepts, and stops at the first
/// short write.
///
/// The function does not retry the rest. For the inflating decoder under
/// [`write_archive_payload`](Transaction::write_archive_payload), a short
/// write means that its DEFLATE stream ended in this call. A retry of the rest
/// asks a finished decoder for more bytes. The decoder refuses with a hard
/// error of its own, where many `AsyncWrite` implementations return `Ok(0)`
/// for a write after close.
///
/// That error after a short write is expected. The function counts it as part
/// of the short write, and does not return it. The caller compares the `Ok`
/// value with `buf.len()` to find out if bytes stayed unconsumed.
///
/// An error on the first attempt for `buf`, before any byte of this call is
/// written, is a different case. The inflating sink under
/// [`write_archive_payload`](Transaction::write_archive_payload) fails when it
/// forwards bytes that it buffers. This can occur long after the chunk that
/// overran it, so this error can be the first sign of the failure. The
/// function returns that error, so its own message reaches the caller. A
/// generic "trailing bytes" message does not replace it.
async fn write_up_to<W: AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) -> io::Result<usize> {
    let mut written = 0;
    while written < buf.len() {
        match poll_fn(|cx| Pin::new(&mut *w).poll_write(cx, &buf[written..])).await {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(e) if written == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(written)
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

/// Streams `reader` into `writer` in bounded chunks, and buffers no whole
/// blob.
///
/// The chunk size is [`COPY_CHUNK`]. The checkout copy path also uses this
/// function, to stream the payload of a file object into a destination temp
/// file.
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

/// A compile-time check that `ContentWriter` and `FileMeta` are `Send + Sync`.
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

    /// The fs-verity digest that the kernel measures for a written content
    /// object equals the digest of ostrya's `FsVerityHasher` over the same
    /// payload.
    ///
    /// The test checks the digest parameters that the two share: SHA-256,
    /// 4096-byte blocks, and zero salt. A bare-user-shared `.file` stores the
    /// raw payload on disk, so the digest of the object is the digest of the
    /// payload bytes. If the file system does not support fs-verity, the test
    /// skips the check.
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
        // A payload of several verity blocks (> 4096 bytes).
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
                // A file system without fs-verity sealed nothing to measure.
                Err(_) => eprintln!("skipping digest check: filesystem lacks fs-verity"),
            }
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod temp_tests {
    use std::os::fd::{AsFd, OwnedFd};

    use super::{PendingTemp, TempKind, unique};

    /// A drop unlinks a named temp that is not staged, and a temp handed on
    /// for staging stays for the stager.
    ///
    /// Each file system that the tests run on supports `O_TMPFILE`, so the
    /// test makes the named form by hand.
    #[test]
    fn a_pending_named_temp_is_removed_on_drop() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-pending-temp-{}-{}",
            std::process::id(),
            unique()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_fd: OwnedFd = std::fs::File::open(&dir).unwrap().into();
        for name in [".ostrya-tmp-dropped", ".ostrya-tmp-kept"] {
            std::fs::write(dir.join(name), b"partial").unwrap();
        }

        drop(PendingTemp::new(
            dir_fd.as_fd(),
            TempKind::Named(".ostrya-tmp-dropped".to_owned()),
        ));
        assert!(!dir.join(".ostrya-tmp-dropped").exists());

        let kept = PendingTemp::new(
            dir_fd.as_fd(),
            TempKind::Named(".ostrya-tmp-kept".to_owned()),
        );
        assert!(matches!(kept.into_inner(), TempKind::Named(_)));
        assert!(dir.join(".ostrya-tmp-kept").exists());

        // An anonymous temp names nothing, so its drop unlinks nothing.
        drop(PendingTemp::new(dir_fd.as_fd(), TempKind::Anonymous));
        assert!(dir.join(".ostrya-tmp-kept").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
