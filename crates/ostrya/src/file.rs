//! The file content reading path.
//!
//! [`Repo::load_file`] reconstructs a file object's logical metadata (uid, gid,
//! mode, xattrs) and kind (regular file or symlink) from however the repository
//! mode stores it, and yields a [`FileObject`]. Its [`reader`](FileObject::reader)
//! streams a regular file's payload in bounded chunks; the payload is never
//! buffered whole. How metadata and payload are stored varies by mode:
//!
//! - archive: a framed `(tuuuusa(ayay))` header prefixes a raw-DEFLATE payload
//!   inside the `.filez` object.
//! - bare: the object is a real inode; metadata comes from `stat` and the
//!   inode's xattrs, and a symlink is a real symlink.
//! - bare-user: the object is a regular file; metadata lives in the
//!   `user.ostreemeta` xattr `(uuua(ayay))`, and a symlink is stored as a
//!   regular file whose content is the target followed by a NUL.
//! - bare-user-only: metadata is the canonical inode mode with uid/gid read
//!   back as 0 and no xattrs; a symlink is a real symlink.
//! - bare-user-shared: identical to bare-user on the read path; the fixed
//!   inode mode a writer applies is never consulted, so the same loader serves
//!   both modes.
//! - bare-split-xattrs: bare inode storage (real uid/gid/mode, real symlinks,
//!   no `user.ostreemeta`); the logical xattrs live in a separate `.file-xattrs`
//!   object reached through the `.file-xattrs-link` entry keyed by the file
//!   checksum.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ostrya_core::{Checksum, FileHeader, ObjectType, RepoMode, Xattrs, loose_path};
use ostrya_rt::File as RtFile;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::inflate::{ArchiveDecoder, archive_decoder};
use crate::object::{self, MAX_FILE_HEADER_SIZE, MAX_METADATA_SIZE};
use crate::repo::Repo;
use crate::write::FileMeta;

/// The largest bare-user symlink target the reader will load. Targets are
/// paths, comfortably under this bound.
const SYMLINK_READ_CAP: u64 = 64 * 1024;

/// Whether a file object is a regular file or a symlink, with the size or
/// target that distinguishes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileKind {
    /// A regular file of the given uncompressed payload size.
    Regular {
        /// The uncompressed payload size in bytes.
        size: u64,
    },
    /// A symbolic link to `target`.
    Symlink {
        /// The link target.
        target: String,
    },
}

/// How a file object's payload is reached, retained so [`FileObject::reader`]
/// can open a fresh stream on demand. The object path is derived from the
/// checksum at read time.
#[derive(Debug, Clone)]
enum ReaderSource {
    /// No streamable payload (a symlink).
    None,
    /// The whole object file is the raw payload.
    Plain,
    /// A `.filez` object: raw-DEFLATE payload after `payload_offset` bytes.
    Archive { payload_offset: u64 },
}

/// Where a file object's bytes live, so [`FileObject::reader`] can open a fresh
/// stream on demand from either the repository's `objects/` or a transaction's
/// staging directory.
#[derive(Debug, Clone)]
enum ObjectStore {
    /// A loose object under the repository's `objects/` directory; the path is
    /// derived from the checksum and mode at read time.
    Repo,
    /// A flat-named object in a transaction staging directory, not yet
    /// published. The directory fd is `Arc`-shared so the object stays `Clone`
    /// and self-contained.
    Staging {
        /// The staging directory the object is ingested into.
        dir: Arc<OwnedFd>,
        /// The object's flat staging name (`<hex>.file` / `<hex>.filez`).
        name: String,
    },
}

/// A file object's logical metadata plus a handle for streaming its payload.
#[derive(Debug, Clone)]
pub struct FileObject {
    repo: Repo,
    checksum: Checksum,
    /// The owning user id.
    pub uid: u32,
    /// The owning group id.
    pub gid: u32,
    /// The full logical `st_mode`.
    pub mode: u32,
    /// The file's extended attributes.
    pub xattrs: Xattrs,
    /// Whether this is a regular file or a symlink.
    pub kind: FileKind,
    source: ReaderSource,
    store: ObjectStore,
}

impl FileObject {
    /// The object identity of this file.
    pub fn checksum(&self) -> &Checksum {
        &self.checksum
    }

    /// Whether the object is a symlink.
    pub fn is_symlink(&self) -> bool {
        matches!(self.kind, FileKind::Symlink { .. })
    }

    /// The object's logical header: the form its checksum covers, which is what
    /// the identity is recomputed from and what the mode checks read.
    pub fn header(&self) -> FileHeader {
        FileHeader {
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
            symlink_target: match &self.kind {
                FileKind::Symlink { target } => target.clone(),
                FileKind::Regular { .. } => String::new(),
            },
            xattrs: self.xattrs.clone(),
        }
    }

    /// The object's logical metadata: the uid, gid, mode, and xattrs a write of
    /// this object applies, and what the mode checks read.
    pub(crate) fn meta(&self) -> FileMeta {
        FileMeta {
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
            xattrs: self.xattrs.clone(),
        }
    }

    /// Open an async reader over the file's payload, streaming it in bounded
    /// chunks. A symlink has no payload, so its reader yields no bytes.
    pub async fn reader(&self) -> Result<ContentReader> {
        let inner = match &self.source {
            ReaderSource::None => ContentReaderInner::Empty,
            ReaderSource::Plain => ContentReaderInner::Plain(self.open_payload(0).await?),
            ReaderSource::Archive { payload_offset } => {
                let file = self.open_payload(*payload_offset).await?;
                ContentReaderInner::Inflate(archive_decoder(file))
            }
        };
        Ok(ContentReader { inner })
    }

    /// Stream the file's payload into `writer` in bounded chunks, buffering no
    /// whole blob whatever the file's size. A symlink has no payload and
    /// writes nothing.
    ///
    /// The writer is left unflushed. A sink takes as many payloads as its owner
    /// sends it, and a framing or compressing sink emits on a flush, so the
    /// flush belongs to the caller: one whose writer buffers -- the async file
    /// over a descriptor does -- settles it once when it has written everything.
    pub async fn write_to<W: futures_io::AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let reader = self.reader().await?;
        crate::write::copy_stream(reader, writer)
            .await
            .map_err(Error::Io)
    }

    /// The directory fd and path the payload is read from: a loose path under
    /// `objects/`, or the flat staging name for a not-yet-published object.
    fn payload_location(&self) -> Result<(OwnedFd, String)> {
        match &self.store {
            ObjectStore::Repo => {
                let path = loose_path(&self.checksum, ObjectType::File, self.repo.mode());
                Ok((self.repo.objects_fd().try_clone_to_owned()?, path))
            }
            ObjectStore::Staging { dir, name } => {
                Ok((dir.as_fd().try_clone_to_owned()?, name.clone()))
            }
        }
    }

    /// Open the object file positioned past `payload_offset` bytes, off the
    /// blocking pool.
    async fn open_payload(&self, payload_offset: u64) -> Result<RtFile> {
        let (dir, path) = self.payload_location()?;
        let file = ostrya_rt::unblock(move || {
            object::open_content_file(dir.as_fd(), &path, payload_offset)
        })
        .await
        .map_err(Error::Io)?;
        Ok(RtFile::from(file))
    }
}

impl Repo {
    /// Load a committed file object: its logical metadata and a handle to
    /// stream its payload. The interpretation follows the repository mode.
    pub async fn load_file(&self, checksum: &Checksum) -> Result<FileObject> {
        let mode = self.mode();
        let path = loose_path(checksum, ObjectType::File, mode);
        let repo = self.clone();
        let key = *checksum;
        let loaded =
            ostrya_rt::unblock(move || load_by_mode(repo.objects_fd(), &path, &key, mode)).await?;
        Ok(FileObject {
            repo: self.clone(),
            checksum: *checksum,
            uid: loaded.uid,
            gid: loaded.gid,
            mode: loaded.mode,
            xattrs: loaded.xattrs,
            kind: loaded.kind,
            source: loaded.source,
            store: ObjectStore::Repo,
        })
    }
}

/// Load a file object from a transaction staging directory by its flat name,
/// used for the staged-first lookup that reads objects staged in the current
/// transaction before they publish into `objects/`. The metadata is decoded the
/// same per-mode way as a loose object; the payload streams from the staging
/// directory.
pub(crate) async fn load_staged_file(
    repo: &Repo,
    staging_fd: BorrowedFd<'_>,
    checksum: &Checksum,
) -> Result<FileObject> {
    let mode = repo.mode();
    let name = crate::write::flat_name(checksum, ObjectType::File, mode);
    let dir = Arc::new(staging_fd.try_clone_to_owned()?);
    let key = *checksum;
    let load_dir = dir.clone();
    let load_name = name.clone();
    let loaded =
        ostrya_rt::unblock(move || load_by_mode(load_dir.as_fd(), &load_name, &key, mode)).await?;
    Ok(FileObject {
        repo: repo.clone(),
        checksum: *checksum,
        uid: loaded.uid,
        gid: loaded.gid,
        mode: loaded.mode,
        xattrs: loaded.xattrs,
        kind: loaded.kind,
        source: loaded.source,
        store: ObjectStore::Staging { dir, name },
    })
}

/// The fields a per-mode loader produces before a [`FileObject`] is assembled.
struct Loaded {
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: Xattrs,
    kind: FileKind,
    source: ReaderSource,
}

/// Dispatch to the loader for the repository mode. `object_path` locates the
/// object relative to `dir_fd`: a loose path under `objects/`, or a flat name in
/// a staging directory.
fn load_by_mode(
    dir_fd: BorrowedFd<'_>,
    object_path: &str,
    checksum: &Checksum,
    mode: RepoMode,
) -> Result<Loaded> {
    match mode {
        RepoMode::Archive => load_archive(dir_fd, object_path, checksum),
        RepoMode::BareUser | RepoMode::BareUserShared => {
            load_bare_user(dir_fd, object_path, checksum)
        }
        RepoMode::Bare => load_bare(dir_fd, object_path, checksum),
        RepoMode::BareUserOnly => load_bare_user_only(dir_fd, object_path, checksum),
        RepoMode::BareSplitXattrs => load_bare_split_xattrs(dir_fd, object_path, checksum),
    }
}

/// Map a syscall error into `ObjectNotFound` for a missing object, else I/O.
fn map_object_error(err: Errno, checksum: &Checksum, ty: ObjectType) -> Error {
    if err == Errno::NOENT {
        Error::ObjectNotFound {
            checksum: *checksum,
            ty,
        }
    } else {
        Error::Io(err.into())
    }
}

/// Open a loose object fd, mapping a missing object to `ObjectNotFound`.
fn open_object(objects_fd: BorrowedFd<'_>, path: &str, checksum: &Checksum) -> Result<OwnedFd> {
    rustix::fs::openat(
        objects_fd,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| map_object_error(e, checksum, ObjectType::File))
}

/// `statat` a loose object without following symlinks, mapping a missing object
/// to `ObjectNotFound`.
fn stat_object(
    objects_fd: BorrowedFd<'_>,
    path: &str,
    checksum: &Checksum,
    ty: ObjectType,
) -> Result<Stat> {
    rustix::fs::statat(objects_fd, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| map_object_error(e, checksum, ty))
}

/// Read the target of a symlink object.
fn read_link_target(objects_fd: BorrowedFd<'_>, path: &str) -> Result<String> {
    let link = rustix::fs::readlinkat(objects_fd, path, Vec::new())?;
    link.into_string()
        .map_err(|_| Error::InvalidFormat("symlink target is not valid UTF-8".into()))
}

/// Recover a bare-user symlink target from its object content, which is the
/// target followed by a single NUL.
fn symlink_target_from_content(content: &[u8]) -> Result<String> {
    let bytes = content.strip_suffix(&[0]).unwrap_or(content);
    if bytes.contains(&0) {
        return Err(Error::InvalidFormat(
            "symlink target has an interior NUL".into(),
        ));
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| Error::InvalidFormat("symlink target is not valid UTF-8".into()))
}

fn load_archive(dir_fd: BorrowedFd<'_>, path: &str, checksum: &Checksum) -> Result<Loaded> {
    use std::io::Read;

    let fd = open_object(dir_fd, path, checksum)?;
    let mut file = std::fs::File::from(fd);

    let mut prefix = [0u8; 8];
    file.read_exact(&mut prefix)?;
    if prefix[4..8] != [0u8; 4] {
        return Err(Error::InvalidFormat(
            "content framing padding is not zero".into(),
        ));
    }
    let header_len = u32::from_be_bytes(prefix[..4].try_into().unwrap()) as u64;
    if header_len > MAX_FILE_HEADER_SIZE {
        return Err(Error::InvalidFormat(
            "content header exceeds the size cap".into(),
        ));
    }
    let mut header_bytes = vec![0u8; header_len as usize];
    file.read_exact(&mut header_bytes)?;
    let (header, uncompressed_size) = FileHeader::parse_archive(&header_bytes)?;

    let (kind, source) = if header.is_symlink() {
        (
            FileKind::Symlink {
                target: header.symlink_target,
            },
            ReaderSource::None,
        )
    } else {
        (
            FileKind::Regular {
                size: uncompressed_size,
            },
            ReaderSource::Archive {
                payload_offset: 8 + header_len,
            },
        )
    };
    Ok(Loaded {
        uid: header.uid,
        gid: header.gid,
        mode: header.mode,
        xattrs: header.xattrs,
        kind,
        source,
    })
}

fn load_bare_user(dir_fd: BorrowedFd<'_>, path: &str, checksum: &Checksum) -> Result<Loaded> {
    use std::io::Read;

    let fd = open_object(dir_fd, path, checksum)?;
    let meta = object::read_xattr(fd.as_fd(), "user.ostreemeta")
        .map_err(Error::Io)?
        .ok_or_else(|| {
            Error::InvalidFormat("bare-user .file is missing its user.ostreemeta xattr".into())
        })?;
    let header = FileHeader::parse_stat_metadata(&meta)?;
    let stat = rustix::fs::fstat(&fd)?;

    let (kind, source) = if header.is_symlink() {
        let mut content = Vec::new();
        std::fs::File::from(fd)
            .take(SYMLINK_READ_CAP)
            .read_to_end(&mut content)?;
        (
            FileKind::Symlink {
                target: symlink_target_from_content(&content)?,
            },
            ReaderSource::None,
        )
    } else {
        (
            FileKind::Regular {
                size: stat.st_size.max(0) as u64,
            },
            ReaderSource::Plain,
        )
    };
    Ok(Loaded {
        uid: header.uid,
        gid: header.gid,
        mode: header.mode,
        xattrs: header.xattrs,
        kind,
        source,
    })
}

fn load_bare(dir_fd: BorrowedFd<'_>, path: &str, checksum: &Checksum) -> Result<Loaded> {
    let stat = stat_object(dir_fd, path, checksum, ObjectType::File)?;
    let uid = stat.st_uid;
    let gid = stat.st_gid;
    let mode = stat.st_mode;

    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Symlink => Ok(Loaded {
            uid,
            gid,
            mode,
            xattrs: object::read_link_xattrs(dir_fd, path)?,
            kind: FileKind::Symlink {
                target: read_link_target(dir_fd, path)?,
            },
            source: ReaderSource::None,
        }),
        FileType::RegularFile => {
            let fd = rustix::fs::openat(
                dir_fd,
                path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| map_object_error(e, checksum, ObjectType::File))?;
            let xattrs = object::read_all_xattrs(fd.as_fd())?;
            Ok(Loaded {
                uid,
                gid,
                mode,
                xattrs,
                kind: FileKind::Regular {
                    size: stat.st_size.max(0) as u64,
                },
                source: ReaderSource::Plain,
            })
        }
        _ => Err(Error::InvalidFormat(
            "bare object is neither a regular file nor a symlink".into(),
        )),
    }
}

fn load_bare_user_only(dir_fd: BorrowedFd<'_>, path: &str, checksum: &Checksum) -> Result<Loaded> {
    let stat = stat_object(dir_fd, path, checksum, ObjectType::File)?;
    // uid/gid are discarded in this mode and read back as 0; the mode is the
    // canonical mode carried on the inode; no xattrs are stored.
    let mode = stat.st_mode;
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Symlink => Ok(Loaded {
            uid: 0,
            gid: 0,
            mode,
            xattrs: Xattrs::empty(),
            kind: FileKind::Symlink {
                target: read_link_target(dir_fd, path)?,
            },
            source: ReaderSource::None,
        }),
        FileType::RegularFile => Ok(Loaded {
            uid: 0,
            gid: 0,
            mode,
            xattrs: Xattrs::empty(),
            kind: FileKind::Regular {
                size: stat.st_size.max(0) as u64,
            },
            source: ReaderSource::Plain,
        }),
        _ => Err(Error::InvalidFormat(
            "bare-user-only object is neither a regular file nor a symlink".into(),
        )),
    }
}

fn load_bare_split_xattrs(
    dir_fd: BorrowedFd<'_>,
    path: &str,
    checksum: &Checksum,
) -> Result<Loaded> {
    // Storage is bare: the inode carries the logical uid/gid/mode, a regular
    // file holds the raw payload, and a symlink is a real symlink. The inode
    // holds no xattrs; the logical set lives in a separate object reached
    // through the `.file-xattrs-link` entry keyed by the file checksum.
    // bare-split-xattrs is read-only and never staged, so `dir_fd` is always the
    // repository's `objects/`; the split-xattrs link is resolved by its own
    // loose path from the checksum.
    let stat = stat_object(dir_fd, path, checksum, ObjectType::File)?;
    let uid = stat.st_uid;
    let gid = stat.st_gid;
    let mode = stat.st_mode;
    let xattrs = load_split_xattrs(dir_fd, checksum)?;

    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Symlink => Ok(Loaded {
            uid,
            gid,
            mode,
            xattrs,
            kind: FileKind::Symlink {
                target: read_link_target(dir_fd, path)?,
            },
            source: ReaderSource::None,
        }),
        FileType::RegularFile => Ok(Loaded {
            uid,
            gid,
            mode,
            xattrs,
            kind: FileKind::Regular {
                size: stat.st_size.max(0) as u64,
            },
            source: ReaderSource::Plain,
        }),
        _ => Err(Error::InvalidFormat(
            "bare-split-xattrs object is neither a regular file nor a symlink".into(),
        )),
    }
}

/// Read a file object's logical xattrs from its `.file-xattrs-link` object,
/// whose bytes are the GVariant `a(ayay)` xattr set. The link is a hardlink to
/// the shared `.file-xattrs` object; reading the bytes at the link name needs
/// no knowledge of the hardlink topology. Every file object carries a link
/// (a file with no xattrs points at the shared empty-set object), so its
/// absence is a malformed repository.
fn load_split_xattrs(objects_fd: BorrowedFd<'_>, checksum: &Checksum) -> Result<Xattrs> {
    let path = loose_path(
        checksum,
        ObjectType::FileXattrsLink,
        RepoMode::BareSplitXattrs,
    );
    let bytes = object::read_meta_object(objects_fd, &path, MAX_METADATA_SIZE).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::InvalidFormat("bare-split-xattrs .file is missing its .file-xattrs-link".into())
        } else {
            Error::Io(e)
        }
    })?;
    Ok(Xattrs::from_gvariant(&bytes)?)
}

/// An async reader over a file object's payload.
///
/// Regular files stream from the object store through `rt::File` (raw for the
/// bare family, on-the-fly raw-DEFLATE for archive), so no whole blob is
/// buffered. A symlink has no payload and reads as empty. The reader
/// implements `futures_io::AsyncRead` unconditionally and `tokio::io::AsyncRead`
/// under the `tokio` feature, so neither backend needs a caller-side adapter.
pub struct ContentReader {
    inner: ContentReaderInner,
}

enum ContentReaderInner {
    Empty,
    Plain(RtFile),
    Inflate(ArchiveDecoder),
}

impl ContentReader {
    /// The shared read step both trait families drive. `rt::File` and the
    /// archive decoder present `futures_io::AsyncRead` under either backend.
    fn poll_read_bytes(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
        use futures_io::AsyncRead;
        match &mut self.inner {
            ContentReaderInner::Empty => Poll::Ready(Ok(0)),
            ContentReaderInner::Plain(inner) => Pin::new(inner).poll_read(cx, out),
            ContentReaderInner::Inflate(inner) => Pin::new(inner).poll_read(cx, out),
        }
    }
}

impl futures_io::AsyncRead for ContentReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_read_bytes(cx, buf)
    }
}

#[cfg(feature = "tokio")]
impl ostrya_rt::tokio_io::AsyncRead for ContentReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ostrya_rt::tokio_io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let out = buf.initialize_unfilled();
        match self.get_mut().poll_read_bytes(cx, out) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// `FileObject` and its content reader move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FileObject>();
    assert_send_sync::<ContentReader>();
};

/// Under the `tokio` feature the content reader also speaks the tokio I/O
/// traits, so a tokio-native caller needs no adapter.
#[cfg(feature = "tokio")]
const _: fn() = || {
    fn assert_tokio_read<T: ostrya_rt::tokio_io::AsyncRead>() {}
    assert_tokio_read::<ContentReader>();
};
