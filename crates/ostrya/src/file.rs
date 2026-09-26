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
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Statx, StatxAttributes, StatxFlags};
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
    /// The fs-verity digest the kernel held for the payload at load time. A
    /// load that does not ask for it leaves `None`.
    kernel_verity: Option<[u8; 32]>,
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
                ContentReaderInner::Inflate(Box::new(archive_decoder(file)))
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

    /// The fs-verity digest the kernel held for this object's payload when it
    /// was loaded, for a load that asked for it.
    ///
    /// Only an object whose whole file is the raw payload qualifies: an
    /// `archive` object stores a header and compressed bytes, so the digest
    /// of its file is not the digest of its content. The descriptor must name
    /// SHA-256, 4096-byte blocks, no salt, and a data size equal to the
    /// payload size. Every error and every mismatch gives `None`, and the
    /// caller computes the digest from the payload. The kernel read takes no
    /// payload byte, so it does not find damage to a sealed object's data or
    /// verity metadata; `fsck` is the check for object integrity.
    pub(crate) fn kernel_fs_verity(&self) -> Option<[u8; 32]> {
        self.kernel_verity
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
        self.load_file_with(checksum, false).await
    }

    /// [`Repo::load_file`], which also reads the kernel's fs-verity digest of
    /// the payload when `measure` is set, on the descriptor and in the
    /// blocking-pool call the metadata load uses. See
    /// [`FileObject::kernel_fs_verity`].
    pub(crate) async fn load_file_with(
        &self,
        checksum: &Checksum,
        measure: bool,
    ) -> Result<FileObject> {
        let mode = self.mode();
        let path = loose_path(checksum, ObjectType::File, mode);
        let repo = self.clone();
        let key = *checksum;
        let loaded =
            ostrya_rt::unblock(move || load_by_mode(repo.objects_fd(), &path, &key, mode, measure))
                .await?;
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
            kernel_verity: loaded.kernel_verity,
        })
    }
}

/// Load a file object from a transaction staging directory by its flat name,
/// used for the staged-first lookup that reads objects staged in the current
/// transaction before they publish into `objects/`. The metadata is decoded the
/// same per-mode way as a loose object; the payload streams from the staging
/// directory. `measure` is the flag of [`Repo::load_file_with`].
pub(crate) async fn load_staged_file(
    repo: &Repo,
    staging_fd: BorrowedFd<'_>,
    checksum: &Checksum,
    measure: bool,
) -> Result<FileObject> {
    let mode = repo.mode();
    let name = crate::write::flat_name(checksum, ObjectType::File, mode);
    let dir = Arc::new(staging_fd.try_clone_to_owned()?);
    let key = *checksum;
    let load_dir = dir.clone();
    let load_name = name.clone();
    let loaded =
        ostrya_rt::unblock(move || load_by_mode(load_dir.as_fd(), &load_name, &key, mode, measure))
            .await?;
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
        kernel_verity: loaded.kernel_verity,
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
    kernel_verity: Option<[u8; 32]>,
}

/// Dispatch to the loader for the repository mode. `object_path` locates the
/// object relative to `dir_fd`: a loose path under `objects/`, or a flat name in
/// a staging directory. `measure` asks a raw-payload loader for the kernel's
/// fs-verity digest; an `archive` object never has one.
fn load_by_mode(
    dir_fd: BorrowedFd<'_>,
    object_path: &str,
    checksum: &Checksum,
    mode: RepoMode,
    measure: bool,
) -> Result<Loaded> {
    match mode {
        RepoMode::Archive => load_archive(dir_fd, object_path, checksum),
        RepoMode::BareUser | RepoMode::BareUserShared => {
            load_bare_user(dir_fd, object_path, checksum, measure)
        }
        RepoMode::Bare => load_bare(dir_fd, object_path, checksum, measure),
        RepoMode::BareUserOnly => load_bare_user_only(dir_fd, object_path, checksum, measure),
        RepoMode::BareSplitXattrs => load_bare_split_xattrs(dir_fd, object_path, checksum, measure),
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

/// The `statx` fields the loaders read: the file type, mode, owner, and size.
/// The attribute words come back whatever the mask asks for.
const STATX_FIELDS: StatxFlags = StatxFlags::TYPE
    .union(StatxFlags::MODE)
    .union(StatxFlags::UID)
    .union(StatxFlags::GID)
    .union(StatxFlags::SIZE);

/// `statx` a loose object without following symlinks, mapping a missing object
/// to `ObjectNotFound`.
fn stat_object(
    objects_fd: BorrowedFd<'_>,
    path: &str,
    checksum: &Checksum,
    ty: ObjectType,
) -> Result<Statx> {
    rustix::fs::statx(objects_fd, path, AtFlags::SYMLINK_NOFOLLOW, STATX_FIELDS)
        .map_err(|e| map_object_error(e, checksum, ty))
}

/// Whether `statx` reports the inode as sealed with fs-verity. The kernel sets
/// the attribute on every file with fs-verity enabled. The attribute mask is
/// not read: btrfs sets the attribute but leaves it out of the mask.
fn is_sealed(stat: &Statx) -> bool {
    stat.stx_attributes.contains(StatxAttributes::VERITY)
}

/// The fs-verity digest the kernel holds for the raw-payload object open at
/// `fd`, when it is sealed with SHA-256, 4096-byte blocks, no salt, and a data
/// size of `size`. A clear `probe` issues no ioctl. Every error and every
/// mismatch gives `None`.
fn sealed_digest(fd: BorrowedFd<'_>, size: u64, probe: bool) -> Option<[u8; 32]> {
    if !probe {
        return None;
    }
    let desc = ostrya_sys::read_verity_descriptor(fd).ok()?;
    if desc.hash_algorithm != 1
        || desc.log_blocksize != 12
        || desc.salt_size != 0
        || desc.data_size != size
    {
        return None;
    }
    ostrya_sys::measure_verity(fd).ok()
}

/// [`sealed_digest`] for an object a loader reached by path alone. A clear
/// `probe` opens nothing.
fn sealed_digest_at(
    dir_fd: BorrowedFd<'_>,
    path: &str,
    size: u64,
    probe: bool,
) -> Option<[u8; 32]> {
    if !probe {
        return None;
    }
    let fd = rustix::fs::openat(
        dir_fd,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .ok()?;
    sealed_digest(fd.as_fd(), size, probe)
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
        kernel_verity: None,
    })
}

fn load_bare_user(
    dir_fd: BorrowedFd<'_>,
    path: &str,
    checksum: &Checksum,
    measure: bool,
) -> Result<Loaded> {
    use std::io::Read;

    let fd = open_object(dir_fd, path, checksum)?;
    let meta = object::read_xattr(fd.as_fd(), "user.ostreemeta")
        .map_err(Error::Io)?
        .ok_or_else(|| {
            Error::InvalidFormat("bare-user .file is missing its user.ostreemeta xattr".into())
        })?;
    let header = FileHeader::parse_stat_metadata(&meta)?;
    let stat = rustix::fs::statx(&fd, "", AtFlags::EMPTY_PATH, StatxFlags::SIZE)?;

    let (kind, source, kernel_verity) = if header.is_symlink() {
        let mut content = Vec::new();
        std::fs::File::from(fd)
            .take(SYMLINK_READ_CAP)
            .read_to_end(&mut content)?;
        (
            FileKind::Symlink {
                target: symlink_target_from_content(&content)?,
            },
            ReaderSource::None,
            None,
        )
    } else {
        let size = stat.stx_size;
        let kernel_verity = sealed_digest(fd.as_fd(), size, measure && is_sealed(&stat));
        (
            FileKind::Regular { size },
            ReaderSource::Plain,
            kernel_verity,
        )
    };
    Ok(Loaded {
        uid: header.uid,
        gid: header.gid,
        mode: header.mode,
        xattrs: header.xattrs,
        kind,
        source,
        kernel_verity,
    })
}

fn load_bare(
    dir_fd: BorrowedFd<'_>,
    path: &str,
    checksum: &Checksum,
    measure: bool,
) -> Result<Loaded> {
    let stat = stat_object(dir_fd, path, checksum, ObjectType::File)?;
    let uid = stat.stx_uid;
    let gid = stat.stx_gid;
    let mode = u32::from(stat.stx_mode);

    match FileType::from_raw_mode(mode) {
        FileType::Symlink => Ok(Loaded {
            uid,
            gid,
            mode,
            xattrs: object::read_link_xattrs(dir_fd, path)?,
            kind: FileKind::Symlink {
                target: read_link_target(dir_fd, path)?,
            },
            source: ReaderSource::None,
            kernel_verity: None,
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
            let size = stat.stx_size;
            Ok(Loaded {
                uid,
                gid,
                mode,
                xattrs,
                kind: FileKind::Regular { size },
                source: ReaderSource::Plain,
                kernel_verity: sealed_digest(fd.as_fd(), size, measure && is_sealed(&stat)),
            })
        }
        _ => Err(Error::InvalidFormat(
            "bare object is neither a regular file nor a symlink".into(),
        )),
    }
}

fn load_bare_user_only(
    dir_fd: BorrowedFd<'_>,
    path: &str,
    checksum: &Checksum,
    measure: bool,
) -> Result<Loaded> {
    let stat = stat_object(dir_fd, path, checksum, ObjectType::File)?;
    // uid/gid are discarded in this mode and read back as 0; the mode is the
    // canonical mode carried on the inode; no xattrs are stored.
    let mode = u32::from(stat.stx_mode);
    match FileType::from_raw_mode(mode) {
        FileType::Symlink => Ok(Loaded {
            uid: 0,
            gid: 0,
            mode,
            xattrs: Xattrs::empty(),
            kind: FileKind::Symlink {
                target: read_link_target(dir_fd, path)?,
            },
            source: ReaderSource::None,
            kernel_verity: None,
        }),
        FileType::RegularFile => Ok(Loaded {
            uid: 0,
            gid: 0,
            mode,
            xattrs: Xattrs::empty(),
            kind: FileKind::Regular {
                size: stat.stx_size,
            },
            source: ReaderSource::Plain,
            kernel_verity: sealed_digest_at(
                dir_fd,
                path,
                stat.stx_size,
                measure && is_sealed(&stat),
            ),
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
    measure: bool,
) -> Result<Loaded> {
    // Storage is bare: the inode carries the logical uid/gid/mode, a regular
    // file holds the raw payload, and a symlink is a real symlink. The inode
    // holds no xattrs; the logical set lives in a separate object reached
    // through the `.file-xattrs-link` entry keyed by the file checksum.
    // bare-split-xattrs is read-only and never staged, so `dir_fd` is always the
    // repository's `objects/`; the split-xattrs link is resolved by its own
    // loose path from the checksum.
    let stat = stat_object(dir_fd, path, checksum, ObjectType::File)?;
    let uid = stat.stx_uid;
    let gid = stat.stx_gid;
    let mode = u32::from(stat.stx_mode);
    let xattrs = load_split_xattrs(dir_fd, checksum)?;

    match FileType::from_raw_mode(mode) {
        FileType::Symlink => Ok(Loaded {
            uid,
            gid,
            mode,
            xattrs,
            kind: FileKind::Symlink {
                target: read_link_target(dir_fd, path)?,
            },
            source: ReaderSource::None,
            kernel_verity: None,
        }),
        FileType::RegularFile => Ok(Loaded {
            uid,
            gid,
            mode,
            xattrs,
            kind: FileKind::Regular {
                size: stat.stx_size,
            },
            source: ReaderSource::Plain,
            kernel_verity: sealed_digest_at(
                dir_fd,
                path,
                stat.stx_size,
                measure && is_sealed(&stat),
            ),
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
    /// Boxed: the decoder state is large beside the other variants.
    Inflate(Box<ArchiveDecoder>),
}

impl ContentReader {
    /// The shared read step both trait families drive. `rt::File` and the
    /// archive decoder present `futures_io::AsyncRead` under either backend.
    fn poll_read_bytes(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
        use futures_io::AsyncRead;
        match &mut self.inner {
            ContentReaderInner::Empty => Poll::Ready(Ok(0)),
            ContentReaderInner::Plain(inner) => Pin::new(inner).poll_read(cx, out),
            ContentReaderInner::Inflate(inner) => Pin::new(&mut **inner).poll_read(cx, out),
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

#[cfg(test)]
mod sealed_verity_tests {
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    use super::{FileKind, is_sealed, sealed_digest_at, stat_object};
    use crate::{CreateOptions, FileMeta, Repo, Transaction};
    use ostrya_composefs::FsVerityHasher;
    use ostrya_core::{Checksum, ObjectType, RepoMode, loose_path};
    use ostrya_rt::block_on;

    /// A payload spanning several verity blocks (> 4096 bytes).
    fn payload() -> Vec<u8> {
        b"sealed fs-verity fast path payload\n".repeat(300)
    }

    /// A fresh scratch directory for one test.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-sealed-{tag}-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Whether the filesystem holding `dir` takes fs-verity, probed by sealing
    /// a file there.
    fn verity_supported(dir: &Path) -> bool {
        let probe = dir.join("probe");
        std::fs::write(&probe, b"probe").unwrap();
        let ro = std::fs::File::open(&probe).unwrap();
        let ok = ostrya_sys::enable_verity(ro.as_fd()).is_ok();
        drop(ro);
        let _ = std::fs::remove_file(&probe);
        ok
    }

    /// Create a `mode` repository under `dir` with `[ex-integrity] fsverity`
    /// set to `fsverity`, and return it opened.
    async fn repo_in(dir: &Path, mode: RepoMode, fsverity: &str) -> Repo {
        let root = dir.join("repo");
        drop(Repo::create(&root, CreateOptions::new(mode)).await.unwrap());
        let cfg = root.join("config");
        let mut text = std::fs::read_to_string(&cfg).unwrap();
        text.push_str(&format!("[ex-integrity]\nfsverity={fsverity}\n"));
        std::fs::write(&cfg, text).unwrap();
        Repo::open(&root).await.unwrap()
    }

    /// Stage [`payload`] as one content object in `txn`, owned by the owner of
    /// `dir`. A bare repository applies the owner, and an unprivileged process
    /// can give a file only its own.
    async fn stage_payload(txn: &Transaction, dir: &Path) -> Checksum {
        let owner = std::fs::metadata(dir).unwrap();
        txn.write_regfile_inline(
            None,
            &FileMeta::regular(owner.uid(), owner.gid(), 0o644),
            &payload(),
        )
        .await
        .unwrap()
    }

    /// Create a `mode` repository as [`repo_in`] does, write [`payload`] as
    /// one committed content object, and return the repository and the
    /// object's checksum.
    async fn repo_with_object(dir: &Path, mode: RepoMode, fsverity: &str) -> (Repo, Checksum) {
        let repo = repo_in(dir, mode, fsverity).await;
        let txn = repo.transaction().await.unwrap();
        let checksum = stage_payload(&txn, dir).await;
        txn.commit().await.unwrap();
        (repo, checksum)
    }

    /// The loose path of `checksum`'s content object under `dir/repo`.
    fn object_path(dir: &Path, checksum: &Checksum, mode: RepoMode) -> PathBuf {
        dir.join("repo/objects")
            .join(loose_path(checksum, ObjectType::File, mode))
    }

    /// Whether `statx` reports `checksum`'s content object as sealed.
    fn sealed(repo: &Repo, checksum: &Checksum) -> bool {
        let path = loose_path(checksum, ObjectType::File, repo.mode());
        let stat = stat_object(repo.objects_fd(), &path, checksum, ObjectType::File).unwrap();
        is_sealed(&stat)
    }

    /// Check that a `mode` object the write path sealed yields the kernel's
    /// digest on a measuring load, and none on a plain load.
    fn check_sealed_object_yields_the_kernel_digest(tag: &str, mode: RepoMode) {
        let dir = scratch(tag);
        if !verity_supported(&dir) {
            eprintln!("skipping sealed digest check: filesystem lacks fs-verity");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        block_on(async {
            let (repo, checksum) = repo_with_object(&dir, mode, "yes").await;
            let file = repo.load_file_with(&checksum, true).await.unwrap();
            assert_eq!(
                file.kernel_fs_verity(),
                Some(FsVerityHasher::hash(&payload())),
                "the kernel digest equals the computed digest"
            );
            let plain = repo.load_file(&checksum).await.unwrap();
            assert_eq!(plain.kernel_fs_verity(), None, "a plain load reads none");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A bare-user object sealed by the write path yields the kernel's digest,
    /// which equals the digest the port computes from the payload.
    #[test]
    fn a_sealed_bare_user_object_yields_the_kernel_digest() {
        check_sealed_object_yields_the_kernel_digest("bare-user", RepoMode::BareUser);
    }

    /// A bare-user-only object, which the loader reaches by path alone, yields
    /// the kernel's digest.
    #[test]
    fn a_sealed_bare_user_only_object_yields_the_kernel_digest() {
        check_sealed_object_yields_the_kernel_digest("bare-user-only", RepoMode::BareUserOnly);
    }

    /// A bare object, owned by the running user, yields the kernel's digest.
    #[test]
    fn a_sealed_bare_object_yields_the_kernel_digest() {
        check_sealed_object_yields_the_kernel_digest("bare", RepoMode::Bare);
    }

    /// An object staged in an open transaction of a sealing repository yields
    /// the kernel's digest from the staging directory, before the commit.
    #[test]
    fn a_sealed_staged_object_yields_the_kernel_digest() {
        let dir = scratch("staged");
        if !verity_supported(&dir) {
            eprintln!("skipping staged digest check: filesystem lacks fs-verity");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        block_on(async {
            let repo = repo_in(&dir, RepoMode::BareUser, "yes").await;
            let txn = repo.transaction().await.unwrap();
            let checksum = stage_payload(&txn, &dir).await;
            assert!(txn.is_staged(&checksum, ObjectType::File));
            let file = txn
                .load_file_staged_first_with(&checksum, true)
                .await
                .unwrap();
            assert_eq!(
                file.kernel_fs_verity(),
                Some(FsVerityHasher::hash(&payload())),
                "the staged object gives the kernel digest"
            );
            txn.abort().await.unwrap();
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `statx` reports a sealed object as sealed and an unsealed one as
    /// unsealed, and an object reported as unsealed is never probed: the
    /// kernel read of a sealed object gives none when the probe is clear.
    #[test]
    fn statx_gates_the_kernel_read() {
        let dir = scratch("gate");
        if !verity_supported(&dir) {
            eprintln!("skipping statx gate check: filesystem lacks fs-verity");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        block_on(async {
            let sealed_dir = dir.join("sealed");
            let open_dir = dir.join("open");
            std::fs::create_dir_all(&sealed_dir).unwrap();
            std::fs::create_dir_all(&open_dir).unwrap();
            let (sealed_repo, sealed_sum) =
                repo_with_object(&sealed_dir, RepoMode::BareUser, "yes").await;
            let (open, open_sum) = repo_with_object(&open_dir, RepoMode::BareUser, "no").await;

            assert!(sealed(&sealed_repo, &sealed_sum));
            assert!(!sealed(&open, &open_sum));
            let file = open.load_file_with(&open_sum, true).await.unwrap();
            assert_eq!(file.kernel_fs_verity(), None);

            let path = loose_path(&sealed_sum, ObjectType::File, RepoMode::BareUser);
            let size = payload().len() as u64;
            let objects = sealed_repo.objects_fd();
            assert!(sealed_digest_at(objects, &path, size, true).is_some());
            assert_eq!(
                sealed_digest_at(objects, &path, size, false),
                None,
                "a clear probe issues no ioctl"
            );
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The bare-user fixture repository, unpacked under `dir` with its
    /// `user.*` xattrs, or `None` when the published package carries no
    /// fixture.
    fn unpack_bare_user_fixture(dir: &Path) -> Option<PathBuf> {
        let tar = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/bare-user.tar");
        if !tar.exists() {
            return None;
        }
        let status = std::process::Command::new("tar")
            .args(["--xattrs", "--xattrs-include=user.*", "-xf"])
            .arg(&tar)
            .arg("-C")
            .arg(dir)
            .status()
            .expect("run tar to unpack the fixture");
        assert!(status.success(), "tar failed to unpack {}", tar.display());
        Some(dir.join("repo"))
    }

    /// Every backed object of the bare-user fixture, once sealed, gives the
    /// kernel's digest on the measuring load the composefs export makes, and
    /// that digest equals the one streamed from the payload. This is the
    /// proof that the sealed-repository export test in `tests/composefs.rs`
    /// takes the kernel path. Skips when the fixture is absent or the
    /// filesystem lacks fs-verity.
    #[test]
    fn every_sealed_fixture_object_yields_the_kernel_digest() {
        use futures_lite::AsyncReadExt;

        let dir = scratch("fixture");
        if !verity_supported(&dir) {
            eprintln!("skipping fixture digest check: filesystem lacks fs-verity");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let Some(root) = unpack_bare_user_fixture(&dir) else {
            eprintln!("skipping fixture digest check: fixture absent");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        };
        let mut objects = Vec::new();
        for fanout in std::fs::read_dir(root.join("objects")).unwrap() {
            let fanout = fanout.unwrap().path();
            if !fanout.is_dir() {
                continue;
            }
            let prefix = fanout.file_name().unwrap().to_str().unwrap().to_owned();
            for entry in std::fs::read_dir(&fanout).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_str().unwrap();
                let Some(rest) = name.strip_suffix(".file") else {
                    continue;
                };
                let checksum = Checksum::from_hex(&format!("{prefix}{rest}")).unwrap();
                let ro = std::fs::File::open(&path).unwrap();
                ostrya_sys::enable_verity(ro.as_fd()).unwrap();
                objects.push(checksum);
            }
        }
        block_on(async {
            let repo = Repo::open(&root).await.unwrap();
            let mut backed = 0;
            for checksum in &objects {
                let file = repo.load_file_with(checksum, true).await.unwrap();
                if !matches!(file.kind, FileKind::Regular { size } if size > 0) {
                    continue;
                }
                let mut reader = file.reader().await.unwrap();
                let mut hasher = FsVerityHasher::new();
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = reader.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                assert_eq!(
                    file.kernel_fs_verity(),
                    Some(hasher.finalize()),
                    "{checksum} gives the kernel digest"
                );
                backed += 1;
            }
            assert!(backed > 0, "the fixture holds backed objects");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An archive object is sealed as a whole `.filez` file, whose digest is not
    /// the digest of its content, so it yields none.
    #[test]
    fn a_sealed_archive_object_yields_none() {
        let dir = scratch("archive");
        if !verity_supported(&dir) {
            eprintln!("skipping archive check: filesystem lacks fs-verity");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        block_on(async {
            let (repo, checksum) = repo_with_object(&dir, RepoMode::Archive, "yes").await;
            let object = object_path(&dir, &checksum, RepoMode::Archive);
            let fd = std::fs::File::open(&object).unwrap();
            assert!(
                ostrya_sys::measure_verity(fd.as_fd()).is_ok(),
                "the write path sealed the archive object"
            );
            let file = repo.load_file_with(&checksum, true).await.unwrap();
            assert_eq!(file.kernel_fs_verity(), None);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An object the write path did not seal yields none. This needs no
    /// verity support, so it runs on every filesystem.
    #[test]
    fn an_unsealed_object_yields_none() {
        let dir = scratch("unsealed");
        block_on(async {
            let (repo, checksum) = repo_with_object(&dir, RepoMode::BareUser, "no").await;
            let file = repo.load_file_with(&checksum, true).await.unwrap();
            assert_eq!(file.kernel_fs_verity(), None);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An object sealed with a salt carries a digest ostree does not use, so it
    /// yields none.
    #[test]
    fn a_salted_object_yields_none() {
        let dir = scratch("salted");
        if !verity_supported(&dir) {
            eprintln!("skipping salted check: filesystem lacks fs-verity");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        block_on(async {
            let (repo, checksum) = repo_with_object(&dir, RepoMode::BareUser, "no").await;
            let object = object_path(&dir, &checksum, RepoMode::BareUser);
            let ro = std::fs::File::open(&object).unwrap();
            ostrya_sys::enable_verity_with_salt(ro.as_fd(), &[0x5a; 8]).unwrap();
            drop(ro);

            let file = repo.load_file_with(&checksum, true).await.unwrap();
            assert_eq!(file.kernel_fs_verity(), None);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Create a `mode` repository under `dir` as [`repo_in`] does, write
    /// [`payload`] with `meta` as one committed content object, and return the
    /// repository and the object's checksum, or the error of the write.
    async fn write_one(
        dir: &Path,
        mode: RepoMode,
        fsverity: &str,
        meta: &FileMeta,
    ) -> crate::Result<(Repo, Checksum)> {
        std::fs::create_dir_all(dir).unwrap();
        let repo = repo_in(dir, mode, fsverity).await;
        let txn = repo.transaction().await?;
        let checksum = txn.write_regfile_inline(None, meta, &payload()).await?;
        txn.commit().await?;
        Ok((repo, checksum))
    }

    /// The name of the logical xattr the bare-mode test gives its objects.
    const SEAL_XATTR: &str = "user.ostrya-seal";

    /// The inode fields of one stored content object that the seal-order tests
    /// compare.
    #[derive(Debug)]
    struct Inode {
        /// The permission bits of the inode mode.
        perm: u32,
        uid: u32,
        gid: u32,
        /// Whether `statx` reports the inode as sealed.
        sealed: bool,
        /// The `user.ostreemeta` value, or `None` when the object has none or
        /// the owner cannot open it.
        ostreemeta: Option<Vec<u8>>,
        /// The [`SEAL_XATTR`] value, read the same way.
        seal_xattr: Option<Vec<u8>>,
    }

    /// The stored inode of `checksum`'s content object.
    fn inode_of(repo: &Repo, checksum: &Checksum) -> Inode {
        use rustix::fs::{Mode, OFlags};

        let path = loose_path(checksum, ObjectType::File, repo.mode());
        let stat = stat_object(repo.objects_fd(), &path, checksum, ObjectType::File).unwrap();
        let fd = rustix::fs::openat(
            repo.objects_fd(),
            path.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .ok();
        let xattr = |name: &str| {
            fd.as_ref()
                .and_then(|fd| crate::object::read_xattr(fd.as_fd(), name).unwrap())
        };
        Inode {
            perm: u32::from(stat.stx_mode) & 0o7777,
            uid: stat.stx_uid,
            gid: stat.stx_gid,
            sealed: is_sealed(&stat),
            ostreemeta: xattr("user.ostreemeta"),
            seal_xattr: xattr(SEAL_XATTR),
        }
    }

    /// Write each of `metas` into a `mode` repository with `[ex-integrity]
    /// fsverity` set to `fsverity`, and into a second repository with verity
    /// off. Check that each write succeeds, that the two objects have the same
    /// checksum, inode mode, owner, and xattrs, that only the first is sealed,
    /// and that the first gives the kernel digest where the loader can read
    /// it. Returns the inodes of the sealed side, or `None` when the
    /// filesystem lacks fs-verity.
    fn check_like_unsealed(
        tag: &str,
        mode: RepoMode,
        fsverity: &str,
        metas: &[FileMeta],
    ) -> Option<Vec<Inode>> {
        let dir = scratch(tag);
        if !verity_supported(&dir) {
            eprintln!("skipping {tag} seal-order check: filesystem lacks fs-verity");
            let _ = std::fs::remove_dir_all(&dir);
            return None;
        }
        let mut failures = Vec::new();
        let mut sealed_side = Vec::new();
        block_on(async {
            for meta in metas {
                let name = format!("{:o}", meta.mode);
                let on = write_one(&dir.join(format!("on-{name}")), mode, fsverity, meta).await;
                let (on_repo, on_sum) = match on {
                    Ok(pair) => pair,
                    Err(e) => {
                        failures.push(format!("{name} with fsverity={fsverity}: {e}"));
                        continue;
                    }
                };
                let (off_repo, off_sum) =
                    write_one(&dir.join(format!("off-{name}")), mode, "no", meta)
                        .await
                        .unwrap();
                assert_eq!(on_sum, off_sum, "{name}: the checksums agree");
                let on = inode_of(&on_repo, &on_sum);
                let off = inode_of(&off_repo, &off_sum);
                assert_eq!(on.perm, off.perm, "{name}: the inode modes agree");
                assert_eq!(
                    (on.uid, on.gid),
                    (off.uid, off.gid),
                    "{name}: the owners agree"
                );
                assert_eq!(
                    on.ostreemeta, off.ostreemeta,
                    "{name}: user.ostreemeta agrees"
                );
                assert_eq!(on.seal_xattr, off.seal_xattr, "{name}: {SEAL_XATTR} agrees");
                assert!(
                    !off.sealed,
                    "{name}: the object with verity off is unsealed"
                );
                if !on.sealed {
                    failures.push(format!("{name} with fsverity={fsverity}: object unsealed"));
                    continue;
                }
                if mode != RepoMode::Archive && on.perm & 0o400 != 0 {
                    let file = on_repo.load_file_with(&on_sum, true).await.unwrap();
                    assert_eq!(
                        file.kernel_fs_verity(),
                        Some(FsVerityHasher::hash(&payload())),
                        "{name}: the kernel digest equals the computed digest"
                    );
                }
                sealed_side.push(on);
            }
        });
        let _ = std::fs::remove_dir_all(&dir);
        assert!(failures.is_empty(), "{tag}: {failures:#?}");
        Some(sealed_side)
    }

    /// Regular-file metadata owned by root for each of `perms`.
    fn metas(perms: &[u32]) -> Vec<FileMeta> {
        perms.iter().map(|&p| FileMeta::regular(0, 0, p)).collect()
    }

    /// A bare-user object whose logical mode has no owner-write bit is sealed
    /// in a repository with `fsverity=yes`, and it is otherwise the object the
    /// same write stores with verity off.
    #[test]
    fn a_bare_user_object_without_owner_write_is_sealed() {
        check_like_unsealed(
            "bu-nowrite",
            RepoMode::BareUser,
            "yes",
            &metas(&[0o444, 0o555, 0o400]),
        );
    }

    /// A bare-user-only object whose logical mode has no owner-write bit is
    /// sealed, and so is one with no owner-read bit (0200), whose stored inode
    /// the owner cannot open.
    #[test]
    fn a_bare_user_only_object_without_owner_write_is_sealed() {
        check_like_unsealed(
            "buo-nowrite",
            RepoMode::BareUserOnly,
            "yes",
            &metas(&[0o444, 0o555, 0o400, 0o200]),
        );
    }

    /// With `fsverity=maybe`, a bare-user object whose logical mode has no
    /// owner-write bit is sealed and not left unsealed without a report.
    #[test]
    fn maybe_seals_a_bare_user_object_without_owner_write() {
        check_like_unsealed("bu-maybe", RepoMode::BareUser, "maybe", &metas(&[0o444]));
    }

    /// An owner-writable object is sealed, and its inode is the one the write
    /// path stores with verity off: in bare-user the logical mode with the
    /// owner-read bit and the logical `user.ostreemeta`, in archive 0644.
    #[test]
    fn an_owner_writable_object_is_sealed_with_an_unchanged_inode() {
        let perms = [0o644, 0o755];
        let Some(inodes) =
            check_like_unsealed("bu-write", RepoMode::BareUser, "yes", &metas(&perms))
        else {
            return;
        };
        for (inode, (perm, meta)) in inodes.iter().zip(perms.iter().zip(metas(&perms))) {
            assert_eq!(inode.perm, perm | 0o400);
            let expected = meta.regular_header().serialize_stat_metadata().unwrap();
            assert_eq!(inode.ostreemeta.as_deref(), Some(&expected[..]));
        }
        let inodes = check_like_unsealed("ar-write", RepoMode::Archive, "yes", &metas(&perms))
            .expect("the archive check runs where the bare-user check ran");
        for inode in inodes {
            assert_eq!(inode.perm, 0o644);
        }
    }

    /// A bare object with an owner other than the writer, a logical mode
    /// without owner write, and a logical xattr is sealed and carries the
    /// logical owner, mode, and xattr. A set-user-ID mode survives the owner
    /// change. Changing the owner of a file needs root.
    #[test]
    fn a_bare_object_with_a_foreign_owner_is_sealed_as_root() {
        if !rustix::process::geteuid().is_root() {
            eprintln!("skipping bare foreign-owner seal check: not running as root");
            return;
        }
        let xattrs =
            ostrya_core::Xattrs::new([(format!("{SEAL_XATTR}\0").into_bytes(), b"v".to_vec())])
                .unwrap();
        let metas: Vec<FileMeta> = [0o100444, 0o104555]
            .into_iter()
            .map(|mode| FileMeta {
                uid: 1234,
                gid: 5678,
                mode,
                xattrs: xattrs.clone(),
            })
            .collect();
        let Some(inodes) = check_like_unsealed("bare-owner", RepoMode::Bare, "yes", &metas) else {
            return;
        };
        for (inode, perm) in inodes.iter().zip([0o444, 0o4555]) {
            assert_eq!((inode.uid, inode.gid), (1234, 5678));
            assert_eq!(inode.perm, perm);
            assert_eq!(inode.seal_xattr.as_deref(), Some(&b"v"[..]));
        }
    }

    /// A bare object owned by the writer, with a logical mode without owner
    /// write and a logical `user.*` xattr, is sealed and carries the logical
    /// mode and xattr. The writer needs no privilege for this owner.
    #[test]
    fn a_bare_object_owned_by_the_writer_without_owner_write_is_sealed() {
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let xattrs =
            ostrya_core::Xattrs::new([(format!("{SEAL_XATTR}\0").into_bytes(), b"v".to_vec())])
                .unwrap();
        let metas: Vec<FileMeta> = [0o100444, 0o100555, 0o100400]
            .into_iter()
            .map(|mode| FileMeta {
                uid,
                gid,
                mode,
                xattrs: xattrs.clone(),
            })
            .collect();
        let Some(inodes) = check_like_unsealed("bare-self", RepoMode::Bare, "yes", &metas) else {
            return;
        };
        for (inode, perm) in inodes.iter().zip([0o444, 0o555, 0o400]) {
            assert_eq!((inode.uid, inode.gid), (uid, gid));
            assert_eq!(inode.perm, perm);
            assert_eq!(inode.seal_xattr.as_deref(), Some(&b"v"[..]));
        }
    }

    /// A bare object whose logical xattrs hold a `security.capability` value
    /// stores that value unchanged, with verity off and with verity on, for an
    /// owner that is the writer and for a foreign owner with a set-user-ID mode
    /// and a `user.*` xattr. The kernel removes `security.capability` when the
    /// owner of a regular file changes, so the write sets the xattrs after the
    /// owner. Setting the xattr and changing the owner need root.
    #[test]
    fn a_bare_object_keeps_its_file_capability_as_root() {
        use rustix::fs::{Mode, OFlags};

        if !rustix::process::geteuid().is_root() {
            eprintln!("skipping bare file-capability check: not running as root");
            return;
        }
        // A VFS_CAP_REVISION_2 value: the revision with the effective bit,
        // then the permitted and inheritable low words, then the high words.
        // The permitted set holds cap_net_raw (bit 13).
        let cap: Vec<u8> = [0x0200_0001u32, 1 << 13, 0, 0, 0]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let cap_xattr = (b"security.capability\0".to_vec(), cap.clone());
        let seal_xattr = (format!("{SEAL_XATTR}\0").into_bytes(), b"v".to_vec());
        // Each case: the tag, the logical metadata, the expected inode
        // permission bits, and the expected SEAL_XATTR value.
        let cases = [
            (
                "self",
                FileMeta {
                    uid: rustix::process::geteuid().as_raw(),
                    gid: rustix::process::getegid().as_raw(),
                    mode: 0o100755,
                    xattrs: ostrya_core::Xattrs::new([cap_xattr.clone()]).unwrap(),
                },
                0o755,
                None,
            ),
            (
                "foreign",
                FileMeta {
                    uid: 1234,
                    gid: 5678,
                    mode: 0o104755,
                    xattrs: ostrya_core::Xattrs::new([cap_xattr, seal_xattr]).unwrap(),
                },
                0o4755,
                Some(b"v".to_vec()),
            ),
        ];
        let dir = scratch("bare-cap");
        let verity = verity_supported(&dir);
        let mut failures = Vec::new();
        block_on(async {
            for fsverity in ["no", "yes"] {
                if fsverity == "yes" && !verity {
                    eprintln!("skipping the verity side: filesystem lacks fs-verity");
                    continue;
                }
                for (tag, meta, perm, seal) in &cases {
                    let (repo, checksum) = write_one(
                        &dir.join(format!("{fsverity}-{tag}")),
                        RepoMode::Bare,
                        fsverity,
                        meta,
                    )
                    .await
                    .unwrap();
                    let path = loose_path(&checksum, ObjectType::File, repo.mode());
                    let fd = rustix::fs::openat(
                        repo.objects_fd(),
                        path.as_str(),
                        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .unwrap();
                    let stored =
                        crate::object::read_xattr(fd.as_fd(), "security.capability").unwrap();
                    if stored.as_deref() != Some(&cap[..]) {
                        failures.push(format!(
                            "fsverity={fsverity} {tag}: security.capability is {stored:02x?}"
                        ));
                    }
                    let inode = inode_of(&repo, &checksum);
                    let what = format!("fsverity={fsverity} {tag}");
                    assert_eq!(inode.perm, *perm, "{what}: the inode mode");
                    assert_eq!(
                        (inode.uid, inode.gid),
                        (meta.uid, meta.gid),
                        "{what}: owner"
                    );
                    assert_eq!(&inode.seal_xattr, seal, "{what}: {SEAL_XATTR}");
                    assert_eq!(inode.sealed, fsverity == "yes", "{what}: the seal");
                }
            }
        });
        let _ = std::fs::remove_dir_all(&dir);
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// Marks the re-executed child of
    /// [`an_object_written_under_a_umask_without_owner_write_is_sealed`], and
    /// names the file the child writes to record that the write ran.
    const SEAL_UMASK_CHILD: &str = "OSTRYA_SEAL_UMASK_CHILD";

    /// An object written while the process umask clears the owner-write bit is
    /// sealed and stored with its logical mode.
    ///
    /// The umask is a property of the process and the tests of this binary run
    /// in parallel threads, so the write goes to a child: this test binary
    /// re-executed for this test alone. The child sets the umask only around
    /// the write, because the staging and fanout directories the transaction
    /// creates need owner write.
    #[test]
    fn an_object_written_under_a_umask_without_owner_write_is_sealed() {
        if let Some(marker) = std::env::var_os(SEAL_UMASK_CHILD) {
            // The child writes in the parent's scratch directory, so the parent
            // removes it also when the child panics.
            let marker = PathBuf::from(marker);
            write_under_umask(&marker.with_file_name("child"));
            std::fs::write(marker, b"written").expect("record that the write ran");
            return;
        }
        let dir = scratch("umask");
        if !verity_supported(&dir) {
            eprintln!("skipping umask seal check: filesystem lacks fs-verity");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let marker = dir.join("written");
        let exe = std::env::current_exe().expect("the path of the running test binary");
        let status = std::process::Command::new(&exe)
            .arg("--exact")
            .arg("file::sealed_verity_tests::an_object_written_under_a_umask_without_owner_write_is_sealed")
            .arg("--nocapture")
            .env(SEAL_UMASK_CHILD, &marker)
            .status()
            .expect("re-run the test binary for the umask write");
        let written = marker.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            status.success(),
            "the write under umask 0222 failed: {status}"
        );
        // A name the child's filter does not match runs nothing and still
        // exits 0, so the marker is what proves the write ran.
        assert!(
            written,
            "the child ran no write: the test name the filter names is stale"
        );
    }

    /// The child half of
    /// [`an_object_written_under_a_umask_without_owner_write_is_sealed`],
    /// writing under `dir`.
    fn write_under_umask(dir: &Path) {
        use rustix::fs::Mode;
        use std::os::unix::fs::PermissionsExt;

        std::fs::create_dir_all(dir).unwrap();
        let meta = FileMeta::regular(0, 0, 0o644);
        block_on(async {
            let repo = repo_in(dir, RepoMode::BareUser, "yes").await;
            let txn = repo.transaction().await.unwrap();
            let old = rustix::process::umask(Mode::from_raw_mode(0o222));
            let probe = dir.join("umask-probe");
            std::fs::write(&probe, b"probe").unwrap();
            let probe_mode = std::fs::metadata(&probe).unwrap().permissions().mode() & 0o7777;
            let written = txn.write_regfile_inline(None, &meta, &payload()).await;
            rustix::process::umask(old);
            assert_eq!(probe_mode, 0o444, "umask 0222 clears the owner-write bit");
            let checksum = written.unwrap();
            txn.commit().await.unwrap();
            let inode = inode_of(&repo, &checksum);
            assert!(inode.sealed, "the object is sealed");
            assert_eq!(inode.perm, 0o644);
            let expected = meta.regular_header().serialize_stat_metadata().unwrap();
            assert_eq!(inode.ostreemeta.as_deref(), Some(&expected[..]));
        });
    }
}
