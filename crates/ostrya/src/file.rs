//! Read access to file objects: their metadata and their payload.
//!
//! [`Repo::load_file`] loads a [`FileObject`] from the object store. Its
//! [`FileKind`] tells a regular file from a symlink. [`FileObject::reader`]
//! gives a [`ContentReader`] over the payload of a regular file.

use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use ostrya_core::{Checksum, FileHeader, ObjectType, RepoMode, Xattrs, loose_path};
use ostrya_rt::FileReader;
use rustix::fs::FileType;

use crate::error::{Error, Result};
use crate::inflate::{ArchiveDecoder, archive_decoder};
use crate::object::{MAX_FILE_HEADER_SIZE, MAX_METADATA_SIZE};
use crate::read::object_path_error;
use crate::repo::Repo;
use crate::repo_fs::{self, FsError, FsResultExt, ObjectEntry, Opened, Reason, RepoDir, Stat};
use crate::write::FileMeta;

/// The largest symlink target that a load reads from a `bare-user` object.
/// A target is a path, so it is much shorter than this limit.
const SYMLINK_READ_CAP: u64 = 64 * 1024;

/// The longest target that a load reads from a symlink object. It is the
/// longest symlink target on Linux.
const LINK_TARGET_CAP: u64 = 4095;

/// The kind of a file object: a regular file or a symlink.
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

/// The way to the payload of a file object. [`FileObject::reader`] keeps it
/// to open a new stream on each call. The object path comes from the checksum
/// at read time.
#[derive(Debug, Clone)]
enum ReaderSource {
    /// No payload to stream (a symlink).
    None,
    /// The whole object file is the raw payload.
    Plain,
    /// A `.filez` object: raw-DEFLATE payload after `payload_offset` bytes.
    Archive { payload_offset: u64 },
}

impl ReaderSource {
    /// Returns the reader over `payload`.
    ///
    /// `payload` is an object file at the start of its payload, and the number
    /// of bytes on disk from there to the end. The reader inflates an archive
    /// payload. If the source has no payload, or `payload` is `None`, the
    /// reader gives no bytes.
    ///
    /// The length on disk bounds the read-ahead of the file. For an archive
    /// object, it is the length of the compressed stream. This stream can be
    /// longer than the payload.
    fn reader_over(&self, payload: Option<Payload>) -> ContentReader {
        let inner = match (self, payload) {
            (ReaderSource::Plain, Some((file, len))) => {
                ContentReaderInner::Plain(FileReader::with_len_hint(file, len))
            }
            (ReaderSource::Archive { .. }, Some((file, len))) => ContentReaderInner::Inflate(
                Box::new(archive_decoder(FileReader::with_len_hint(file, len), len)),
            ),
            _ => ContentReaderInner::Empty,
        };
        ContentReader { inner }
    }
}

/// The location of the bytes of a file object: the `objects/` directory of
/// the repository or the staging directory of a transaction.
/// [`FileObject::reader`] opens a new stream from it on each call.
#[derive(Debug, Clone)]
enum ObjectStore {
    /// A loose object under the `objects/` directory of the repository. The
    /// path comes from the checksum and the mode at read time.
    Repo,
    /// An object with a flat name in the staging directory of a transaction,
    /// not published yet. A clone of the handle shares its descriptor, so the
    /// object stays `Clone` and self-contained.
    Staging {
        /// The staging directory that holds the object.
        dir: RepoDir,
        /// The flat staging name of the object (`<hex>.file` or `<hex>.filez`).
        name: String,
    },
}

/// The logical metadata of a file object and a handle to its payload.
///
/// [`Repo::load_file`] and
/// [`StagingTree::read_file`](crate::StagingTree::read_file) give a
/// `FileObject`.
#[derive(Debug, Clone)]
pub struct FileObject {
    repo: Repo,
    checksum: Checksum,
    /// The user id of the owner.
    pub uid: u32,
    /// The group id of the owner.
    pub gid: u32,
    /// The logical `st_mode`, file type bits included.
    pub mode: u32,
    /// The extended attributes of the file.
    pub xattrs: Xattrs,
    /// The kind of the file: a regular file with its size, or a symlink with
    /// its target.
    pub kind: FileKind,
    source: ReaderSource,
    store: ObjectStore,
    /// The fs-verity digest the kernel held for the payload at load time. A
    /// load that does not ask for it leaves `None`.
    kernel_verity: Option<[u8; 32]>,
    /// The size of the object file on disk at load time, in bytes.
    stored_size: u64,
}

impl FileObject {
    /// Returns the checksum of the file object.
    pub fn checksum(&self) -> &Checksum {
        &self.checksum
    }

    /// Returns `true` if the object is a symlink.
    pub fn is_symlink(&self) -> bool {
        matches!(self.kind, FileKind::Symlink { .. })
    }

    /// Returns the logical header of the object.
    ///
    /// The checksum of the object covers this form of the header, so a new
    /// computation of the checksum starts from it. The mode checks also read
    /// it.
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

    /// Returns the logical metadata of the object: the uid, gid, mode, and
    /// xattrs that a write of this object applies. The mode checks read it.
    pub(crate) fn meta(&self) -> FileMeta {
        FileMeta {
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
            xattrs: self.xattrs.clone(),
        }
    }

    /// Opens an async reader over the payload of the file.
    ///
    /// The reader streams the payload in bounded chunks. Each call opens the
    /// object file again and gives a stream from the start of the payload. A
    /// symlink has no payload, so its reader gives no bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the object file or its fan-out
    ///   directory `objects/<xx>` is absent.
    /// - [`Error::InvalidFormat`] if a symlink is at `objects/<xx>` or at the
    ///   object path, or if the object file is not a regular file. The
    ///   message is `<path> passes through a symlink; ostrya refuses a symlink
    ///   in the repository` or `<path> is not a regular file`. The open of a
    ///   FIFO does not wait for a writer.
    /// - [`Error::InvalidFormat`] with the message `<path> is not a directory`
    ///   if `objects/<xx>` is not a directory.
    /// - [`Error::Io`] for each other failure of the open.
    pub async fn reader(&self) -> Result<ContentReader> {
        let payload = match &self.source {
            ReaderSource::None => None,
            ReaderSource::Plain => {
                let len = match self.kind {
                    FileKind::Regular { size } => size,
                    FileKind::Symlink { .. } => 0,
                };
                Some((self.open_payload(0, false).await?.0, len))
            }
            ReaderSource::Archive { payload_offset } => {
                Some(self.open_payload(*payload_offset, true).await?)
            }
        };
        Ok(self.source.reader_over(payload))
    }

    /// Writes the payload of the file into `writer` in bounded chunks.
    ///
    /// The method holds no whole payload in memory, whatever the size of the
    /// file. A symlink has no payload and writes nothing.
    ///
    /// The method does not flush `writer`, and the caller owns the flush. A
    /// sink can take many payloads, and a framing or compressing sink emits
    /// bytes on a flush. If the writer buffers, as the async file over a
    /// descriptor does, the caller flushes it once after the last write.
    ///
    /// # Errors
    ///
    /// - The errors of the open of [`reader`](FileObject::reader).
    /// - [`Error::Io`] if a read of the payload or a write to `writer` fails.
    ///   An `archive` payload that does not inflate also gives this variant.
    pub async fn write_to<W: futures_io::AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let reader = self.reader().await?;
        crate::write::copy_stream(reader, writer)
            .await
            .map_err(Error::Io)
    }

    /// Returns the fs-verity digest that the kernel held for the payload at
    /// load time, for a load that asked for it.
    ///
    /// Only an object whose whole file is the raw payload has one. An
    /// `archive` object stores a header and compressed bytes, so the digest
    /// of its file is not the digest of its content. The descriptor must name
    /// SHA-256, 4096-byte blocks, no salt, and a data size equal to the
    /// payload size.
    ///
    /// Every error and every mismatch gives `None`, and the caller then
    /// computes the digest from the payload. The kernel read takes no payload
    /// byte, so it does not find damage to the data or the verity metadata of
    /// a sealed object. `fsck` is the check for object integrity.
    pub(crate) fn kernel_fs_verity(&self) -> Option<[u8; 32]> {
        self.kernel_verity
    }

    /// Returns the size of the object on disk at load time, in bytes: the size
    /// that the `statx` of the load gave. In an `archive` repository it is the
    /// size of the `.filez` file.
    pub(crate) fn stored_size(&self) -> u64 {
        self.stored_size
    }

    /// Returns the reader over `payload`, the object file that a load with
    /// [`Repo::open_file`] kept open. The reader is the one that
    /// [`reader`](FileObject::reader) gives. `None` gives a reader with no
    /// bytes.
    pub(crate) fn reader_over(&self, payload: Option<Payload>) -> ContentReader {
        self.source.reader_over(payload)
    }

    /// Returns the directory handle and the path of the payload.
    ///
    /// The path is a loose path under `objects/`, or the flat staging name of
    /// an object that is not published yet.
    fn payload_location(&self) -> (RepoDir, String) {
        match &self.store {
            ObjectStore::Repo => {
                let path = loose_path(&self.checksum, ObjectType::File, self.repo.mode());
                (self.repo.objects().clone(), path)
            }
            ObjectStore::Staging { dir, name } => (dir.clone(), name.clone()),
        }
    }

    /// Opens the object file on the blocking pool, positioned after its first
    /// `payload_offset` bytes. If `measure` is set, the same pool call also
    /// gives the number of bytes from there to the end of the file. If it is
    /// clear, that number is 0.
    ///
    /// The open is [`RepoDir::open_regular_at`]: it follows no symlink at
    /// `objects/<xx>` or at the object path, also if the symlink replaced the
    /// directory or the file after the load, and it refuses an object file
    /// that is not a regular file. The open of a FIFO does not wait for a
    /// writer. An absent entry gives [`Error::ObjectNotFound`].
    async fn open_payload(&self, payload_offset: u64, measure: bool) -> Result<Payload> {
        let (dir, path) = self.payload_location();
        let checksum = self.checksum;
        ostrya_rt::unblock(move || {
            let Opened { file, stat } = dir
                .open_regular_at(&path, payload_offset)
                .map_err(|e| e.into_object_error(&checksum, ObjectType::File))?;
            let len = if measure {
                stat.size.saturating_sub(payload_offset)
            } else {
                0
            };
            Ok((file, len))
        })
        .await
    }
}

/// Methods that read file objects.
impl Repo {
    /// Loads a file object from the object store, with a handle to its payload.
    ///
    /// The [`FileObject`] holds the logical metadata (uid, gid, mode, and
    /// xattrs) and the [`FileKind`] of the object. The repository mode sets
    /// where the load reads these values. A regular-file payload streams
    /// through [`FileObject::reader`] in bounded chunks, and no load holds the
    /// whole payload in memory.
    ///
    /// # Storage by mode
    ///
    /// - `archive`: the `.filez` object holds a framed `(tuuuusa(ayay))`
    ///   header, then the payload as raw DEFLATE.
    /// - `bare`: the object is a real inode. The metadata comes from `stat`
    ///   and from the xattrs of the inode. A symlink is a real symlink.
    /// - `bare-user`: the object is a regular file. The `user.ostreemeta`
    ///   xattr holds the metadata as `(uuua(ayay))`. A symlink is a regular
    ///   file whose content is the target and one NUL byte.
    /// - `bare-user-only`: the metadata is the canonical inode mode. The uid
    ///   and the gid read back as 0, and the object has no xattrs. A symlink
    ///   is a real symlink.
    /// - `bare-user-shared`: the load is the same as in `bare-user`. The load
    ///   does not read the fixed inode mode that a writer applies, so one
    ///   loader serves both modes.
    /// - `bare-user-private`: the load is the same as in `bare-user`. Each
    ///   content object has the inode mode 0400, so the load must run as the
    ///   owner of the object or with privilege.
    /// - `bare-split-xattrs`: the storage is bare (the real uid, gid, and
    ///   mode, real symlinks, and no `user.ostreemeta`). A separate
    ///   `.file-xattrs` object holds the logical xattrs. The load reaches it
    ///   through the `.file-xattrs-link` entry that the file checksum names.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the object is not in the object store.
    /// - [`Error::InvalidFormat`] if the object does not have the form of the
    ///   repository mode:
    ///   - the framing padding of an `archive` object is not zero
    ///   - the header of an `archive` object is larger than 1 MiB
    ///   - a `bare-user` object has no `user.ostreemeta` xattr
    ///   - a `bare-split-xattrs` object has no `.file-xattrs-link`
    ///   - a `bare`, `bare-user-only`, or `bare-split-xattrs` object is not a
    ///     regular file or a symlink, with the message `<path> is not a
    ///     regular file`
    ///   - an `archive`, `bare-user`, `bare-user-shared`, or
    ///     `bare-user-private` object, or a `.file-xattrs-link`, is not a
    ///     regular file, with the same message
    ///   - a symlink target is not valid UTF-8, or has an interior NUL
    ///   - the content of a `bare-user` symlink object is larger than 65536
    ///     bytes, with the message `<path> is larger than its cap of 65536
    ///     bytes`
    ///   - a `.file-xattrs-link` is larger than [`MAX_METADATA_SIZE`]
    /// - [`Error::InvalidFormat`] if a symlink is at `objects/<xx>`, at a
    ///   `.file-xattrs-link`, or at the object path in the `archive`,
    ///   `bare-user`, `bare-user-shared`, and `bare-user-private` modes. The
    ///   message is `<path> passes through a symlink; ostrya refuses a
    ///   symlink in the repository`. In the other modes, a symlink at the
    ///   object path is a symlink object, and the load reads its target.
    /// - [`Error::Core`] if the file header, the `user.ostreemeta` value, or
    ///   the xattr set of a `.file-xattrs-link` does not parse.
    /// - [`Error::Io`] of kind [`InvalidData`](std::io::ErrorKind::InvalidData)
    ///   if the xattrs of a `bare` object do not make a valid set. An xattr
    ///   name need not be UTF-8.
    /// - [`Error::Io`] for other failures of the file system.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> ostrya::Result<()> {
    /// use futures_lite::AsyncReadExt;
    ///
    /// let repo = ostrya::Repo::open("/srv/repo".as_ref()).await?;
    /// let checksum = ostrya::Checksum::from_hex(
    ///     "8c2c0bd09f23a6d4e2bf4e7a4b4a2d1e0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c",
    /// )?;
    /// let file = repo.load_file(&checksum).await?;
    /// if let ostrya::FileKind::Regular { size } = file.kind {
    ///     let mut reader = file.reader().await?;
    ///     let mut chunk = vec![0u8; 64 * 1024];
    ///     let mut total = 0u64;
    ///     loop {
    ///         let n = reader.read(&mut chunk).await?;
    ///         if n == 0 {
    ///             break;
    ///         }
    ///         total += n as u64;
    ///     }
    ///     assert_eq!(total, size);
    /// }
    /// # Ok(()) }
    /// ```
    pub async fn load_file(&self, checksum: &Checksum) -> Result<FileObject> {
        self.load_file_with(checksum, false).await
    }

    /// Loads a file object as [`Repo::load_file`] does. If `measure` is set,
    /// it also reads the fs-verity digest that the kernel holds for the
    /// payload. The read uses the descriptor and the blocking-pool call of the
    /// metadata load. See [`FileObject::kernel_fs_verity`].
    pub(crate) async fn load_file_with(
        &self,
        checksum: &Checksum,
        measure: bool,
    ) -> Result<FileObject> {
        let loaded = self.load_loose(checksum, measure, false).await?;
        Ok(self.file_object(checksum, loaded).0)
    }

    /// Loads a file object as [`Repo::load_file`] does, and keeps the object
    /// file of a regular file open at the start of its payload.
    ///
    /// The second value is that file and the number of bytes on disk from
    /// there to the end, or `None` for a symlink.
    /// [`FileObject::reader_over`] gives the reader over it, so the object
    /// opens once.
    pub(crate) async fn open_file(
        &self,
        checksum: &Checksum,
    ) -> Result<(FileObject, Option<Payload>)> {
        let loaded = self.load_loose(checksum, false, true).await?;
        Ok(self.file_object(checksum, loaded))
    }

    /// Runs [`open_file`](Repo::open_file) on the calling thread. If `measure`
    /// is set, the load also reads the fs-verity digest that the kernel holds
    /// for the payload, as [`load_file_with`](Repo::load_file_with) does.
    pub(crate) fn open_file_blocking(
        &self,
        checksum: &Checksum,
        measure: bool,
    ) -> Result<(FileObject, Option<Payload>)> {
        let mode = self.mode();
        let path = loose_path(checksum, ObjectType::File, mode);
        let loaded = load_by_mode(self.objects(), &path, mode, measure, true)
            .map_err(|e| e.into_error(checksum))?;
        Ok(self.file_object(checksum, loaded))
    }

    /// Runs the loader of the repository mode on the blocking pool for the
    /// loose file object `checksum`. `measure` and `keep` are the flags of
    /// [`load_by_mode`].
    async fn load_loose(&self, checksum: &Checksum, measure: bool, keep: bool) -> Result<Loaded> {
        let mode = self.mode();
        let path = loose_path(checksum, ObjectType::File, mode);
        let repo = self.clone();
        let key = *checksum;
        ostrya_rt::unblock(move || {
            load_by_mode(repo.objects(), &path, mode, measure, keep).map_err(|e| e.into_error(&key))
        })
        .await
    }

    /// Returns the sum of the content bytes of the file objects `checksums`.
    ///
    /// The sum counts the bytes that a push session reads from
    /// [`Repo::open_file`] or from the stored file. The function runs on the
    /// calling thread. If `stored` is set, each object of an `archive`
    /// repository counts the size of its stored `.filez`, which the session
    /// sends unchanged. Otherwise each object counts the uncompressed size of
    /// its payload, and a symlink counts 0.
    ///
    /// The pass reads no payload byte:
    ///
    /// - A stored `.filez` takes one [`RepoDir::lstat`].
    /// - An `archive` object without `stored` takes an open and the read of
    ///   its file header.
    /// - A `bare-user` object is a regular file, also for a symlink. It takes
    ///   an open and the read of its `user.ostreemeta` xattr.
    /// - An object of the other modes takes one [`RepoDir::lstat`].
    ///
    /// Each path resolves as the loads of the session resolve it: relative to
    /// `objects/`, with no symlink followed at any component. The errors are
    /// those of the loads: an entry of a type that the mode does not store
    /// fails the pass.
    #[cfg_attr(not(feature = "push"), allow(dead_code))]
    pub(crate) fn content_size_blocking(
        &self,
        checksums: &[Checksum],
        stored: bool,
    ) -> Result<u64> {
        let mut total = 0u64;
        for checksum in checksums {
            total = total.saturating_add(self.object_content_size_blocking(checksum, stored)?);
        }
        Ok(total)
    }

    /// Returns the content bytes of the file object `checksum`, as
    /// [`content_size_blocking`](Repo::content_size_blocking) counts them.
    #[cfg_attr(not(feature = "push"), allow(dead_code))]
    pub(crate) fn object_content_size_blocking(
        &self,
        checksum: &Checksum,
        stored: bool,
    ) -> Result<u64> {
        let mode = self.mode();
        let dir = self.objects();
        let path = loose_path(checksum, ObjectType::File, mode);
        let size = (|| -> std::result::Result<u64, LoadError> {
            Ok(match mode {
                RepoMode::Archive if stored => {
                    let stat = dir.lstat(&path)?;
                    if stat.file_type == FileType::RegularFile {
                        stat.size
                    } else {
                        // The open refuses the type with the error of a load.
                        dir.open_regular(&path)?.stat.size
                    }
                }
                RepoMode::Archive => match load_archive(dir, &path, false)?.kind {
                    FileKind::Regular { size } => size,
                    FileKind::Symlink { .. } => 0,
                },
                RepoMode::BareUser | RepoMode::BareUserShared | RepoMode::BareUserPrivate => {
                    bare_user_payload_size(dir, &path)?
                }
                RepoMode::Bare | RepoMode::BareUserOnly | RepoMode::BareSplitXattrs => {
                    let stat = dir.lstat(&path)?;
                    match stat.file_type {
                        FileType::Symlink => 0,
                        FileType::RegularFile => stat.size,
                        // The open refuses the type with the error of a load.
                        _ => match dir.open_object(&path)? {
                            ObjectEntry::Regular(opened) => opened.stat.size,
                            ObjectEntry::Symlink(_) => 0,
                        },
                    }
                }
            })
        })();
        size.map_err(|e| e.into_error(checksum))
    }

    /// Loads a file object as [`Repo::open_file`] does, on the calling
    /// thread, and gives a typed outcome.
    ///
    /// The load follows no symlink at any component of the object path, as
    /// each load does. In a mode that stores a symlink as a symlink, the load
    /// reads a symlink object with `readlinkat`. An absent object, and an
    /// entry at `objects/<xx>` that is not a directory, give
    /// [`Contained::NotFound`]. A symlink on the object path gives
    /// [`Contained::Refused`]. Each other failure of the load is an error.
    /// The caller runs the function on the blocking pool and takes the result
    /// with [`Repo::contained_file`].
    pub(crate) fn load_contained_blocking(
        &self,
        checksum: &Checksum,
    ) -> Result<Contained<ContainedFile>> {
        let mode = self.mode();
        let path = loose_path(checksum, ObjectType::File, mode);
        match load_by_mode(self.objects(), &path, mode, false, true) {
            Ok(loaded) => Ok(Contained::Found(ContainedFile { loaded })),
            Err(e) => e.into_contained(checksum),
        }
    }

    /// Returns the file object and the payload reader of a
    /// [`Repo::load_contained_blocking`] load.
    pub(crate) fn contained_file(
        &self,
        checksum: &Checksum,
        contained: ContainedFile,
    ) -> (FileObject, ContentReader) {
        let (file, payload) = self.file_object(checksum, contained.loaded);
        let reader = file.reader_over(payload);
        (file, reader)
    }

    /// Checks on the calling thread that the content object `checksum` is
    /// present, and reads nothing of it.
    ///
    /// The check uses the path rules and the outcomes of
    /// [`Repo::load_contained_blocking`]. It reads no xattr and no byte of
    /// the payload. It opens a regular-file object, so a file that the
    /// process cannot read fails as the load fails.
    ///
    /// In a mode that stores a symlink as a symlink, a symlink object passes.
    /// In the other modes, it gives [`Contained::Refused`]. In
    /// `bare-split-xattrs`, an open of the `.file-xattrs-link` beside the
    /// object follows the open of the object. An absent object gives
    /// [`Contained::NotFound`], as the load does. A symlink at the link gives
    /// [`Contained::Refused`], and a missing link fails as the load fails.
    pub(crate) fn probe_contained_blocking(&self, checksum: &Checksum) -> Result<Contained<()>> {
        let mode = self.mode();
        let path = loose_path(checksum, ObjectType::File, mode);
        let objects = self.objects();
        let probed = (|| -> std::result::Result<(), LoadError> {
            match mode {
                RepoMode::Bare | RepoMode::BareUserOnly => {
                    objects.open_object(&path)?;
                }
                RepoMode::BareSplitXattrs => {
                    objects.open_object(&path)?;
                    probe_split_xattrs_link(objects, &path)?;
                }
                RepoMode::Archive
                | RepoMode::BareUser
                | RepoMode::BareUserShared
                | RepoMode::BareUserPrivate => {
                    objects.open_regular(&path)?;
                }
            }
            Ok(())
        })();
        match probed {
            Ok(()) => Ok(Contained::Found(())),
            Err(e) => e.into_contained(checksum),
        }
    }

    /// Returns the file object of a load of the loose object `checksum`, and
    /// the payload that the load kept.
    fn file_object(&self, checksum: &Checksum, loaded: Loaded) -> (FileObject, Option<Payload>) {
        let file = FileObject {
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
            stored_size: loaded.stored_size,
        };
        (file, loaded.payload)
    }
}

/// Loads a file object by its flat name from the staging directory of a
/// transaction.
///
/// The staged-first lookup uses it to read the objects of the current
/// transaction before they are published into `objects/`. The metadata decodes
/// per mode, as for a loose object. The payload streams from the staging
/// directory. `measure` is the flag of [`Repo::load_file_with`].
pub(crate) async fn load_staged_file(
    repo: &Repo,
    staging: &RepoDir,
    checksum: &Checksum,
    measure: bool,
) -> Result<FileObject> {
    let mode = repo.mode();
    let name = crate::write::flat_name(checksum, ObjectType::File, mode);
    let key = *checksum;
    let load_dir = staging.clone();
    let load_name = name.clone();
    let loaded = ostrya_rt::unblock(move || {
        load_by_mode(&load_dir, &load_name, mode, measure, false).map_err(|e| e.into_error(&key))
    })
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
        store: ObjectStore::Staging {
            dir: staging.clone(),
            name,
        },
        kernel_verity: loaded.kernel_verity,
        stored_size: loaded.stored_size,
    })
}

/// The outcome of [`Repo::load_contained_blocking`] and of
/// [`Repo::probe_contained_blocking`].
pub(crate) enum Contained<T> {
    /// The object is present. The payload is the result of the load or of the
    /// probe.
    Found(T),
    /// The object is absent.
    NotFound,
    /// A symlink is on the object path.
    Refused,
}

/// The result of [`Repo::load_contained_blocking`], which keeps its payload.
pub(crate) struct ContainedFile {
    /// The fields of the load and the open payload.
    loaded: Loaded,
}

/// The error of the loader of one mode.
///
/// An error of a file system operation on the object path stays an
/// [`FsError`], so the caller selects its result: [`LoadError::into_error`]
/// gives the error of a load, and [`LoadError::into_contained`] gives the
/// outcome of the archive view.
enum LoadError {
    /// An error of a file system operation on the object path.
    Fs(FsError),
    /// Each other error.
    Other(Error),
}

impl From<FsError> for LoadError {
    fn from(err: FsError) -> LoadError {
        LoadError::Fs(err)
    }
}

impl From<Error> for LoadError {
    fn from(err: Error) -> LoadError {
        LoadError::Other(err)
    }
}

impl From<io::Error> for LoadError {
    fn from(err: io::Error) -> LoadError {
        LoadError::Other(Error::Io(err))
    }
}

impl From<ostrya_core::Error> for LoadError {
    fn from(err: ostrya_core::Error) -> LoadError {
        LoadError::Other(err.into())
    }
}

impl LoadError {
    /// Converts the error of a load of the file object `checksum` into an
    /// [`Error`]. An absent entry gives [`Error::ObjectNotFound`].
    fn into_error(self, checksum: &Checksum) -> Error {
        match self {
            LoadError::Fs(err) => err.into_object_error(checksum, ObjectType::File),
            LoadError::Other(err) => err,
        }
    }

    /// Converts the error of a load of the file object `checksum` into the
    /// outcome of [`Repo::load_contained_blocking`].
    ///
    /// An absent entry, and an entry that is not a directory at the place of
    /// the fan-out directory, give [`Contained::NotFound`]. A symlink on the
    /// path gives [`Contained::Refused`]. Each other error stays an error.
    fn into_contained<T>(self, checksum: &Checksum) -> Result<Contained<T>> {
        match self {
            LoadError::Fs(
                FsError::Absent { .. }
                | FsError::Invalid {
                    reason: Reason::NotDirectory,
                    ..
                },
            ) => Ok(Contained::NotFound),
            LoadError::Fs(FsError::Invalid {
                reason: Reason::Symlink,
                ..
            }) => Ok(Contained::Refused),
            other => Err(other.into_error(checksum)),
        }
    }
}

/// The fields that the loader of one mode produces, before a [`FileObject`]
/// is built from them.
struct Loaded {
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: Xattrs,
    kind: FileKind,
    source: ReaderSource,
    kernel_verity: Option<[u8; 32]>,
    /// The size of the object on disk, from the `statx` of the load.
    stored_size: u64,
    /// The object file of a regular file, at the start of its payload, and the
    /// number of bytes on disk from there to the end. Only a load that keeps
    /// the payload sets it.
    payload: Option<Payload>,
}

/// An object file at the start of its payload, and the number of bytes on
/// disk from there to the end.
pub(crate) type Payload = (File, u64);

/// Calls the loader of the repository mode.
///
/// `object_path` locates the object below `dir`: a loose path below the
/// `objects/` handle, or a flat name below a staging handle. `measure` asks a
/// raw-payload loader for the fs-verity digest of the kernel. An `archive`
/// object never has one. `keep` asks the loader of a regular file to keep its
/// object file open at the payload. With neither flag, the `bare-user-only`
/// and `bare-split-xattrs` loaders do not open a regular file.
///
/// Each operation is a primitive of [`RepoDir`], so the loaders follow no
/// symlink at any component of the path, and refuse an entry of a type that
/// the mode does not store.
fn load_by_mode(
    dir: &RepoDir,
    object_path: &str,
    mode: RepoMode,
    measure: bool,
    keep: bool,
) -> std::result::Result<Loaded, LoadError> {
    match mode {
        RepoMode::Archive => load_archive(dir, object_path, keep),
        RepoMode::BareUser | RepoMode::BareUserShared | RepoMode::BareUserPrivate => {
            load_bare_user(dir, object_path, measure, keep)
        }
        RepoMode::Bare => load_bare(dir, object_path, measure, keep),
        RepoMode::BareUserOnly => load_bare_user_only(dir, object_path, measure, keep),
        RepoMode::BareSplitXattrs => load_bare_split_xattrs(dir, object_path, measure, keep),
    }
}

/// Returns the fs-verity digest that the kernel holds for the raw-payload
/// object `file` with the status `stat`, if `measure` is set and the status
/// reports the object as sealed. Each other case gives `None`.
fn kernel_digest(file: &File, stat: &Stat, measure: bool) -> Option<[u8; 32]> {
    if !(measure && stat.verity) {
        return None;
    }
    repo_fs::verity_digest(file.as_fd(), stat.size)
}

/// Returns the target of a symlink object, from the bytes of the target.
fn link_target(target: Vec<u8>) -> Result<String> {
    String::from_utf8(target)
        .map_err(|_| Error::InvalidFormat("symlink target is not valid UTF-8".into()))
}

/// Returns the target of a `bare-user` symlink from its object content, which
/// is the target and one NUL byte.
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

/// Returns the logical header of the `bare-user` object open as `file`, from
/// its `user.ostreemeta` xattr.
fn bare_user_header(file: &File) -> std::result::Result<FileHeader, LoadError> {
    let meta = repo_fs::xattr(file.as_fd(), "user.ostreemeta")?.ok_or_else(|| {
        Error::InvalidFormat("bare-user .file is missing its user.ostreemeta xattr".into())
    })?;
    Ok(FileHeader::parse_stat_metadata(&meta)?)
}

fn load_archive(dir: &RepoDir, path: &str, keep: bool) -> std::result::Result<Loaded, LoadError> {
    use std::io::Read;

    let Opened { mut file, stat } = dir.open_regular(path)?;

    let mut prefix = [0u8; 8];
    file.read_exact(&mut prefix)?;
    if prefix[4..8] != [0u8; 4] {
        return Err(Error::InvalidFormat("content framing padding is not zero".into()).into());
    }
    let header_len = u32::from_be_bytes(prefix[..4].try_into().unwrap()) as u64;
    if header_len > MAX_FILE_HEADER_SIZE {
        return Err(Error::InvalidFormat("content header exceeds the size cap".into()).into());
    }
    let mut header_bytes = vec![0u8; header_len as usize];
    file.read_exact(&mut header_bytes)?;
    let (header, uncompressed_size) = FileHeader::parse_archive(&header_bytes)?;

    // The reads stop at the end of the header, so the file is at the start
    // of the payload.
    let (kind, source, payload) = if header.is_symlink() {
        (
            FileKind::Symlink {
                target: header.symlink_target,
            },
            ReaderSource::None,
            None,
        )
    } else {
        (
            FileKind::Regular {
                size: uncompressed_size,
            },
            ReaderSource::Archive {
                payload_offset: 8 + header_len,
            },
            keep.then(|| (file, stat.size.saturating_sub(8 + header_len))),
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
        stored_size: stat.size,
        payload,
    })
}

/// Loads a `bare-user` object.
///
/// The object is a regular file. A symlink object holds its target as
/// content, and the loader reads that content with a second open, with a cap
/// of 64 KiB.
fn load_bare_user(
    dir: &RepoDir,
    path: &str,
    measure: bool,
    keep: bool,
) -> std::result::Result<Loaded, LoadError> {
    let Opened { file, stat } = dir.open_regular(path)?;
    let header = bare_user_header(&file)?;

    let stored_size = stat.size;
    let (kind, source, kernel_verity, payload) = if header.is_symlink() {
        drop(file);
        let content = dir.read_capped(path, SYMLINK_READ_CAP)?;
        (
            FileKind::Symlink {
                target: symlink_target_from_content(&content)?,
            },
            ReaderSource::None,
            None,
            None,
        )
    } else {
        let size = stat.size;
        let kernel_verity = kernel_digest(&file, &stat, measure);
        (
            FileKind::Regular { size },
            ReaderSource::Plain,
            kernel_verity,
            keep.then_some((file, size)),
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
        stored_size,
        payload,
    })
}

/// Returns the payload size of the `bare-user` object at `path`: its length,
/// or 0 if its `user.ostreemeta` xattr names a symlink. The function does not
/// read the object content.
fn bare_user_payload_size(dir: &RepoDir, path: &str) -> std::result::Result<u64, LoadError> {
    let Opened { file, stat } = dir.open_regular(path)?;
    if bare_user_header(&file)?.is_symlink() {
        return Ok(0);
    }
    Ok(stat.size)
}

/// A loose object of a mode that stores a symlink as a symlink, as
/// [`bare_entry`] reads it.
enum BareEntry {
    /// A regular file, its status, and the file if the read opened it.
    Regular(Stat, Option<File>),
    /// A symlink, its status, its target, and its xattrs if the read took
    /// them.
    Symlink(Stat, Vec<u8>, Xattrs),
}

/// Reads the loose object at `path` below `dir` in a mode that stores a
/// symlink as a symlink.
///
/// With `open`, the read starts with [`RepoDir::open_object`]. Otherwise it
/// starts with one [`RepoDir::lstat`], so an object that the process cannot
/// read loads. It then opens a regular file only if `measure` is set and the
/// file is sealed with fs-verity. An entry of another type opens as the
/// object, so the open refuses it with its type.
///
/// A symlink gives its status, its target, and with `link_xattrs` its
/// xattrs. An error of the xattr read at the parent directory of a loose
/// object names the object path.
fn bare_entry(
    dir: &RepoDir,
    path: &str,
    open: bool,
    measure: bool,
    link_xattrs: bool,
) -> std::result::Result<BareEntry, LoadError> {
    let opened = if open {
        match dir.open_object(path)? {
            ObjectEntry::Regular(Opened { file, stat }) => {
                return Ok(BareEntry::Regular(stat, Some(file)));
            }
            ObjectEntry::Symlink(target) => Some(target),
        }
    } else {
        None
    };
    let stat = dir.lstat(path)?;
    let target = match opened {
        Some(target) => target,
        None => match stat.file_type {
            FileType::Symlink => dir.read_link(path, LINK_TARGET_CAP)?,
            FileType::RegularFile if !(measure && stat.verity) => {
                return Ok(BareEntry::Regular(stat, None));
            }
            _ => return bare_entry(dir, path, true, measure, link_xattrs),
        },
    };
    let xattrs = if link_xattrs {
        dir.link_xattrs(path)
            .map_err(|e| object_path_error(e, path))?
    } else {
        Xattrs::empty()
    };
    Ok(BareEntry::Symlink(stat, target, xattrs))
}

/// Returns the fields of a symlink object of the bare family with the status
/// `stat`, the target `target`, and the logical `uid`, `gid`, and `xattrs`.
fn symlink_loaded(
    stat: &Stat,
    uid: u32,
    gid: u32,
    xattrs: Xattrs,
    target: Vec<u8>,
) -> std::result::Result<Loaded, LoadError> {
    Ok(Loaded {
        uid,
        gid,
        mode: stat.mode,
        xattrs,
        kind: FileKind::Symlink {
            target: link_target(target)?,
        },
        source: ReaderSource::None,
        kernel_verity: None,
        stored_size: stat.size,
        payload: None,
    })
}

/// Returns the fields of a regular-file object of the bare family with the
/// status `stat` and the logical `uid`, `gid`, and `xattrs`. The whole file
/// is the payload.
///
/// `file` is the object file if the load opened it. `measure` reads the
/// fs-verity digest of the kernel from it, and `keep` keeps it open at the
/// payload.
fn regular_loaded(
    stat: &Stat,
    file: Option<File>,
    uid: u32,
    gid: u32,
    xattrs: Xattrs,
    measure: bool,
    keep: bool,
) -> Loaded {
    Loaded {
        uid,
        gid,
        mode: stat.mode,
        xattrs,
        kind: FileKind::Regular { size: stat.size },
        source: ReaderSource::Plain,
        kernel_verity: file.as_ref().and_then(|f| kernel_digest(f, stat, measure)),
        stored_size: stat.size,
        payload: file.filter(|_| keep).map(|f| (f, stat.size)),
    }
}

fn load_bare(
    dir: &RepoDir,
    path: &str,
    measure: bool,
    keep: bool,
) -> std::result::Result<Loaded, LoadError> {
    // The xattrs of a regular file come from its descriptor, so the load
    // opens the object.
    Ok(match bare_entry(dir, path, true, measure, true)? {
        BareEntry::Symlink(stat, target, xattrs) => {
            symlink_loaded(&stat, stat.uid, stat.gid, xattrs, target)?
        }
        BareEntry::Regular(stat, file) => {
            let xattrs = match &file {
                Some(file) => repo_fs::xattrs(file.as_fd())?,
                None => Xattrs::empty(),
            };
            regular_loaded(&stat, file, stat.uid, stat.gid, xattrs, measure, keep)
        }
    })
}

fn load_bare_user_only(
    dir: &RepoDir,
    path: &str,
    measure: bool,
    keep: bool,
) -> std::result::Result<Loaded, LoadError> {
    // This mode does not keep the uid and the gid, so they read back as 0.
    // The inode carries the canonical mode. The mode stores no xattrs.
    Ok(match bare_entry(dir, path, keep, measure, false)? {
        BareEntry::Symlink(stat, target, _) => {
            symlink_loaded(&stat, 0, 0, Xattrs::empty(), target)?
        }
        BareEntry::Regular(stat, file) => {
            regular_loaded(&stat, file, 0, 0, Xattrs::empty(), measure, keep)
        }
    })
}

fn load_bare_split_xattrs(
    dir: &RepoDir,
    path: &str,
    measure: bool,
    keep: bool,
) -> std::result::Result<Loaded, LoadError> {
    // The storage is bare: the inode carries the logical uid, gid, and mode.
    // A regular file holds the raw payload, and a symlink is a real symlink.
    // The inode holds no xattrs. A separate object holds the logical set, and
    // the `.file-xattrs-link` entry that the file checksum names leads to it.
    //
    // A bare-split-xattrs repository is read-only, and nothing is staged in
    // it. The link is beside the object. Its name is the object name with the
    // suffix `-xattrs-link`, so it resolves below `dir` as the object does.
    let entry = bare_entry(dir, path, keep, measure, false)?;
    let xattrs = load_split_xattrs(dir, path)?;
    Ok(match entry {
        BareEntry::Symlink(stat, target, _) => {
            symlink_loaded(&stat, stat.uid, stat.gid, xattrs, target)?
        }
        BareEntry::Regular(stat, file) => {
            regular_loaded(&stat, file, stat.uid, stat.gid, xattrs, measure, keep)
        }
    })
}

/// Returns the error of a `bare-split-xattrs` object with no
/// `.file-xattrs-link`.
fn missing_xattrs_link() -> LoadError {
    Error::InvalidFormat("bare-split-xattrs .file is missing its .file-xattrs-link".into()).into()
}

/// Reads the logical xattrs of a file object from its `.file-xattrs-link`
/// object.
///
/// The bytes are the GVariant `a(ayay)` xattr set. The link is a hardlink to
/// the shared `.file-xattrs` object. So a read of the bytes at the link name
/// needs no knowledge of the hardlink layout. Every file object has a link (a
/// file with no xattrs links to the shared empty-set object), so a missing
/// link means a malformed repository.
///
/// `file_path` is the path of the `.file` object below `dir`. The read is
/// [`RepoDir::read_capped`] with the metadata cap. The link is a hardlink, so
/// a symlink at its path fails the read, and a FIFO there does not block it.
fn load_split_xattrs(dir: &RepoDir, file_path: &str) -> std::result::Result<Xattrs, LoadError> {
    let path = format!("{file_path}-xattrs-link");
    let bytes = dir
        .read_capped(&path, MAX_METADATA_SIZE)
        .optional()?
        .ok_or_else(missing_xattrs_link)?;
    Ok(Xattrs::from_gvariant(&bytes)?)
}

/// Checks the `.file-xattrs-link` of the `.file` object at `file_path` below
/// `dir`, and reads none of its bytes. The check is one open with
/// [`RepoDir::open_regular`]. The results are the results that
/// [`load_split_xattrs`] gives.
fn probe_split_xattrs_link(dir: &RepoDir, file_path: &str) -> std::result::Result<(), LoadError> {
    let path = format!("{file_path}-xattrs-link");
    dir.open_regular(&path)
        .optional()?
        .map(drop)
        .ok_or_else(missing_xattrs_link)
}

/// An async reader over the payload of a file object.
///
/// A regular file streams from the object store through the async file reader
/// of `ostrya-rt`. The payload is raw in the bare modes, and the reader
/// inflates it from raw DEFLATE in the `archive` mode. The reader holds no
/// whole payload in memory. A symlink has no payload and reads as empty.
///
/// The reader always implements `futures_io::AsyncRead`. Under the `tokio`
/// feature, it also implements `tokio::io::AsyncRead`, so neither runtime
/// backend needs an adapter on the side of the caller. A failure of a read,
/// also of an `archive` payload that does not inflate, is an `io::Error`.
pub struct ContentReader {
    inner: ContentReaderInner,
}

enum ContentReaderInner {
    Empty,
    Plain(FileReader),
    /// The decoder is in a `Box`, because its state is large beside the other
    /// variants.
    Inflate(Box<ArchiveDecoder>),
}

impl ContentReader {
    /// Creates a reader that gives no bytes and holds no descriptor.
    pub(crate) fn empty() -> ContentReader {
        ContentReader {
            inner: ContentReaderInner::Empty,
        }
    }

    /// Reads bytes for both trait families. The file reader of `ostrya-rt`
    /// and the archive decoder implement `futures_io::AsyncRead` under either
    /// backend.
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

/// `FileObject` and `ContentReader` are `Send` and `Sync`, so they can move
/// across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FileObject>();
    assert_send_sync::<ContentReader>();
};

/// Under the `tokio` feature, `ContentReader` also implements the tokio I/O
/// traits, so a caller on tokio needs no adapter.
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

    use super::FileKind;
    use crate::repo_fs::verity_digest;
    use crate::{CreateOptions, FileMeta, Repo, Transaction};
    use ostrya_composefs::FsVerityHasher;
    use ostrya_core::{Checksum, ObjectType, RepoMode, loose_path};
    use ostrya_rt::block_on;

    /// A payload of several verity blocks (more than 4096 bytes).
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

    /// Returns `true` if the file system that holds `dir` accepts fs-verity.
    /// The probe seals a file there.
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

    /// Returns `true` if `statx` reports the content object of `checksum` as
    /// sealed.
    fn sealed(repo: &Repo, checksum: &Checksum) -> bool {
        let path = loose_path(checksum, ObjectType::File, repo.mode());
        repo.objects().lstat(&path).unwrap().verity
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
    /// which equals the digest that ostrya computes from the payload.
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

    /// A bare-user-private object, sealed before the write path sets the inode
    /// mode 0400, yields the kernel's digest.
    #[test]
    fn a_sealed_bare_user_private_object_yields_the_kernel_digest() {
        check_sealed_object_yields_the_kernel_digest(
            "bare-user-private",
            RepoMode::BareUserPrivate,
        );
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
    /// unsealed. An object reported as unsealed is never probed. The kernel
    /// read of a sealed object gives its digest for its own size alone.
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
            let opened = sealed_repo.objects().open_regular(&path).unwrap();
            assert!(opened.stat.verity);
            assert_eq!(
                verity_digest(opened.file.as_fd(), size),
                Some(FsVerityHasher::hash(&payload()))
            );
            assert_eq!(
                verity_digest(opened.file.as_fd(), size + 1),
                None,
                "another size gives no digest"
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
    /// digest of the kernel on the measuring load of the composefs export.
    /// That digest equals the digest streamed from the payload. This is the
    /// proof that the sealed-repository export test in `tests/composefs.rs`
    /// takes the kernel path. The test skips if the fixture is absent or the
    /// file system lacks fs-verity.
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

    /// An object the write path did not seal yields none. This test needs no
    /// verity support, so it runs on every file system.
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

    /// An object sealed with a salt carries a digest that ostree does not use,
    /// so it yields none.
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

    /// Creates a `mode` repository under `dir` as [`repo_in`] does, and writes
    /// [`payload`] with `meta` as one committed content object.
    ///
    /// Returns the repository and the checksum of the object, or the error of
    /// the write.
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
        /// `true` if `statx` reports the inode as sealed.
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
        let stat = repo.objects().lstat(&path).unwrap();
        let fd = rustix::fs::openat(
            repo.objects_fd(),
            path.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .ok();
        let xattr = |name: &str| {
            fd.as_ref()
                .and_then(|fd| crate::repo_fs::xattr(fd.as_fd(), name).unwrap())
        };
        Inode {
            perm: stat.mode & 0o7777,
            uid: stat.uid,
            gid: stat.gid,
            sealed: stat.verity,
            ostreemeta: xattr("user.ostreemeta"),
            seal_xattr: xattr(SEAL_XATTR),
        }
    }

    /// Write each of `metas` into a `mode` repository with `[ex-integrity]
    /// fsverity` set to `fsverity`, and into a second repository with verity
    /// off. Then check that:
    ///
    /// - each write succeeds
    /// - the two objects have the same checksum, inode mode, owner, and xattrs
    /// - only the first object is sealed
    /// - the first object gives the kernel digest where the loader can read it
    ///
    /// Returns the inodes of the sealed side, or `None` if the file system
    /// lacks fs-verity.
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
    /// in a repository with `fsverity=yes`. In all other ways it is the object
    /// that the same write stores with verity off.
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
    /// sealed. An object with no owner-read bit (0200) is also sealed, and the
    /// owner cannot open its stored inode.
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

    /// An owner-writable object is sealed, and its inode is the inode that the
    /// write path stores with verity off:
    ///
    /// - in bare-user, the logical mode with the owner-read bit and the
    ///   logical `user.ostreemeta`
    /// - in archive, the mode 0644
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
    /// without owner write, and a logical xattr is sealed. It carries the
    /// logical owner, mode, and xattr. A set-user-ID mode survives the owner
    /// change. A change of the owner of a file needs root.
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
    /// write and a logical `user.*` xattr, is sealed. It carries the logical
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
    /// stores that value unchanged, with verity off and with verity on. The
    /// test covers an owner that is the writer, and a foreign owner with a
    /// set-user-ID mode and a `user.*` xattr. The kernel removes
    /// `security.capability` when the owner of a regular file changes, so the
    /// write sets the xattrs after the owner. A write of the xattr and a change
    /// of the owner need root.
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
                    let stored = crate::repo_fs::xattr(fd.as_fd(), "security.capability").unwrap();
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
    /// The umask is a property of the process, and the tests of this binary
    /// run in parallel threads, so the write goes to a child. The child is this
    /// test binary, re-executed for this test alone. The child sets the umask
    /// only around the write, because the staging and fanout directories that
    /// the transaction creates need owner write.
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
    /// which writes under `dir`.
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

#[cfg(test)]
mod content_size_tests {
    use std::path::Path;

    use ostrya_core::{Checksum, ObjectType, RepoMode, loose_path};
    use ostrya_rt::block_on;

    use crate::repo_fs::TestDir;
    use crate::{CreateOptions, Error, Repo};

    /// The text that follows the path in the refusal of a symlink in a
    /// repository.
    const SYMLINK_TEXT: &str =
        "passes through a symlink; ostrya refuses a symlink in the repository";

    /// The kinds of entry that the test puts at an object path.
    #[derive(Debug, Clone, Copy)]
    enum Kind {
        Symlink,
        Fifo,
    }

    /// Creates a `mode` repository under `dir`, puts an entry of `kind` at the
    /// path of a file object, and gives the result of the content size of
    /// that object, with the path of the object relative to the repository.
    fn size_of_entry(dir: &Path, mode: RepoMode, kind: Kind, stored: bool) -> (Error, String) {
        let root = dir.join(format!("{mode:?}-{kind:?}-{stored}"));
        let repo = block_on(Repo::create(&root, CreateOptions::new(mode))).unwrap();
        let checksum = Checksum::from_hex(&format!("ab{}", "c".repeat(62))).unwrap();
        let rel = loose_path(&checksum, ObjectType::File, mode);
        let path = root.join("objects").join(&rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        match kind {
            Kind::Symlink => std::os::unix::fs::symlink("../../config", &path).unwrap(),
            Kind::Fifo => rustix::fs::mknodat(
                rustix::fs::CWD,
                &path,
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap(),
        }
        let err = repo.content_size_blocking(&[checksum], stored).unwrap_err();
        (err, format!("objects/{rel}"))
    }

    /// The content size refuses a symlink where the mode stores a regular
    /// file, and a FIFO in each mode, with the error of a load. In a mode that
    /// stores a symlink as a symlink, a symlink object counts 0.
    #[test]
    fn content_size_refuses_a_type_that_the_mode_does_not_store() {
        let dir = TestDir::new("content-size-type");
        let cases = [
            (RepoMode::Archive, Kind::Symlink, true, SYMLINK_TEXT),
            (RepoMode::Archive, Kind::Fifo, true, "is not a regular file"),
            (
                RepoMode::Archive,
                Kind::Fifo,
                false,
                "is not a regular file",
            ),
            (RepoMode::BareUser, Kind::Symlink, false, SYMLINK_TEXT),
            (
                RepoMode::BareUser,
                Kind::Fifo,
                false,
                "is not a regular file",
            ),
            (
                RepoMode::BareUserOnly,
                Kind::Fifo,
                false,
                "is not a regular file",
            ),
            (RepoMode::Bare, Kind::Fifo, false, "is not a regular file"),
        ];
        for (mode, kind, stored, text) in cases {
            let (err, path) = size_of_entry(dir.path(), mode, kind, stored);
            match err {
                Error::InvalidFormat(m) => {
                    assert_eq!(m, format!("{path} {text}"), "{mode:?} {kind:?} {stored}")
                }
                other => panic!("{mode:?} {kind:?} {stored}: {other}"),
            }
        }

        let root = dir.path().join("buo-link");
        let repo = block_on(Repo::create(
            &root,
            CreateOptions::new(RepoMode::BareUserOnly),
        ))
        .unwrap();
        let checksum = Checksum::from_hex(&format!("ab{}", "d".repeat(62))).unwrap();
        let rel = loose_path(&checksum, ObjectType::File, RepoMode::BareUserOnly);
        let path = root.join("objects").join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("target", &path).unwrap();
        assert_eq!(repo.content_size_blocking(&[checksum], false).unwrap(), 0);
    }
}
