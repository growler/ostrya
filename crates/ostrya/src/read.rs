//! Reads of metadata objects and of the state of a commit.
//!
//! The format caps the size of a metadata object: a commit, a dirtree, a
//! dirmeta, or detached commit metadata. A load reads the whole object into
//! memory and parses it with the `ostrya-core` object model.
//! [`MetadataReader`] streams the same bytes to a caller that copies them to a
//! sink. The methods of the [`file`](mod@crate::file) module read file
//! objects and stream their payload.
//!
//! The entry points are methods of [`Repo`]:
//!
//! - [`load_commit`](Repo::load_commit),
//!   [`load_commit_with_bytes`](Repo::load_commit_with_bytes),
//!   [`load_dirtree`](Repo::load_dirtree),
//!   [`load_dirmeta`](Repo::load_dirmeta),
//!   [`load_variant`](Repo::load_variant), and
//!   [`load_object_bytes`](Repo::load_object_bytes) load a metadata object.
//! - [`metadata_reader`](Repo::metadata_reader) opens a [`MetadataReader`].
//! - [`commit_state`](Repo::commit_state) and
//!   [`commit_sizes`](Repo::commit_sizes) read the state of a commit.
//! - [`has_object`](Repo::has_object) checks if a loose object exists.
//!
//! Each method is an `async fn` and runs its system calls on the blocking
//! pool. If an object is not in the object store, a load returns
//! [`Error::ObjectNotFound`].

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use ostrya_core::{
    Checksum, Commit, DirMeta, DirTree, ObjectType, Type, Value, from_bytes, loose_path,
};
use ostrya_rt::FileReader;

use crate::error::{Error, Result};
use crate::object::MAX_METADATA_SIZE;
use crate::repo::Repo;
use crate::repo_fs::{FsError, FsResultExt, Opened, Reason};

/// The object totals that the `ostree.sizes` metadata of a commit states.
///
/// Each `*_needed` field counts only the recorded objects that are not in the
/// object store. A commit holds the `ostree.sizes` key only if its writer
/// asked for the key. For a commit without the key,
/// [`commit_sizes`](Repo::commit_sizes) returns `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommitSizes {
    /// The on-disk (compressed) size in bytes of all recorded objects.
    pub compressed_total: u64,
    /// The on-disk size in bytes of the recorded objects that are not in the
    /// object store.
    pub compressed_needed: u64,
    /// The uncompressed size in bytes of all recorded objects.
    pub unpacked_total: u64,
    /// The uncompressed size in bytes of the recorded objects that are not in
    /// the object store.
    pub unpacked_needed: u64,
    /// The number of objects that the metadata records.
    pub objects_total: u64,
    /// The number of recorded objects that are not in the object store.
    pub objects_needed: u64,
}

/// The completeness state of a commit in the object store.
///
/// A commit is [`Partial`](CommitState::Partial) while the marker
/// `state/<checksum>.commitpartial` exists. A pull writes the marker before
/// all objects of the commit are local. The pull removes the marker when the
/// commit is complete. [`Repo::pull_local`] states the full rules of the
/// marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitState {
    /// The state of a commit that has no `.commitpartial` marker.
    ///
    /// A complete commit has this state. [`commit_state`](Repo::commit_state)
    /// does not check that the objects of the commit are present.
    Normal,
    /// The state of a commit that has a `.commitpartial` marker.
    ///
    /// Objects of the commit can be missing.
    Partial,
}

/// Methods that read metadata objects and the state of a commit.
impl Repo {
    /// Loads the serialized bytes of a metadata object.
    ///
    /// A borrowed view, for example
    /// [`DirTreeRef`](ostrya_core::DirTreeRef), can parse the returned
    /// buffer. The load holds the whole object in memory, so it is for
    /// metadata objects only. The format caps their size at
    /// [`MAX_METADATA_SIZE`] bytes. The load does not verify the checksum of
    /// the bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the object is not in the object store.
    /// - [`Error::InvalidFormat`] with the message `<path> is larger than its
    ///   cap of 134217728 bytes` if the object is larger than
    ///   [`MAX_METADATA_SIZE`]. The load also gives this error if the file
    ///   grows past the cap during the read. `<path>` is the path of the
    ///   object relative to the repository, for example
    ///   `objects/ab/<62 hex>.dirtree`.
    /// - [`Error::InvalidFormat`] with the message `<path> is not a regular
    ///   file` if the object is not a regular file. The open of a FIFO does
    ///   not wait for a writer.
    /// - [`Error::InvalidFormat`] with the message `<path> passes through a
    ///   symlink; ostrya refuses a symlink in the repository` if a symlink is
    ///   at `objects/<xx>` or at the object path. `<path>` is the path of the
    ///   object.
    /// - [`Error::InvalidFormat`] with the message `<path> is not a directory`
    ///   if `objects/<xx>` is not a directory.
    /// - [`Error::Io`] for other failures of the file system.
    pub async fn load_object_bytes(&self, ty: ObjectType, checksum: &Checksum) -> Result<Vec<u8>> {
        let repo = self.clone();
        let key = *checksum;
        ostrya_rt::unblock(move || repo.load_object_bytes_blocking(ty, &key)).await
    }

    /// Runs [`load_object_bytes`](Repo::load_object_bytes) on the calling
    /// thread.
    pub(crate) fn load_object_bytes_blocking(
        &self,
        ty: ObjectType,
        checksum: &Checksum,
    ) -> Result<Vec<u8>> {
        let checksum = *checksum;
        self.held_object_bytes_blocking(ty, &checksum)?
            .ok_or(Error::ObjectNotFound { checksum, ty })
    }

    /// Loads the bytes of a metadata object as
    /// [`load_object_bytes`](Repo::load_object_bytes) does, or returns `None`
    /// when the object store does not hold the object.
    pub(crate) async fn held_object_bytes(
        &self,
        ty: ObjectType,
        checksum: &Checksum,
    ) -> Result<Option<Vec<u8>>> {
        let repo = self.clone();
        let key = *checksum;
        ostrya_rt::unblock(move || repo.held_object_bytes_blocking(ty, &key)).await
    }

    /// Runs [`held_object_bytes`](Repo::held_object_bytes) on the calling
    /// thread.
    pub(crate) fn held_object_bytes_blocking(
        &self,
        ty: ObjectType,
        checksum: &Checksum,
    ) -> Result<Option<Vec<u8>>> {
        let path = loose_path(checksum, ty, self.mode());
        Ok(self
            .objects()
            .read_capped(&path, MAX_METADATA_SIZE)
            .optional()?)
    }

    /// Opens a streaming reader over the bytes of a metadata object.
    ///
    /// The reader buffers no whole object. The caller reads the bytes in
    /// chunks of its own size. A caller that copies a metadata object to a
    /// sink can use this reader. A parse that needs the whole buffer uses
    /// [`load_object_bytes`](Repo::load_object_bytes).
    ///
    /// The reader holds the same [`MAX_METADATA_SIZE`] cap as
    /// [`load_object_bytes`](Repo::load_object_bytes), and [`MetadataReader`]
    /// states the two checks. The reader does not verify the checksum. If a
    /// caller must verify the object, it hashes the streamed bytes itself.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the object is not in the object store.
    /// - [`Error::InvalidFormat`] with the message `<path> is larger than its
    ///   cap of 134217728 bytes` if the object is larger than the cap at the
    ///   open. No bytes stream in this case.
    /// - [`Error::InvalidFormat`] if the object is not a regular file, or if
    ///   a symlink is at `objects/<xx>` or at the object path, as
    ///   [`load_object_bytes`](Repo::load_object_bytes) states.
    /// - [`Error::InvalidFormat`] with the message `<path> is not a directory`
    ///   if `objects/<xx>` is not a directory.
    /// - [`Error::Io`] for other failures of the file system.
    pub async fn metadata_reader(
        &self,
        ty: ObjectType,
        checksum: &Checksum,
    ) -> Result<MetadataReader> {
        let path = loose_path(checksum, ty, self.mode());
        let repo = self.clone();
        let key = *checksum;
        ostrya_rt::unblock(move || {
            let objects = repo.objects();
            let Opened { file, stat } = objects
                .open_regular(&path)
                .map_err(|e| e.into_object_error(&key, ty))?;
            // The path of the cap error is relative to the repository root,
            // as the errors of the open give it.
            let path = format!("objects/{path}");
            if stat.size > MAX_METADATA_SIZE {
                return Err(Error::InvalidFormat(format!("{path} {CAP_REASON}")));
            }
            Ok(MetadataReader {
                file: FileReader::with_len_hint(file, stat.size),
                path,
                taken: 0,
                refused: false,
            })
        })
        .await
    }

    /// Loads a metadata object as a dynamic [`Value`] tree.
    ///
    /// The parse uses the GVariant type string of the object type:
    ///
    /// - dirtree: `(a(say)a(sayay))`
    /// - dirmeta: `(uuua(ayay))`
    /// - commit: `(a{sv}aya(say)sstayay)`
    /// - detached commit metadata: `a{sv}`
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if `ty` is not [`ObjectType::DirTree`],
    ///   [`ObjectType::DirMeta`], [`ObjectType::Commit`], or
    ///   [`ObjectType::CommitMeta`].
    /// - [`Error::ObjectNotFound`] if the object is not in the object store.
    /// - [`Error::InvalidFormat`] if the object is larger than
    ///   [`MAX_METADATA_SIZE`], if it is not a regular file, or if a symlink
    ///   is on its path, as [`load_object_bytes`](Repo::load_object_bytes)
    ///   states.
    /// - [`Error::Io`] for other failures of the file system.
    /// - [`Error::Core`] if the bytes do not parse as the type string.
    pub async fn load_variant(&self, ty: ObjectType, checksum: &Checksum) -> Result<Value> {
        // The GVariant type strings of the metadata objects.
        let signature = match ty {
            ObjectType::DirTree => "(a(say)a(sayay))",
            ObjectType::DirMeta => "(uuua(ayay))",
            ObjectType::Commit => "(a{sv}aya(say)sstayay)",
            ObjectType::CommitMeta => "a{sv}",
            other => {
                return Err(Error::Unsupported(format!(
                    "load_variant does not support {other:?} objects"
                )));
            }
        };
        let bytes = self.load_object_bytes(ty, checksum).await?;
        let ty = Type::parse(signature).map_err(ostrya_core::Error::from)?;
        Ok(from_bytes(&ty, &bytes).map_err(ostrya_core::Error::from)?)
    }

    /// Loads and parses a commit object, and returns its completeness state
    /// and the bytes of the object.
    ///
    /// The bytes are the bytes that
    /// [`load_object_bytes`](Repo::load_object_bytes) returns, so a caller
    /// that also verifies a signature over them reads the object one time.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the commit object is not in the object
    ///   store.
    /// - [`Error::InvalidFormat`] if the object is larger than
    ///   [`MAX_METADATA_SIZE`], if it is not a regular file, or if a symlink
    ///   is on its path, as [`load_object_bytes`](Repo::load_object_bytes)
    ///   states.
    /// - [`Error::Io`] for other failures of the file system, also in the
    ///   check of the `.commitpartial` marker.
    /// - [`Error::Core`] if the bytes do not parse as a commit object.
    pub async fn load_commit_with_bytes(
        &self,
        checksum: &Checksum,
    ) -> Result<(Commit, CommitState, Vec<u8>)> {
        let bytes = self.load_object_bytes(ObjectType::Commit, checksum).await?;
        let commit = Commit::parse(&bytes)?;
        let state = self.commit_state(checksum).await?;
        Ok((commit, state, bytes))
    }

    /// Loads and parses a commit object, and returns its completeness state.
    ///
    /// # Errors
    ///
    /// The errors of [`load_commit_with_bytes`](Repo::load_commit_with_bytes).
    pub async fn load_commit(&self, checksum: &Checksum) -> Result<(Commit, CommitState)> {
        let (commit, state, _) = self.load_commit_with_bytes(checksum).await?;
        Ok((commit, state))
    }

    /// Loads and parses a dirtree object.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the dirtree object is not in the object
    ///   store.
    /// - [`Error::InvalidFormat`] if the object is larger than
    ///   [`MAX_METADATA_SIZE`], if it is not a regular file, or if a symlink
    ///   is on its path, as [`load_object_bytes`](Repo::load_object_bytes)
    ///   states.
    /// - [`Error::Io`] for other failures of the file system.
    /// - [`Error::Core`] if the bytes do not parse as a dirtree object.
    pub async fn load_dirtree(&self, checksum: &Checksum) -> Result<DirTree> {
        let bytes = self
            .load_object_bytes(ObjectType::DirTree, checksum)
            .await?;
        Ok(DirTree::parse(&bytes)?)
    }

    /// Loads and parses a dirmeta object.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the dirmeta object is not in the object
    ///   store.
    /// - [`Error::InvalidFormat`] if the object is larger than
    ///   [`MAX_METADATA_SIZE`], if it is not a regular file, or if a symlink
    ///   is on its path, as [`load_object_bytes`](Repo::load_object_bytes)
    ///   states.
    /// - [`Error::Io`] for other failures of the file system.
    /// - [`Error::Core`] if the bytes do not parse as a dirmeta object.
    pub async fn load_dirmeta(&self, checksum: &Checksum) -> Result<DirMeta> {
        let bytes = self
            .load_object_bytes(ObjectType::DirMeta, checksum)
            .await?;
        Ok(DirMeta::parse(&bytes)?)
    }

    /// Returns the totals of the `ostree.sizes` metadata of a commit.
    ///
    /// If the commit has no `ostree.sizes` key, the method returns `None`. An
    /// entry whose object is not in the object store counts toward the
    /// `*_needed` totals of [`CommitSizes`]. If an entry records no object
    /// type, the method reads it as a file object. On the commits whose
    /// entries omit the type, the key lists file objects only.
    ///
    /// # Errors
    ///
    /// - [`Error::ObjectNotFound`] if the commit object is not in the object
    ///   store.
    /// - [`Error::Core`] if the bytes do not parse as a commit object.
    /// - [`Error::InvalidFormat`] with the message `ostree.sizes is not an
    ///   array of packed entries` if the value of the key is not an array.
    /// - [`Error::InvalidFormat`] with the message `an ostree.sizes entry is
    ///   not a byte array` if an entry is not a byte array.
    /// - [`Error::Core`] if an entry does not decode:
    ///   - the entry is shorter than a checksum
    ///   - a size is not a valid varint
    ///   - the type byte names no object type
    ///   - trailing bytes follow the sizes
    /// - [`Error::InvalidFormat`] if the commit object is larger than
    ///   [`MAX_METADATA_SIZE`], if it is not a regular file, or if a symlink
    ///   is on its path, as [`load_object_bytes`](Repo::load_object_bytes)
    ///   states. The check of each recorded object gives the errors of
    ///   [`has_object`](Repo::has_object).
    /// - [`Error::Io`] for other failures of the file system.
    pub async fn commit_sizes(&self, checksum: &Checksum) -> Result<Option<CommitSizes>> {
        let (commit, _) = self.load_commit(checksum).await?;
        let Some(value) = commit.metadata.dict_get("ostree.sizes") else {
            return Ok(None);
        };
        let packed = match value.as_variant() {
            Some((_, inner)) => inner,
            None => value,
        };
        let entries = packed.as_array().ok_or_else(|| {
            Error::InvalidFormat("ostree.sizes is not an array of packed entries".into())
        })?;
        let mut sizes = CommitSizes::default();
        for packed in entries {
            let buf = packed.as_bytes().ok_or_else(|| {
                Error::InvalidFormat("an ostree.sizes entry is not a byte array".into())
            })?;
            let entry = ostrya_core::sizes::unpack_entry(buf)?;
            sizes.compressed_total += entry.compressed;
            sizes.unpacked_total += entry.unpacked;
            sizes.objects_total += 1;
            let ty = entry.objtype.unwrap_or(ObjectType::File);
            if !self.has_object(ty, &entry.checksum).await? {
                sizes.compressed_needed += entry.compressed;
                sizes.unpacked_needed += entry.unpacked;
                sizes.objects_needed += 1;
            }
        }
        Ok(Some(sizes))
    }

    /// Returns the on-disk (compressed) size of a loose object.
    ///
    /// A caller uses it to rebuild an `ostree.sizes` record for an object that
    /// `objects/` already holds.
    pub(crate) async fn loose_object_size(
        &self,
        ty: ObjectType,
        checksum: &Checksum,
    ) -> Result<u64> {
        let checksum = *checksum;
        self.held_object_size(ty, &checksum)
            .await?
            .ok_or(Error::ObjectNotFound { checksum, ty })
    }

    /// Returns the on-disk size of a loose object as
    /// [`loose_object_size`](Repo::loose_object_size) does, or `None` when the
    /// object store does not hold the object.
    pub(crate) async fn held_object_size(
        &self,
        ty: ObjectType,
        checksum: &Checksum,
    ) -> Result<Option<u64>> {
        let path = loose_path(checksum, ty, self.mode());
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            Ok(repo
                .objects()
                .lstat(&path)
                .optional()?
                .map(|stat| stat.size))
        })
        .await
    }

    /// Returns `true` if a loose object of the given type is in the object
    /// store.
    ///
    /// An entry of any type at the object path is present, also a symlink.
    /// An absent fan-out directory `objects/<xx>` gives `false`. The check
    /// is one `openat2` of the object path with `RESOLVE_BENEATH`,
    /// `RESOLVE_NO_SYMLINKS`, `O_PATH`, and `O_NOFOLLOW`, and one `close`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] with the message `objects/<xx>/<name>
    ///   passes through a symlink; ostrya refuses a symlink in the
    ///   repository` if `objects/<xx>` is a symlink, or with the message
    ///   `objects/<xx>/<name> is not a directory` if `objects/<xx>` is not a
    ///   directory.
    /// - [`Error::Io`] if the open fails with another error.
    pub async fn has_object(&self, ty: ObjectType, checksum: &Checksum) -> Result<bool> {
        let repo = self.clone();
        let key = *checksum;
        ostrya_rt::unblock(move || repo.has_object_blocking(ty, &key)).await
    }

    /// Runs [`has_object`](Repo::has_object) on the calling thread.
    pub(crate) fn has_object_blocking(&self, ty: ObjectType, checksum: &Checksum) -> Result<bool> {
        let path = loose_path(checksum, ty, self.mode());
        Ok(self.objects().exists(&path)?)
    }

    /// Returns the completeness state of a commit.
    ///
    /// If the `.commitpartial` marker of the commit exists, the state is
    /// [`Partial`](CommitState::Partial). Otherwise the state is
    /// [`Normal`](CommitState::Normal). The method does not check that the
    /// commit object exists.
    ///
    /// The check of the marker follows no symlink at `state` and at the
    /// marker. A symlink at the marker is a marker.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] with the message
    ///   `state/<checksum>.commitpartial passes through a symlink; ostrya
    ///   refuses a symlink in the repository` if `state` is a symlink, or with
    ///   the message `state/<checksum>.commitpartial is not a directory` if
    ///   `state` is not a directory.
    /// - [`Error::Io`] if the check fails with another error.
    pub async fn commit_state(&self, checksum: &Checksum) -> Result<CommitState> {
        let repo = self.clone();
        let key = *checksum;
        ostrya_rt::unblock(move || repo.commit_state_blocking(&key)).await
    }

    /// Runs [`commit_state`](Repo::commit_state) on the calling thread.
    pub(crate) fn commit_state_blocking(&self, checksum: &Checksum) -> Result<CommitState> {
        let path = crate::pull::partial_path(checksum);
        Ok(if self.root_dir().exists(&path)? {
            CommitState::Partial
        } else {
            CommitState::Normal
        })
    }
}

/// The reason of the refusal of a metadata object larger than its cap.
const CAP_REASON: Reason = Reason::TooLarge {
    cap: MAX_METADATA_SIZE,
};

/// Gives the error `err` of an operation on the loose object at `path`,
/// relative to `objects/`, with the path of the object.
///
/// An operation that opens the parent directory of the object first names
/// that directory, `objects/<xx>`, in an error of the open. The function
/// gives such an [`FsError::Absent`] or [`FsError::Invalid`] the path
/// `objects/<path>`. Each other error stays as it is.
pub(crate) fn object_path_error(err: FsError, path: &str) -> FsError {
    let Some((parent, _)) = path.rsplit_once('/') else {
        return err;
    };
    let at_parent = |p: &str| p.strip_prefix("objects/") == Some(parent);
    match err {
        FsError::Absent { path: p } if at_parent(&p) => FsError::Absent {
            path: format!("objects/{path}"),
        },
        FsError::Invalid { path: p, reason } if at_parent(&p) => FsError::Invalid {
            path: format!("objects/{path}"),
            reason,
        },
        other => other,
    }
}

/// An async reader over the bytes of a metadata object.
///
/// A metadata object has no compression and no framed header in any
/// repository mode. The reader streams the object file from offset 0, in
/// chunks of the size that the caller asks for. It buffers no whole object.
/// [`Repo::metadata_reader`] opens it.
///
/// The reader implements `futures_io::AsyncRead` always, and
/// `tokio::io::AsyncRead` under the `tokio` feature. A caller of either
/// runtime backend needs no adapter. The reader does not verify the checksum.
///
/// # Size cap
///
/// The reader applies the [`MAX_METADATA_SIZE`] cap twice, as
/// [`Repo::load_object_bytes`] does:
///
/// - At the open, the `statx` of the open file refuses an object that is
///   already larger than the cap, with [`Error::InvalidFormat`] and the
///   message of the read failure below.
/// - During the read, a running total of the bytes given to the caller guards
///   against an object that grows. If the total is at the cap and the object
///   holds one more byte, the read fails.
///
/// The read failure is an [`io::Error`] of kind
/// [`InvalidData`](io::ErrorKind::InvalidData) with the message `<path> is
/// larger than its cap of 134217728 bytes`, where `<path>` is the path of the
/// object relative to the repository. Before the failure, the reader gives no
/// more than [`MAX_METADATA_SIZE`] bytes.
///
/// The failure is final, so an object that is too large never reads back as
/// an object that ends at the cap. Each later read returns the same error.
/// Before a failure, a read into an empty buffer returns `Ok(0)`.
pub struct MetadataReader {
    file: FileReader,
    /// The path of the object relative to the repository, for the cap error.
    path: String,
    /// The number of bytes that the caller has read.
    taken: u64,
    /// `true` after the running total refused the object.
    ///
    /// The probe read that finds the extra byte removes that byte from the
    /// stream. Without this flag, a later read reports the end of the object
    /// one byte early.
    refused: bool,
}

impl MetadataReader {
    /// Returns the error of a read past the cap.
    fn cap_exceeded(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} {CAP_REASON}", self.path),
        )
    }

    /// Runs the read step that both trait implementations call.
    ///
    /// `rt::FileReader` gives `futures_io::AsyncRead` under each runtime
    /// backend.
    fn poll_read_bytes(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
        use futures_io::AsyncRead;
        if self.refused {
            return Poll::Ready(Err(self.cap_exceeded()));
        }
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let room = MAX_METADATA_SIZE.saturating_sub(self.taken);
        if room == 0 {
            // At the cap, one more byte in the object makes it larger than the
            // cap. This probe finds out if the file ends at the cap. The probe
            // reads into its own byte. So the buffer of the caller never gets
            // the byte that fails the cap, and `taken` never counts it.
            let mut probe = [0u8; 1];
            let n = match Pin::new(&mut self.file).poll_read(cx, &mut probe) {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };
            if n == 0 {
                return Poll::Ready(Ok(0));
            }
            self.refused = true;
            return Poll::Ready(Err(self.cap_exceeded()));
        }
        // The limit is the number of bytes left under the cap. After a short
        // read or a full read, `taken` equals the number of bytes that the
        // caller has.
        let limit = room.min(out.len() as u64) as usize;
        let n = match Pin::new(&mut self.file).poll_read(cx, &mut out[..limit]) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        self.taken += n as u64;
        Poll::Ready(Ok(n))
    }
}

impl futures_io::AsyncRead for MetadataReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_read_bytes(cx, buf)
    }
}

#[cfg(feature = "tokio")]
impl ostrya_rt::tokio_io::AsyncRead for MetadataReader {
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

/// Checks at compile time that [`MetadataReader`] is `Send` and `Sync`, so
/// it can move across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MetadataReader>();
};

/// Checks at compile time that [`MetadataReader`] implements the tokio
/// `AsyncRead` trait under the `tokio` feature, so a tokio caller needs no
/// adapter.
#[cfg(feature = "tokio")]
const _: fn() = || {
    fn assert_tokio_read<T: ostrya_rt::tokio_io::AsyncRead>() {}
    assert_tokio_read::<MetadataReader>();
};
