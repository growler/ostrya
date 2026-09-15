//! The metadata reading path: loading objects, commits, and trees, and
//! resolving commit state.
//!
//! Metadata objects (commit, dirtree, dirmeta, detached commit metadata) are
//! small and bounded, so they load whole into memory and parse through the
//! `ostrya-core` object model. [`MetadataReader`] streams the same bytes for a
//! caller that hands them to a sink instead of parsing them. File content
//! objects have their own path in [`crate::file`], which streams the payload.
//! Every entry point is `async fn` and offloads its syscalls to the blocking
//! pool; a missing object surfaces as [`Error::ObjectNotFound`].

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use ostrya_core::{
    Checksum, Commit, DirMeta, DirTree, ObjectType, Type, Value, from_bytes, loose_path,
};
use ostrya_rt::File as RtFile;

use crate::error::{Error, Result};
use crate::object::{self, MAX_METADATA_SIZE};
use crate::repo::Repo;

/// The totals a commit's `ostree.sizes` metadata states, together with the part
/// of them whose objects are absent from the local store.
///
/// The metadata key is written by a commit that asked for it, so a commit
/// without the key has no sizes to report and
/// [`commit_sizes`](Repo::commit_sizes) yields `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommitSizes {
    /// On-disk (compressed) bytes over every recorded object.
    pub compressed_total: u64,
    /// On-disk bytes over the recorded objects absent locally.
    pub compressed_needed: u64,
    /// Uncompressed bytes over every recorded object.
    pub unpacked_total: u64,
    /// Uncompressed bytes over the recorded objects absent locally.
    pub unpacked_needed: u64,
    /// How many objects the metadata records.
    pub objects_total: u64,
    /// How many of the recorded objects are absent locally.
    pub objects_needed: u64,
}

/// The completeness state of a commit in the local store.
///
/// A commit is [`Partial`](CommitState::Partial) while a
/// `state/<checksum>.commitpartial` marker is present, which a pull writes
/// before the commit's objects are all local and removes once the commit is
/// complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitState {
    /// The commit and its reachable objects are fully present.
    Normal,
    /// A `.commitpartial` marker is present: the commit may be incomplete.
    Partial,
}

impl Repo {
    /// Load the raw serialized bytes of a metadata object. Views borrow this
    /// buffer. Intended for metadata objects, whose size the format caps.
    pub async fn load_object_bytes(&self, ty: ObjectType, checksum: &Checksum) -> Result<Vec<u8>> {
        let path = loose_path(checksum, ty, self.mode());
        let repo = self.clone();
        let key = *checksum;
        let res = ostrya_rt::unblock(move || {
            object::read_meta_object(repo.objects_fd(), &path, MAX_METADATA_SIZE)
        })
        .await;
        match res {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::ObjectNotFound { checksum: key, ty })
            }
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Open a streaming reader over a metadata object's raw bytes.
    ///
    /// The reader holds the same [`MAX_METADATA_SIZE`] cap
    /// [`load_object_bytes`](Repo::load_object_bytes) holds, and it buffers no
    /// whole object: the caller takes the bytes in chunks of its own size. Use
    /// it to copy a metadata object into a sink; use
    /// [`load_object_bytes`](Repo::load_object_bytes) where a parse needs the
    /// whole buffer.
    ///
    /// The reader carries no checksum verification, matching
    /// [`load_object_bytes`](Repo::load_object_bytes). A caller that needs the
    /// identity checked hashes the streamed bytes itself.
    ///
    /// A missing object surfaces as [`Error::ObjectNotFound`]. An object the
    /// open already measures above the cap fails here, so an oversized object
    /// costs no streaming.
    pub async fn metadata_reader(
        &self,
        ty: ObjectType,
        checksum: &Checksum,
    ) -> Result<MetadataReader> {
        let path = loose_path(checksum, ty, self.mode());
        let repo = self.clone();
        let key = *checksum;
        let res = ostrya_rt::unblock(move || open_meta_file(repo.objects_fd(), &path)).await;
        match res {
            Ok(file) => Ok(MetadataReader {
                file: RtFile::from(file),
                taken: 0,
                refused: false,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::ObjectNotFound { checksum: key, ty })
            }
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Load a metadata object as a dynamic [`Value`] tree, parsed against the
    /// object type's GVariant signature. Supports the metadata object types;
    /// other types return [`Error::Unsupported`].
    pub async fn load_variant(&self, ty: ObjectType, checksum: &Checksum) -> Result<Value> {
        // The metadata object GVariant type strings, from `format-reference.md`.
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

    /// Load and parse a commit object together with its completeness state.
    pub async fn load_commit(&self, checksum: &Checksum) -> Result<(Commit, CommitState)> {
        let bytes = self.load_object_bytes(ObjectType::Commit, checksum).await?;
        let commit = Commit::parse(&bytes)?;
        let state = self.commit_state(checksum).await?;
        Ok((commit, state))
    }

    /// Load and parse a dirtree object.
    pub async fn load_dirtree(&self, checksum: &Checksum) -> Result<DirTree> {
        let bytes = self
            .load_object_bytes(ObjectType::DirTree, checksum)
            .await?;
        Ok(DirTree::parse(&bytes)?)
    }

    /// Load and parse a dirmeta object.
    pub async fn load_dirmeta(&self, checksum: &Checksum) -> Result<DirMeta> {
        let bytes = self
            .load_object_bytes(ObjectType::DirMeta, checksum)
            .await?;
        Ok(DirMeta::parse(&bytes)?)
    }

    /// Total the `ostree.sizes` metadata of a commit, or `None` when the commit
    /// carries no such key.
    ///
    /// An entry whose object is absent from the local store counts toward the
    /// "needed" totals. An entry that records no object type is read as a file
    /// object, the only type the key covers on the commits that omit it.
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

    /// The on-disk (compressed) size of a loose object, used to recover an
    /// `ostree.sizes` record for an object that deduplicated against `objects/`.
    pub(crate) async fn loose_object_size(
        &self,
        ty: ObjectType,
        checksum: &Checksum,
    ) -> Result<u64> {
        let path = loose_path(checksum, ty, self.mode());
        let repo = self.clone();
        let key = *checksum;
        let res = ostrya_rt::unblock(move || object::object_size(repo.objects_fd(), &path)).await;
        match res {
            Ok(size) => Ok(size),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::ObjectNotFound { checksum: key, ty })
            }
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Whether a loose object of the given type is present.
    pub async fn has_object(&self, ty: ObjectType, checksum: &Checksum) -> Result<bool> {
        let path = loose_path(checksum, ty, self.mode());
        let repo = self.clone();
        ostrya_rt::unblock(move || object::object_exists(repo.objects_fd(), &path)).await
    }

    /// The completeness state of a commit: [`Partial`](CommitState::Partial)
    /// when a `.commitpartial` marker is present, else
    /// [`Normal`](CommitState::Normal).
    pub async fn commit_state(&self, checksum: &Checksum) -> Result<CommitState> {
        let path = crate::pull::partial_path(checksum);
        let repo = self.clone();
        let partial =
            ostrya_rt::unblock(move || object::object_exists(repo.repo_fd(), &path)).await?;
        Ok(if partial {
            CommitState::Partial
        } else {
            CommitState::Normal
        })
    }
}

/// Open a metadata object for streaming. The function refuses an object that
/// the `fstat` already measures above [`MAX_METADATA_SIZE`]. This check matches
/// the open-time check of `object::read_meta_object`, so the streaming path and
/// the buffered path refuse the same object with the same error.
///
/// This check and the running total in `MetadataReader` both read
/// [`MAX_METADATA_SIZE`], so the open and the read hold one bound.
fn open_meta_file(dir: rustix::fd::BorrowedFd<'_>, path: &str) -> std::io::Result<std::fs::File> {
    let fd = object::open_object(dir, path)?;
    let stat = rustix::fs::fstat(&fd)?;
    let size = stat.st_size.max(0) as u64;
    if size > MAX_METADATA_SIZE {
        return Err(object::metadata_cap_exceeded());
    }
    Ok(std::fs::File::from(fd))
}

/// An async reader over a metadata object's raw bytes.
///
/// A metadata object carries no compression and no framed header in any
/// repository mode, so the reader streams the object file itself from offset 0
/// in chunks of the caller's size and buffers nothing whole.
///
/// The reader holds the [`MAX_METADATA_SIZE`] cap twice, the way
/// [`Repo::load_object_bytes`] holds it. The `fstat` at the open refuses an
/// object already above the cap. A running total of the bytes handed to the
/// caller then guards an object that grows while the read is in flight: once the
/// total stands at the cap and the object still holds a further byte, the read
/// fails with the same error, and the reader has handed over no more than
/// [`MAX_METADATA_SIZE`] bytes when it does. That refusal is terminal -- every
/// later read repeats it -- so an oversized object never reads back as one that
/// ended at the cap.
///
/// A read into an empty buffer makes no progress and yields `Ok(0)`.
///
/// The reader implements `futures_io::AsyncRead` unconditionally and
/// `tokio::io::AsyncRead` under the `tokio` feature, so neither backend needs a
/// caller-side adapter. It carries no checksum verification.
pub struct MetadataReader {
    file: RtFile,
    /// How many bytes the caller has taken so far.
    taken: u64,
    /// Whether the running total has already refused the object. The probe read
    /// that raises the refusal takes the byte that carried the object over the
    /// cap out of the stream, so a reader that carried on from there would
    /// report the end of an object one byte short of the truth.
    refused: bool,
}

impl MetadataReader {
    /// The shared read step both trait families drive. `rt::File` presents
    /// `futures_io::AsyncRead` under either backend.
    fn poll_read_bytes(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
        use futures_io::AsyncRead;
        if self.refused {
            return Poll::Ready(Err(object::metadata_cap_exceeded()));
        }
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let room = MAX_METADATA_SIZE.saturating_sub(self.taken);
        if room == 0 {
            // With the cap reached, one further byte in the object puts it above
            // the cap. This probe settles cap-versus-end-of-file. It reads into
            // a byte of its own, so the byte that fails the cap never lands in
            // the caller's buffer, and `taken` never counts it.
            let mut probe = [0u8; 1];
            let n = match Pin::new(&mut self.file).poll_read(cx, &mut probe) {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };
            if n == 0 {
                return Poll::Ready(Ok(0));
            }
            self.refused = true;
            return Poll::Ready(Err(object::metadata_cap_exceeded()));
        }
        // Clamped to the bytes left under the cap, so a short read and a full
        // read alike leave `taken` equal to the bytes the caller has.
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

/// The metadata reader moves freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MetadataReader>();
};

/// Under the `tokio` feature the metadata reader also speaks the tokio I/O
/// traits, so a tokio-native caller needs no adapter.
#[cfg(feature = "tokio")]
const _: fn() = || {
    fn assert_tokio_read<T: ostrya_rt::tokio_io::AsyncRead>() {}
    assert_tokio_read::<MetadataReader>();
};
