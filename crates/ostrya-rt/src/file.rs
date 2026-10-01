//! Async files over an already-open descriptor.
//!
//! Opens are performed elsewhere through `rustix` (fd-relative `openat`);
//! [`File`] and [`FileReader`] only stream over a descriptor they are handed.
//! [`File`] wraps the backend's async file (`smol::fs::File` or
//! `tokio::fs::File`) and presents the `futures-io` traits under both
//! backends, so core code stays generic. Under the `tokio` feature it
//! additionally implements the tokio I/O traits for tokio-native callers.
//! [`FileReader`] is the read-only form with a bounded read-ahead, and it
//! presents the `futures-io` read trait alone.

use std::io;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(all(feature = "smol", not(feature = "tokio")))]
type Backend = smol::fs::File;
#[cfg(feature = "tokio")]
type Backend = tokio::fs::File;

/// An async file over an already-open descriptor.
///
/// Constructed from a `std::fs::File` or, on Unix, an `OwnedFd`; both take
/// ownership of the descriptor. The current descriptor offset is preserved, so
/// a caller that seeked before wrapping (past a framed header, for instance)
/// streams from that offset.
pub struct File {
    inner: Backend,
    /// The `futures-io` seek shim under the tokio backend must remember that a
    /// seek is in flight across polls, because tokio's `AsyncSeek` is a
    /// two-step (`start_seek` then `poll_complete`) API.
    #[cfg(feature = "tokio")]
    seeking: bool,
}

impl From<std::fs::File> for File {
    fn from(file: std::fs::File) -> File {
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            File {
                inner: smol::fs::File::from(file),
            }
        }
        #[cfg(feature = "tokio")]
        {
            File {
                inner: tokio::fs::File::from_std(file),
                seeking: false,
            }
        }
    }
}

#[cfg(unix)]
impl From<OwnedFd> for File {
    fn from(fd: OwnedFd) -> File {
        File::from(std::fs::File::from(fd))
    }
}

impl File {
    /// Settle queued writes into the descriptor.
    ///
    /// The backend hands a write to a blocking worker and holds what the worker
    /// has not taken yet, so a file dropped at process exit loses that tail.
    /// This asks for the held bytes and nothing further, which is what a
    /// descriptor that refuses a sync -- a pipe, a terminal -- accepts;
    /// [`sync_all`](File::sync_all) and [`sync_data`](File::sync_data) ask for
    /// durability as well.
    pub async fn flush(&mut self) -> io::Result<()> {
        #[cfg(feature = "tokio")]
        {
            use tokio::io::AsyncWriteExt;

            self.inner.flush().await
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            use smol::io::AsyncWriteExt;

            self.inner.flush().await
        }
    }

    /// Flush queued writes and durably sync contents and metadata.
    pub async fn sync_all(&mut self) -> io::Result<()> {
        self.inner.sync_all().await
    }

    /// Flush queued writes and durably sync contents; metadata may lag.
    pub async fn sync_data(&mut self) -> io::Result<()> {
        self.inner.sync_data().await
    }

    /// Recover an owned `std::fs::File`, settling pending writes first.
    ///
    /// Under the tokio backend this returns the file tokio was driving. Under
    /// the smol backend the async file holds its descriptor behind an `Arc`,
    /// so this flushes and then duplicates the descriptor (the handle on
    /// Windows); the returned file shares the same open file description.
    pub async fn into_std(self) -> std::fs::File {
        #[cfg(feature = "tokio")]
        {
            self.inner.into_std().await
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            use smol::io::AsyncWriteExt;

            let mut inner = self.inner;
            let _ = inner.flush().await;
            #[cfg(unix)]
            let owned = {
                use std::os::fd::AsFd;
                inner.as_fd().try_clone_to_owned()
            };
            #[cfg(windows)]
            let owned = {
                use std::os::windows::io::AsHandle;
                inner.as_handle().try_clone_to_owned()
            };
            std::fs::File::from(owned.expect("duplicate descriptor for into_std"))
        }
    }
}

// --- smol backend: delegate to the futures-io impls async-fs provides ---

#[cfg(all(feature = "smol", not(feature = "tokio")))]
mod smol_impls {
    use super::*;
    use futures_io::{AsyncRead, AsyncSeek, AsyncWrite};

    impl AsyncRead for File {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for File {
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
            Pin::new(&mut self.get_mut().inner).poll_close(cx)
        }
    }

    impl AsyncSeek for File {
        fn poll_seek(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            pos: io::SeekFrom,
        ) -> Poll<io::Result<u64>> {
            Pin::new(&mut self.get_mut().inner).poll_seek(cx, pos)
        }
    }
}

// --- tokio backend: present futures-io over the tokio file, and the tokio
// traits natively for tokio-native callers ---

#[cfg(feature = "tokio")]
mod tokio_impls {
    use super::*;
    use tokio::io::{
        AsyncRead as TokioRead, AsyncSeek as TokioSeek, AsyncWrite as TokioWrite, ReadBuf,
    };

    impl futures_io::AsyncRead for File {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut read_buf = ReadBuf::new(buf);
            match TokioRead::poll_read(Pin::new(&mut self.get_mut().inner), cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl futures_io::AsyncWrite for File {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            TokioWrite::poll_write(Pin::new(&mut self.get_mut().inner), cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            TokioWrite::poll_flush(Pin::new(&mut self.get_mut().inner), cx)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            TokioWrite::poll_shutdown(Pin::new(&mut self.get_mut().inner), cx)
        }
    }

    impl futures_io::AsyncSeek for File {
        fn poll_seek(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            pos: io::SeekFrom,
        ) -> Poll<io::Result<u64>> {
            let me = self.get_mut();
            if !me.seeking {
                if let Err(e) = TokioSeek::start_seek(Pin::new(&mut me.inner), pos) {
                    return Poll::Ready(Err(e));
                }
                me.seeking = true;
            }
            match TokioSeek::poll_complete(Pin::new(&mut me.inner), cx) {
                Poll::Ready(result) => {
                    me.seeking = false;
                    Poll::Ready(result)
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl TokioRead for File {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            TokioRead::poll_read(Pin::new(&mut self.get_mut().inner), cx, buf)
        }
    }

    impl TokioWrite for File {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            TokioWrite::poll_write(Pin::new(&mut self.get_mut().inner), cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            TokioWrite::poll_flush(Pin::new(&mut self.get_mut().inner), cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            TokioWrite::poll_shutdown(Pin::new(&mut self.get_mut().inner), cx)
        }
    }

    impl TokioSeek for File {
        fn start_seek(self: Pin<&mut Self>, pos: io::SeekFrom) -> io::Result<()> {
            TokioSeek::start_seek(Pin::new(&mut self.get_mut().inner), pos)
        }

        fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
            TokioSeek::poll_complete(Pin::new(&mut self.get_mut().inner), cx)
        }
    }
}

/// The read-ahead of a [`FileReader`] when the caller gives no length, and
/// the most a length hint can give.
const READ_AHEAD: usize = 256 * 1024;

/// The least read-ahead a length hint can give.
const MIN_READ_AHEAD: usize = 4 * 1024;

#[cfg(all(feature = "smol", not(feature = "tokio")))]
type ReaderBackend = smol::Unblock<std::fs::File>;
#[cfg(feature = "tokio")]
type ReaderBackend = tokio::fs::File;

/// A read-only async file over an already-open descriptor.
///
/// The reader streams from the current descriptor offset to the end of the
/// file and reads ahead by at most 256 KiB. It does no seek, so a reader over
/// a pipe or over a descriptor positioned past a header costs no extra
/// syscall. Use [`File`] for a descriptor that must also be written, sought,
/// or recovered as a `std::fs::File`.
///
/// Under the smol backend the reads run on the blocking pool through a ring
/// buffer of the read-ahead size. The ring is allocated when the first read
/// starts, and it is zeroed in parts as it fills, up to its size.
/// [`FileReader::with_len_hint`] bounds the ring by the length the caller
/// already knows, so a small file costs a small buffer. Under the tokio
/// backend each read is one blocking-pool read of at most the caller's buffer;
/// a length hint below the read-ahead also bounds that read. A dropped reader
/// closes its descriptor on the pool thread after the read in flight returns.
pub struct FileReader {
    inner: ReaderBackend,
}

impl FileReader {
    /// Wrap `file`, with a read-ahead of `len + 1` bytes, held between
    /// 4 KiB and 256 KiB.
    ///
    /// `len` is the number of bytes the caller expects to read. The extra
    /// byte lets a read of exactly `len` bytes see the end of the file in the
    /// same run of reads. A `len` below the real length gives a smaller
    /// read-ahead, and the reader still streams to the end of the file, in
    /// runs of at least 4 KiB.
    pub fn with_len_hint(file: std::fs::File, len: u64) -> FileReader {
        let cap = read_ahead_for(len);
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            FileReader {
                inner: smol::Unblock::with_capacity(cap, file),
            }
        }
        #[cfg(feature = "tokio")]
        {
            let mut inner = tokio::fs::File::from_std(file);
            if cap < READ_AHEAD {
                inner.set_max_buf_size(cap);
            }
            FileReader { inner }
        }
    }
}

/// The read-ahead for a length hint of `len` bytes.
fn read_ahead_for(len: u64) -> usize {
    usize::try_from(len.saturating_add(1))
        .map_or(READ_AHEAD, |n| n.clamp(MIN_READ_AHEAD, READ_AHEAD))
}

impl From<std::fs::File> for FileReader {
    fn from(file: std::fs::File) -> FileReader {
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            FileReader {
                inner: smol::Unblock::with_capacity(READ_AHEAD, file),
            }
        }
        #[cfg(feature = "tokio")]
        {
            FileReader {
                inner: tokio::fs::File::from_std(file),
            }
        }
    }
}

#[cfg(unix)]
impl From<OwnedFd> for FileReader {
    fn from(fd: OwnedFd) -> FileReader {
        FileReader::from(std::fs::File::from(fd))
    }
}

impl futures_io::AsyncRead for FileReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // The smol backend takes a read into an empty buffer for the end of
        // the stream and drops the bytes it has read ahead.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            futures_io::AsyncRead::poll_read(Pin::new(&mut self.get_mut().inner), cx, buf)
        }
        #[cfg(feature = "tokio")]
        {
            let mut read_buf = tokio::io::ReadBuf::new(buf);
            match tokio::io::AsyncRead::poll_read(
                Pin::new(&mut self.get_mut().inner),
                cx,
                &mut read_buf,
            ) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

/// `File` and `FileReader` move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<File>();
    assert_send_sync::<FileReader>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;
    use futures_lite::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempPath(PathBuf);

    impl TempPath {
        fn new() -> TempPath {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("ostrya-rt-{}-{n}.tmp", std::process::id()));
            let _ = std::fs::remove_file(&path);
            TempPath(path)
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn reads_from_the_current_descriptor_offset() {
        let tmp = TempPath::new();
        std::fs::write(&tmp.0, b"0123456789").unwrap();
        block_on(async {
            use std::io::Seek;
            let mut std_file = std::fs::File::open(&tmp.0).unwrap();
            std_file.seek(std::io::SeekFrom::Start(4)).unwrap();
            let mut file = File::from(std_file);
            let mut out = Vec::new();
            file.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"456789");
        });
    }

    #[test]
    fn reader_reads_from_the_current_descriptor_offset() {
        let tmp = TempPath::new();
        std::fs::write(&tmp.0, b"0123456789").unwrap();
        block_on(async {
            use std::io::Seek;
            let mut std_file = std::fs::File::open(&tmp.0).unwrap();
            std_file.seek(std::io::SeekFrom::Start(4)).unwrap();
            let mut reader = FileReader::from(std_file);
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"456789");
        });
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn read_back(len: usize, hint: Option<u64>) -> Vec<u8> {
        let tmp = TempPath::new();
        std::fs::write(&tmp.0, pattern(len)).unwrap();
        let std_file = std::fs::File::open(&tmp.0).unwrap();
        let mut reader = match hint {
            Some(hint) => FileReader::with_len_hint(std_file, hint),
            None => FileReader::from(std_file),
        };
        block_on(async {
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            out
        })
    }

    #[test]
    fn reader_round_trips_a_file_larger_than_its_read_ahead() {
        let len = 200 * 1024;
        assert_eq!(read_back(len, None), pattern(len));
        assert_eq!(read_back(len, Some(len as u64)), pattern(len));
        // A read-ahead of 4097 bytes wraps the ring many times.
        assert_eq!(read_back(len, Some(4096)), pattern(len));
    }

    #[test]
    fn read_ahead_is_held_between_its_bounds() {
        assert_eq!(read_ahead_for(0), MIN_READ_AHEAD);
        assert_eq!(read_ahead_for(100), MIN_READ_AHEAD);
        assert_eq!(read_ahead_for(4095), MIN_READ_AHEAD);
        assert_eq!(read_ahead_for(10_000), 10_001);
        assert_eq!(read_ahead_for(300 * 1024), READ_AHEAD);
        assert_eq!(read_ahead_for(u64::MAX), READ_AHEAD);
    }

    #[test]
    fn reader_reads_an_empty_file() {
        assert!(read_back(0, None).is_empty());
        assert!(read_back(0, Some(0)).is_empty());
    }

    #[test]
    fn reader_read_into_an_empty_buffer_keeps_the_stream() {
        let tmp = TempPath::new();
        std::fs::write(&tmp.0, b"0123456789").unwrap();
        let std_file = std::fs::File::open(&tmp.0).unwrap();
        let mut reader = FileReader::from(std_file);
        block_on(async {
            let mut head = [0u8; 2];
            reader.read_exact(&mut head).await.unwrap();
            assert_eq!(reader.read(&mut []).await.unwrap(), 0);
            let mut rest = Vec::new();
            reader.read_to_end(&mut rest).await.unwrap();
            assert_eq!(&head, b"01");
            assert_eq!(rest, b"23456789");
        });
    }

    #[test]
    fn reader_with_a_short_hint_reads_the_whole_file() {
        assert_eq!(read_back(10_000, Some(0)), pattern(10_000));
        assert_eq!(read_back(10_000, Some(10)), pattern(10_000));
    }

    #[test]
    fn writes_then_seeks_and_reads_back() {
        let tmp = TempPath::new();
        let std_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp.0)
            .unwrap();
        block_on(async {
            let mut file = File::from(std_file);
            file.write_all(b"hello ostrya").await.unwrap();
            file.flush().await.unwrap();
            file.seek(std::io::SeekFrom::Start(6)).await.unwrap();
            let mut out = Vec::new();
            file.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"ostrya");
        });
    }

    #[test]
    fn into_std_recovers_a_readable_file() {
        let tmp = TempPath::new();
        let std_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp.0)
            .unwrap();
        block_on(async {
            let mut file = File::from(std_file);
            file.write_all(b"settled").await.unwrap();
            file.flush().await.unwrap();
            let recovered = file.into_std().await;
            drop(recovered);
            assert_eq!(std::fs::read(&tmp.0).unwrap(), b"settled");
        });
    }
}
