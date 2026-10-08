//! Async files over a descriptor that is already open.
//!
//! Other code opens the files through `rustix` (fd-relative `openat`).
//! [`File`] and [`FileReader`] only stream over the descriptor that they get.
//! [`File`] wraps the async file of the backend (`smol::fs::File` or
//! `tokio::fs::File`). The `futures-io` traits on it keep the code of a caller
//! the same with each backend.

use std::io;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(all(feature = "smol", not(feature = "tokio")))]
type Backend = smol::fs::File;
#[cfg(feature = "tokio")]
type Backend = tokio::fs::File;

/// An async file over a descriptor that is already open.
///
/// `File::from` takes a `std::fs::File` or, on Unix, an `OwnedFd`. Both forms
/// take ownership of the descriptor. The file keeps the current offset of the
/// descriptor. If a caller seeks before the wrap, for example past a framed
/// header, the stream starts at that offset.
///
/// `File` implements the `AsyncRead`, `AsyncWrite`, and `AsyncSeek` traits of
/// `futures-io` with each backend. With the `tokio` feature, it also
/// implements the same three traits of `tokio`, which `tokio_io` re-exports.
///
/// # Examples
///
/// ```
/// use futures_lite::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
/// use std::io::SeekFrom;
///
/// let name = format!("ostrya-rt-doc-{}.tmp", std::process::id());
/// let path = std::env::temp_dir().join(name);
/// let std_file = std::fs::OpenOptions::new()
///     .read(true)
///     .write(true)
///     .create(true)
///     .truncate(true)
///     .open(&path)?;
///
/// let out = ostrya_rt::block_on(async {
///     let mut file = ostrya_rt::File::from(std_file);
///     file.write_all(b"hello ostrya").await?;
///     file.flush().await?;
///     file.seek(SeekFrom::Start(6)).await?;
///     let mut out = Vec::new();
///     file.read_to_end(&mut out).await?;
///     Ok::<_, std::io::Error>(out)
/// })?;
///
/// std::fs::remove_file(&path)?;
/// assert_eq!(out, b"ostrya");
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct File {
    inner: Backend,
    /// Records a seek that is in flight across polls. The `futures-io` seek
    /// impl needs it with the tokio backend, because the tokio `AsyncSeek`
    /// trait has two steps: `start_seek`, then `poll_complete`.
    #[cfg(feature = "tokio")]
    seeking: bool,
}

/// Wraps a `std::fs::File`.
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

/// Wraps an `OwnedFd`.
#[cfg(unix)]
impl From<OwnedFd> for File {
    fn from(fd: OwnedFd) -> File {
        File::from(std::fs::File::from(fd))
    }
}

impl File {
    /// Writes the queued bytes to the descriptor.
    ///
    /// A write to a `File` can complete before its bytes reach the descriptor.
    /// If the file drops at process exit, the queued bytes are lost.
    ///
    /// `flush` asks for no durability, so a descriptor that refuses a sync, for
    /// example a pipe or a terminal, accepts it.
    ///
    /// # Errors
    ///
    /// The function returns an I/O error of the file if a queued write fails.
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

    /// Writes the queued bytes and makes the contents and the metadata durable.
    ///
    /// # Errors
    ///
    /// The function returns an I/O error of the file.
    pub async fn sync_all(&mut self) -> io::Result<()> {
        self.inner.sync_all().await
    }

    /// Writes the queued bytes and makes the contents durable.
    ///
    /// The metadata of the file does not always become durable with the
    /// contents.
    ///
    /// # Errors
    ///
    /// The function returns an I/O error of the file.
    pub async fn sync_data(&mut self) -> io::Result<()> {
        self.inner.sync_data().await
    }

    /// Returns this file as an owned `std::fs::File`.
    ///
    /// The function first writes the queued bytes. It does not report a
    /// failure of that write.
    ///
    /// With the `smol` feature, the function then duplicates the descriptor
    /// (the handle on Windows). The returned file shares the open file
    /// description of the original descriptor.
    ///
    /// With the `tokio` feature, the function returns the file that the
    /// backend drives.
    ///
    /// # Panics
    ///
    /// With the `smol` feature, the function panics if the operating system
    /// refuses the duplicate, for example at the limit of open descriptors.
    //
    // With smol, the async file holds its descriptor behind an `Arc`, so the
    // function duplicates the descriptor.
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

// The smol backend: each impl calls the `futures-io` impl of the smol file.

#[cfg(all(feature = "smol", not(feature = "tokio")))]
mod smol_impls {
    use super::*;
    use futures_io::{AsyncRead, AsyncSeek, AsyncWrite};

    /// The read trait of `futures-io`.
    impl AsyncRead for File {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    /// The write trait of `futures-io`.
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

    /// The seek trait of `futures-io`.
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

// The tokio backend: the `futures-io` impls over the tokio file, and the
// tokio traits for callers that use tokio.

#[cfg(feature = "tokio")]
mod tokio_impls {
    use super::*;
    use tokio::io::{
        AsyncRead as TokioRead, AsyncSeek as TokioSeek, AsyncWrite as TokioWrite, ReadBuf,
    };

    /// The read trait of `futures-io`.
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

    /// The write trait of `futures-io`.
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

    /// The seek trait of `futures-io`.
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

    /// The read trait of `tokio`, also in [`tokio_io`](crate::tokio_io).
    impl TokioRead for File {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            TokioRead::poll_read(Pin::new(&mut self.get_mut().inner), cx, buf)
        }
    }

    /// The write trait of `tokio`, also in [`tokio_io`](crate::tokio_io).
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

    /// The seek trait of `tokio`, also in [`tokio_io`](crate::tokio_io).
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

// With smol, `smol::Unblock` runs the reads on the blocking pool through a
// ring buffer of the read-ahead size. It allocates the ring when the first
// read starts, and it zeroes the ring in parts as it fills, up to its size.
#[cfg(all(feature = "smol", not(feature = "tokio")))]
type ReaderBackend = smol::Unblock<std::fs::File>;
#[cfg(feature = "tokio")]
type ReaderBackend = tokio::fs::File;

/// A read-only async file over a descriptor that is already open.
///
/// The reader streams from the current offset of the descriptor to the end of
/// the file. It does no seek, so a reader over a pipe or over a descriptor
/// positioned past a header costs no extra syscall. [`File`] can also write,
/// seek, and return a `std::fs::File`.
///
/// `FileReader` implements the `AsyncRead` trait of `futures-io` alone. A read
/// into an empty buffer returns 0 and does not end the stream.
///
/// # Read-ahead
///
/// The read-ahead is 256 KiB by default, and no read-ahead is larger.
/// [`with_len_hint`](FileReader::with_len_hint) gives a smaller read-ahead
/// for a file of known length, so a small file costs a small buffer.
///
/// With the `smol` feature, the reads run on the blocking pool and fill a
/// buffer of the read-ahead size.
///
/// With the `tokio` feature, each read is one read on the blocking pool of at
/// most the length of the buffer of the caller. A length hint below 256 KiB
/// also bounds that read.
///
/// If a read is in flight when the reader drops, the descriptor closes on the
/// pool thread after that read returns.
pub struct FileReader {
    inner: ReaderBackend,
}

impl FileReader {
    /// Creates a reader over `file` with a read-ahead for `len` bytes.
    ///
    /// `len` is the number of bytes that the caller expects to read. The
    /// read-ahead is `len + 1` bytes, held between 4 KiB and 256 KiB. The extra
    /// byte lets a read of exactly `len` bytes see the end of the file in the
    /// same run of reads.
    ///
    /// If `len` is less than the real length, the read-ahead is smaller. The
    /// reader still streams to the end of the file.
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

/// Wraps a `std::fs::File` and takes ownership of its descriptor.
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

/// Wraps an `OwnedFd` and takes ownership of the descriptor.
#[cfg(unix)]
impl From<OwnedFd> for FileReader {
    fn from(fd: OwnedFd) -> FileReader {
        FileReader::from(std::fs::File::from(fd))
    }
}

/// The read trait of `futures-io`.
impl futures_io::AsyncRead for FileReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // The smol backend takes a read into an empty buffer for the end of
        // the stream and drops the bytes that it read ahead.
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

// `File` and `FileReader` move freely across tasks and threads.
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
