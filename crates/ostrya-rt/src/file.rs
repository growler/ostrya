//! An async file over an already-open descriptor.
//!
//! Opens are performed elsewhere through `rustix` (fd-relative `openat`);
//! [`File`] only streams over a descriptor it is handed. It wraps the
//! backend's async file (`smol::fs::File` or `tokio::fs::File`) and presents
//! the `futures-io` traits under both backends, so core code stays generic.
//! Under the `tokio` feature it additionally implements the tokio I/O traits
//! for tokio-native callers.

use std::io;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(all(feature = "smol", not(feature = "tokio")))]
type Backend = smol::fs::File;
#[cfg(feature = "tokio")]
type Backend = tokio::fs::File;

/// An async file over an already-open descriptor.
///
/// Constructed from a `std::fs::File` or an `OwnedFd`; both take ownership of
/// the descriptor. The current descriptor offset is preserved, so a caller
/// that seeked before wrapping (past a framed header, for instance) streams
/// from that offset.
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
    /// so this flushes and then duplicates the descriptor; the returned file
    /// shares the same open file description.
    pub async fn into_std(self) -> std::fs::File {
        #[cfg(feature = "tokio")]
        {
            self.inner.into_std().await
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            use smol::io::AsyncWriteExt;
            use std::os::fd::AsFd;

            let mut inner = self.inner;
            let _ = inner.flush().await;
            let fd = inner
                .as_fd()
                .try_clone_to_owned()
                .expect("duplicate descriptor for into_std");
            std::fs::File::from(fd)
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

/// `File` moves freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<File>();
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
