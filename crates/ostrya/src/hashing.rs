//! Streaming SHA-256 wrappers, the primitives the write path builds on.
//!
//! [`HashingReader`] and [`HashingWriter`] wrap an inner async stream and feed
//! a SHA-256 digester with every byte they pass through, tracking the byte
//! count. [`finalize`](HashingReader::finalize) consumes the wrapper and
//! yields the object identity and the number of bytes seen. ostree hashes with
//! SHA-256 throughout, so the digester is fixed rather than generic.
//!
//! The digester is supplied by value and may be pre-seeded: a content-object
//! identity covers the framed file header before the raw payload, so the write
//! path seeds the header bytes and then streams the payload through the reader.
//!
//! Both wrappers implement the `futures-io` traits when their inner stream
//! does, and the tokio I/O traits under the `tokio` feature, so they compose
//! with `rt::File`, [`ContentReader`](crate::ContentReader), and network
//! streams without a caller-side adapter.

use std::pin::Pin;
use std::task::{Context, Poll, ready};

use ostrya_core::Checksum;
use pin_project_lite::pin_project;
use sha2::{Digest, Sha256};

pin_project! {
    /// An async reader that hashes every byte it yields.
    pub struct HashingReader<R> {
        hasher: Sha256,
        count: u64,
        #[pin]
        inner: R,
    }
}

impl<R> HashingReader<R> {
    /// Wrap `inner`, feeding read bytes into `hasher`. Pass `Sha256::new()`
    /// for an unseeded digest, or a pre-updated digester to cover leading
    /// bytes (such as a framed file header) before the stream.
    pub fn new(hasher: Sha256, inner: R) -> HashingReader<R> {
        HashingReader {
            hasher,
            count: 0,
            inner,
        }
    }

    /// The number of stream bytes hashed so far.
    pub fn size(&self) -> u64 {
        self.count
    }

    /// Consume the reader and return the SHA-256 digest and the byte count.
    /// Meaningful once the inner stream has been read to EOF.
    pub fn finalize(self) -> (Checksum, u64) {
        (
            Checksum::from_bytes(self.hasher.finalize().into()),
            self.count,
        )
    }
}

pin_project! {
    /// An async writer that hashes every byte it forwards.
    pub struct HashingWriter<W> {
        hasher: Sha256,
        count: u64,
        #[pin]
        inner: W,
    }
}

impl<W> HashingWriter<W> {
    /// Wrap `inner`, feeding forwarded bytes into `hasher`. Pass
    /// `Sha256::new()` for an unseeded digest, or a pre-updated digester to
    /// cover leading bytes before the stream.
    pub fn new(hasher: Sha256, inner: W) -> HashingWriter<W> {
        HashingWriter {
            hasher,
            count: 0,
            inner,
        }
    }

    /// The number of stream bytes hashed so far.
    pub fn size(&self) -> u64 {
        self.count
    }

    /// Consume the writer and return the SHA-256 digest and the byte count.
    /// Flush or close the inner writer first for the bytes to be durable.
    pub fn finalize(self) -> (Checksum, u64) {
        (
            Checksum::from_bytes(self.hasher.finalize().into()),
            self.count,
        )
    }
}

impl<R: futures_io::AsyncRead> futures_io::AsyncRead for HashingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.project();
        let n = ready!(me.inner.poll_read(cx, buf))?;
        me.hasher.update(&buf[..n]);
        *me.count += n as u64;
        Poll::Ready(Ok(n))
    }
}

impl<W: futures_io::AsyncWrite> futures_io::AsyncWrite for HashingWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.project();
        let n = ready!(me.inner.poll_write(cx, buf))?;
        me.hasher.update(&buf[..n]);
        *me.count += n as u64;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_close(cx)
    }
}

#[cfg(feature = "tokio")]
impl<R: ostrya_rt::tokio_io::AsyncRead> ostrya_rt::tokio_io::AsyncRead for HashingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ostrya_rt::tokio_io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.project();
        let before = buf.filled().len();
        ready!(me.inner.poll_read(cx, buf))?;
        let fresh = &buf.filled()[before..];
        me.hasher.update(fresh);
        *me.count += fresh.len() as u64;
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "tokio")]
impl<W: ostrya_rt::tokio_io::AsyncWrite> ostrya_rt::tokio_io::AsyncWrite for HashingWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.project();
        let n = ready!(me.inner.poll_write(cx, buf))?;
        me.hasher.update(&buf[..n]);
        *me.count += n as u64;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

/// The hashing streams move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<HashingReader<ostrya_rt::File>>();
    assert_send_sync::<HashingWriter<ostrya_rt::File>>();
};

/// Under the `tokio` feature the hashing streams speak the tokio I/O traits
/// when their inner stream does, so tokio-native callers need no adapter.
#[cfg(feature = "tokio")]
const _: fn() = || {
    fn assert_tokio_read<T: ostrya_rt::tokio_io::AsyncRead>() {}
    fn assert_tokio_write<T: ostrya_rt::tokio_io::AsyncWrite>() {}
    assert_tokio_read::<HashingReader<ostrya_rt::File>>();
    assert_tokio_write::<HashingWriter<ostrya_rt::File>>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
    use ostrya_rt::block_on;

    /// A minimal in-memory `futures-io` writer for exercising `HashingWriter`.
    struct VecSink(Vec<u8>);

    impl futures_io::AsyncWrite for VecSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn reader_hashes_payload_and_reports_size() {
        block_on(async {
            let data = b"hello ostrya\n";
            let mut reader = HashingReader::new(Sha256::new(), futures_lite::io::Cursor::new(data));
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, data);
            assert_eq!(reader.size(), data.len() as u64);
            let (digest, size) = reader.finalize();
            assert_eq!(size, data.len() as u64);
            assert_eq!(digest, Checksum::sha256(data));
        });
    }

    #[test]
    fn reader_covers_a_preseeded_digester() {
        block_on(async {
            let header = b"framed-header";
            let payload = b"payload-bytes";
            let mut seeded = Sha256::new();
            seeded.update(header);
            let mut reader = HashingReader::new(seeded, futures_lite::io::Cursor::new(payload));
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            let (digest, size) = reader.finalize();
            // The size counts only the streamed payload, not the seed.
            assert_eq!(size, payload.len() as u64);
            // The digest covers header followed by payload.
            let mut whole = Vec::new();
            whole.extend_from_slice(header);
            whole.extend_from_slice(payload);
            assert_eq!(digest, Checksum::sha256(&whole));
        });
    }

    #[test]
    fn reader_handles_empty_payload() {
        block_on(async {
            let mut reader = HashingReader::new(Sha256::new(), futures_lite::io::Cursor::new(&[]));
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            assert!(out.is_empty());
            let (digest, size) = reader.finalize();
            assert_eq!(size, 0);
            assert_eq!(digest, Checksum::sha256(b""));
        });
    }

    #[test]
    fn writer_hashes_forwarded_bytes() {
        block_on(async {
            let data = b"streamed through the writer";
            let mut writer = HashingWriter::new(Sha256::new(), VecSink(Vec::new()));
            writer.write_all(data).await.unwrap();
            writer.flush().await.unwrap();
            assert_eq!(writer.size(), data.len() as u64);
            let (digest, size) = writer.finalize();
            assert_eq!(size, data.len() as u64);
            assert_eq!(digest, Checksum::sha256(data));
        });
    }
}
