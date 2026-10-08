//! Streaming SHA-256 wrappers for async readers and writers.
//!
//! The crate root re-exports [`HashingReader`], [`HashingWriter`], and
//! [`VerifyingReader`]. Their docs hold the facts for API readers.

use std::pin::Pin;
use std::task::{Context, Poll, ready};

use ostrya_core::Checksum;
use pin_project_lite::pin_project;
use sha2::{Digest, Sha256};

pin_project! {
    /// An async reader that hashes every byte that it yields.
    ///
    /// The reader feeds each byte that it reads from the inner stream to a
    /// SHA-256 digester and counts the bytes. [`finalize`](Self::finalize)
    /// consumes the reader and returns the checksum and the byte count. The
    /// digester is always SHA-256, the one hash function of the ostree object
    /// format.
    ///
    /// If `R` implements `futures_io::AsyncRead`, the reader implements it
    /// too. Under the `tokio` feature, the same rule applies to the tokio
    /// `AsyncRead`. The reader can wrap an `ostrya_rt::File`, a
    /// [`ContentReader`](crate::ContentReader), or a network stream with no
    /// adapter.
    ///
    /// # Seeded digesters
    ///
    /// [`new`](Self::new) takes the digester by value, so the caller can feed
    /// leading bytes to it before the stream. The checksum of a content object
    /// covers the framed file header and then the raw payload. To compute it,
    /// seed the digester with the header bytes and stream the payload through
    /// the reader. The byte count holds the stream bytes alone.
    pub struct HashingReader<R> {
        hasher: Sha256,
        count: u64,
        #[pin]
        inner: R,
    }
}

impl<R> HashingReader<R> {
    /// Creates a reader that feeds the bytes that it reads from `inner` to
    /// `hasher`.
    ///
    /// For a digest of the stream alone, pass `Sha256::new()`. To include
    /// leading bytes before the stream, for example a framed file header, pass
    /// a digester that already holds them.
    pub fn new(hasher: Sha256, inner: R) -> HashingReader<R> {
        HashingReader {
            hasher,
            count: 0,
            inner,
        }
    }

    /// Returns the number of stream bytes hashed so far.
    pub fn size(&self) -> u64 {
        self.count
    }

    /// Consumes the reader and returns the SHA-256 checksum and the byte count.
    ///
    /// The checksum covers the whole stream only if the caller read the inner
    /// stream to EOF.
    pub fn finalize(self) -> (Checksum, u64) {
        (
            Checksum::from_bytes(self.hasher.finalize().into()),
            self.count,
        )
    }

    /// Returns the digest of the bytes hashed so far and keeps the reader.
    /// [`VerifyingReader`] verifies this digest at EOF, where it cannot
    /// consume the reader.
    fn digest_now(&self) -> Checksum {
        Checksum::from_bytes(self.hasher.clone().finalize().into())
    }
}

pin_project! {
    /// An async writer that hashes every byte that it forwards.
    ///
    /// The writer feeds each byte that the inner writer accepts to a SHA-256
    /// digester and counts the bytes. [`finalize`](Self::finalize) consumes
    /// the writer and returns the checksum and the byte count. [`new`](Self::new)
    /// takes a seeded digester, as [`HashingReader::new`] does.
    ///
    /// If `W` implements `futures_io::AsyncWrite`, the writer implements it
    /// too. Under the `tokio` feature, the same rule applies to the tokio
    /// `AsyncWrite`.
    pub struct HashingWriter<W> {
        hasher: Sha256,
        count: u64,
        #[pin]
        inner: W,
    }
}

impl<W> HashingWriter<W> {
    /// Creates a writer that feeds the bytes that it forwards to `inner` to
    /// `hasher`.
    ///
    /// For a digest of the stream alone, pass `Sha256::new()`. To include
    /// leading bytes before the stream, pass a digester that already holds
    /// them.
    pub fn new(hasher: Sha256, inner: W) -> HashingWriter<W> {
        HashingWriter {
            hasher,
            count: 0,
            inner,
        }
    }

    /// Returns the number of stream bytes hashed so far.
    pub fn size(&self) -> u64 {
        self.count
    }

    /// Consumes the writer and returns the SHA-256 checksum and the byte count.
    ///
    /// To make the bytes durable, the caller must flush or close the inner
    /// writer before this call.
    pub fn finalize(self) -> (Checksum, u64) {
        (
            Checksum::from_bytes(self.hasher.finalize().into()),
            self.count,
        )
    }
}

/// The state of the digest check of a [`VerifyingReader`].
enum Checked {
    /// The reader did not reach EOF, so no comparison ran.
    Pending,
    /// The stream hashed to the expected digest.
    Passed,
    /// The stream hashed to the digest held here, which differs from the
    /// expected one.
    Failed(Checksum),
}

pin_project! {
    /// An async reader that verifies a stream against an expected checksum.
    ///
    /// The bytes pass through unchanged. The reader hashes them with SHA-256
    /// and verifies the digest at EOF. A caller can wrap a fetched payload in
    /// one. Then a body that does not hash to the checksum of the object fails
    /// at EOF.
    ///
    /// If `R` implements `futures_io::AsyncRead`, the reader implements it
    /// too. Under the `tokio` feature, the same rule applies to the tokio
    /// `AsyncRead`.
    ///
    /// # Verification
    ///
    /// - The read that reaches EOF is the read that yields zero bytes. If the
    ///   digest of the stream differs from the expected checksum, this read
    ///   fails with [`InvalidData`](std::io::ErrorKind::InvalidData).
    /// - The error message is `checksum mismatch: expected <expected>,
    ///   computed <actual>`.
    /// - Each read after a mismatch fails with the same error. A consumer that
    ///   reads past the mismatch never sees a clean end of stream.
    /// - After a match, each later read returns zero bytes.
    /// - A consumer that stops before EOF never verifies the stream. The
    ///   verified property is "this stream, read whole, hashes to this
    ///   checksum".
    /// - A read into an empty buffer reads nothing from the stream and does
    ///   not change the state of the check.
    pub struct VerifyingReader<R> {
        expected: Checksum,
        checked: Checked,
        #[pin]
        inner: HashingReader<R>,
    }
}

impl<R> VerifyingReader<R> {
    /// Creates a reader that expects the contents of `inner` to hash to
    /// `expected`.
    ///
    /// As with [`HashingReader::new`], `hasher` can hold leading bytes that
    /// the stream does not carry, for example the framed header of a content
    /// object.
    pub fn new(expected: Checksum, hasher: Sha256, inner: R) -> VerifyingReader<R> {
        VerifyingReader {
            expected,
            checked: Checked::Pending,
            inner: HashingReader::new(hasher, inner),
        }
    }

    /// Returns the checksum that the reader verifies the stream against.
    pub fn expected(&self) -> &Checksum {
        &self.expected
    }

    /// Returns the number of stream bytes read so far.
    pub fn size(&self) -> u64 {
        self.inner.size()
    }
}

/// Returns the error that reports a digest mismatch at EOF and after it.
fn mismatch(expected: &Checksum, actual: &Checksum) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("checksum mismatch: expected {expected}, computed {actual}"),
    )
}

impl<R: futures_io::AsyncRead> futures_io::AsyncRead for VerifyingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut me = self.project();
        match me.checked {
            Checked::Pending => {}
            Checked::Passed => return Poll::Ready(Ok(0)),
            Checked::Failed(actual) => return Poll::Ready(Err(mismatch(me.expected, actual))),
        }
        let n = ready!(me.inner.as_mut().poll_read(cx, buf))?;
        if n == 0 {
            let actual = me.inner.digest_now();
            if actual != *me.expected {
                let error = mismatch(me.expected, &actual);
                *me.checked = Checked::Failed(actual);
                return Poll::Ready(Err(error));
            }
            *me.checked = Checked::Passed;
        }
        Poll::Ready(Ok(n))
    }
}

#[cfg(feature = "tokio")]
impl<R: ostrya_rt::tokio_io::AsyncRead> ostrya_rt::tokio_io::AsyncRead for VerifyingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ostrya_rt::tokio_io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut me = self.project();
        match me.checked {
            Checked::Pending => {}
            Checked::Passed => return Poll::Ready(Ok(())),
            Checked::Failed(actual) => return Poll::Ready(Err(mismatch(me.expected, actual))),
        }
        let before = buf.filled().len();
        ready!(me.inner.as_mut().poll_read(cx, buf))?;
        if buf.filled().len() == before {
            let actual = me.inner.digest_now();
            if actual != *me.expected {
                let error = mismatch(me.expected, &actual);
                *me.checked = Checked::Failed(actual);
                return Poll::Ready(Err(error));
            }
            *me.checked = Checked::Passed;
        }
        Poll::Ready(Ok(()))
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

/// Checks at compile time that the hashing streams are `Send + Sync`, so they
/// move across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<HashingReader<ostrya_rt::File>>();
    assert_send_sync::<HashingWriter<ostrya_rt::File>>();
    assert_send_sync::<VerifyingReader<ostrya_rt::File>>();
};

/// Checks at compile time that, under the `tokio` feature, the hashing streams
/// implement the tokio I/O traits if their inner stream does.
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

    /// An in-memory `futures-io` writer for the tests of `HashingWriter`.
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
            // The size counts the streamed payload and excludes the seed.
            assert_eq!(size, payload.len() as u64);
            // The digest covers the header and then the payload.
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
    fn verifying_reader_passes_a_matching_stream_through() {
        block_on(async {
            let data = b"verified payload";
            let mut reader = VerifyingReader::new(
                Checksum::sha256(data),
                Sha256::new(),
                futures_lite::io::Cursor::new(data),
            );
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, data);
            assert_eq!(reader.size(), data.len() as u64);
            assert_eq!(reader.expected(), &Checksum::sha256(data));
        });
    }

    #[test]
    fn verifying_reader_fails_the_final_read_on_a_mismatch() {
        block_on(async {
            let data = b"payload as delivered";
            let mut reader = VerifyingReader::new(
                Checksum::sha256(b"payload as promised"),
                Sha256::new(),
                futures_lite::io::Cursor::new(data),
            );
            let mut out = Vec::new();
            let err = reader.read_to_end(&mut out).await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("checksum mismatch"), "{err}");
            // The reader delivered the bytes before the check failed at EOF.
            assert_eq!(out, data);
        });
    }

    #[test]
    fn verifying_reader_repeats_the_mismatch_on_every_later_read() {
        block_on(async {
            let data = b"payload as delivered";
            let mut reader = VerifyingReader::new(
                Checksum::sha256(b"payload as promised"),
                Sha256::new(),
                futures_lite::io::Cursor::new(data),
            );
            let mut out = Vec::new();
            let first = reader.read_to_end(&mut out).await.unwrap_err();

            // Each read after the failure returns the same error, never EOF.
            let mut buf = [0u8; 8];
            for _ in 0..2 {
                let err = reader.read(&mut buf).await.unwrap_err();
                assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
                assert_eq!(err.to_string(), first.to_string());
            }
            let err = reader.read_to_end(&mut out).await.unwrap_err();
            assert_eq!(err.to_string(), first.to_string());
        });
    }

    #[test]
    fn verifying_reader_checks_a_preseeded_digester_and_an_empty_stream() {
        block_on(async {
            let header = b"framed-header";
            let payload = b"payload-bytes";
            let mut whole = header.to_vec();
            whole.extend_from_slice(payload);
            let mut seeded = Sha256::new();
            seeded.update(header);
            let mut reader = VerifyingReader::new(
                Checksum::sha256(&whole),
                seeded,
                futures_lite::io::Cursor::new(payload),
            );
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, payload);

            // An empty stream verifies against the digest of no bytes.
            let mut reader = VerifyingReader::new(
                Checksum::sha256(b""),
                Sha256::new(),
                futures_lite::io::Cursor::new(&[]),
            );
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            assert!(out.is_empty());
        });
    }

    #[test]
    fn a_reader_stopped_before_eof_never_verifies() {
        block_on(async {
            let data = b"a longer payload than the caller reads";
            let mut reader = VerifyingReader::new(
                // This digest cannot match, so the test shows that no check runs.
                Checksum::sha256(b"something else"),
                Sha256::new(),
                futures_lite::io::Cursor::new(data),
            );
            let mut head = [0u8; 8];
            reader.read_exact(&mut head).await.unwrap();
            assert_eq!(&head, b"a longer");

            // A read into an empty buffer reads no bytes and records no EOF.
            assert_eq!(reader.read(&mut []).await.unwrap(), 0);
            assert_eq!(reader.size(), 8);
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
