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
//! [`VerifyingReader`] is the checking counterpart: it hashes what it passes
//! through and fails the read that reaches EOF, and every read after it, when
//! the result differs from the digest the caller expected. Pull wraps fetched
//! payloads in one, so a body that does not hash to the object's identity
//! cannot be stored.
//!
//! All three implement the `futures-io` traits when their inner stream does,
//! and the tokio I/O traits under the `tokio` feature, so they compose with
//! `rt::File`, [`ContentReader`](crate::ContentReader), and network streams
//! without a caller-side adapter.

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

    /// The digest of the bytes hashed so far, leaving the reader usable.
    /// [`VerifyingReader`] checks this at EOF, where consuming the reader is
    /// not an option.
    fn digest_now(&self) -> Checksum {
        Checksum::from_bytes(self.hasher.clone().finalize().into())
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

/// Where a [`VerifyingReader`]'s digest check stands.
enum Checked {
    /// EOF has not been reached, so no comparison has run.
    Pending,
    /// The stream hashed to the expected digest.
    Passed,
    /// The stream hashed to the digest held here, which is not the expected
    /// one.
    Failed(Checksum),
}

pin_project! {
    /// An async reader that checks the stream against an expected digest.
    ///
    /// Bytes pass through unchanged. The check happens at EOF: the final read,
    /// the one that yields zero bytes, fails with
    /// [`InvalidData`](std::io::ErrorKind::InvalidData) when the digest of what
    /// was read differs from the expected one, and every read after it fails
    /// the same way, so a consumer that keeps reading past the mismatch never
    /// sees a clean end of stream. A consumer that stops early never observes
    /// EOF and so never verifies -- the checked property is "this stream, read
    /// whole, hashed to this" -- and a read into an empty buffer touches
    /// neither the stream nor the check.
    pub struct VerifyingReader<R> {
        expected: Checksum,
        checked: Checked,
        #[pin]
        inner: HashingReader<R>,
    }
}

impl<R> VerifyingReader<R> {
    /// Wrap `inner`, expecting its contents to hash to `expected`. As with
    /// [`HashingReader::new`], `hasher` may be pre-seeded to cover leading
    /// bytes -- a content object's framed header, for instance -- that the
    /// stream itself does not carry.
    pub fn new(expected: Checksum, hasher: Sha256, inner: R) -> VerifyingReader<R> {
        VerifyingReader {
            expected,
            checked: Checked::Pending,
            inner: HashingReader::new(hasher, inner),
        }
    }

    /// The digest the stream is checked against.
    pub fn expected(&self) -> &Checksum {
        &self.expected
    }

    /// The number of stream bytes read so far.
    pub fn size(&self) -> u64 {
        self.inner.size()
    }
}

/// The mismatch reported by the read that reaches EOF.
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

/// The hashing streams move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<HashingReader<ostrya_rt::File>>();
    assert_send_sync::<HashingWriter<ostrya_rt::File>>();
    assert_send_sync::<VerifyingReader<ostrya_rt::File>>();
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
            // The bytes were delivered before the check fired at EOF.
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

            // Reading past the failure reports it again rather than EOF.
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
                // A digest that cannot match, to prove no check fires.
                Checksum::sha256(b"something else"),
                Sha256::new(),
                futures_lite::io::Cursor::new(data),
            );
            let mut head = [0u8; 8];
            reader.read_exact(&mut head).await.unwrap();
            assert_eq!(&head, b"a longer");

            // An empty buffer neither reads bytes nor latches EOF.
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
