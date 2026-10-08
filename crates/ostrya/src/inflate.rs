//! A streaming raw-DEFLATE decoder for the content objects of an archive
//! repository.
//!
//! An archive-mode content object (`.filez`) stores its payload as raw DEFLATE,
//! with no zlib or gzip wrapper. The objects that the `ostree` command writes
//! show this form.
//!
//! `BufSource` buffers an `rt::FileReader` as the `futures_io::AsyncBufRead`
//! that the DEFLATE decoder of `async-compression` reads. It reads the input
//! in bounded chunks, so it never holds a whole blob in memory. The decoder
//! makes bounded chunks of decompressed payload in the task, inside
//! `poll_read`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use async_compression::futures::bufread::DeflateDecoder;
use futures_io::{AsyncBufRead, AsyncRead};
use ostrya_rt::FileReader;
use pin_project_lite::pin_project;

/// The size of the input read-ahead buffer.
///
/// The buffer reads the inner reader in chunks of at most this size. This
/// bounds the memory use for a compressed object of any size.
const IN_CHUNK: usize = 16 * 1024;

pin_project! {
    /// A bounded read-ahead buffer that gives the DEFLATE decoder an
    /// `AsyncBufRead` over an `AsyncRead`.
    pub(crate) struct BufSource<R> {
        #[pin]
        inner: R,
        buf: Box<[u8]>,
        pos: usize,
        cap: usize,
    }
}

impl<R> BufSource<R> {
    pub(crate) fn new(inner: R) -> BufSource<R> {
        BufSource::with_len_hint(inner, IN_CHUNK as u64)
    }

    /// Creates a `BufSource` for an input of about `len` bytes.
    ///
    /// The buffer holds `len + 1` bytes, at least 1 byte and at most
    /// `IN_CHUNK`.
    pub(crate) fn with_len_hint(inner: R, len: u64) -> BufSource<R> {
        let size = usize::try_from(len.saturating_add(1)).map_or(IN_CHUNK, |n| n.min(IN_CHUNK));
        BufSource {
            inner,
            buf: vec![0u8; size].into_boxed_slice(),
            pos: 0,
            cap: 0,
        }
    }
}

impl<R: AsyncRead> AsyncRead for BufSource<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let available = ready!(self.as_mut().poll_fill_buf(cx))?;
        let n = available.len().min(out.len());
        out[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Poll::Ready(Ok(n))
    }
}

impl<R: AsyncRead> AsyncBufRead for BufSource<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let me = self.project();
        if *me.pos >= *me.cap {
            let n = ready!(me.inner.poll_read(cx, &mut me.buf[..]))?;
            *me.pos = 0;
            *me.cap = n;
        }
        Poll::Ready(Ok(&me.buf[*me.pos..*me.cap]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let me = self.project();
        *me.pos = (*me.pos + amt).min(*me.cap);
    }
}

/// The decoder of an archive payload: raw DEFLATE over a buffered
/// `rt::FileReader`.
pub(crate) type ArchiveDecoder = DeflateDecoder<BufSource<FileReader>>;

/// Returns a streaming decoder over a content-object file.
///
/// The position of `file` must be at the start of the raw-DEFLATE payload.
/// `len` is the length of the stream on disk, and it bounds the input buffer.
pub(crate) fn archive_decoder(file: FileReader, len: u64) -> ArchiveDecoder {
    DeflateDecoder::new(BufSource::with_len_hint(file, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_compression::futures::bufread::DeflateEncoder;
    use futures_lite::future::block_on;
    use futures_lite::io::{AsyncReadExt, Cursor};

    /// Compresses `data` as raw DEFLATE and decompresses it again.
    ///
    /// The decompression goes through the `BufSource` and decoder pipeline of
    /// the archive read path. It reads `read_chunk` bytes at a time.
    fn round_trip(data: &[u8], read_chunk: usize) -> Vec<u8> {
        block_on(async {
            let mut encoder = DeflateEncoder::new(Cursor::new(data.to_vec()));
            let mut compressed = Vec::new();
            encoder.read_to_end(&mut compressed).await.unwrap();

            let mut decoder = DeflateDecoder::new(BufSource::new(Cursor::new(compressed)));
            let mut out = Vec::new();
            let mut buf = vec![0u8; read_chunk.max(1)];
            loop {
                let n = decoder.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            out
        })
    }

    #[test]
    fn round_trips_small_and_empty() {
        assert_eq!(round_trip(b"", 8), b"");
        assert_eq!(round_trip(b"hello ostree\n", 4), b"hello ostree\n");
    }

    #[test]
    fn round_trips_large_payload_in_tiny_reads() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(round_trip(&data, 1), data);
    }

    #[test]
    fn rejects_corrupt_input() {
        block_on(async {
            let mut decoder = DeflateDecoder::new(BufSource::new(Cursor::new(vec![0xffu8; 32])));
            let mut buf = [0u8; 16];
            assert!(decoder.read(&mut buf).await.is_err());
        });
    }
}
