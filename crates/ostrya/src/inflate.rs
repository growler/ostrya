//! Streaming raw-DEFLATE decoding for archive-mode content objects.
//!
//! Archive-mode content objects (`.filez`) store their payload raw-DEFLATE
//! compressed (no zlib or gzip wrapper), recovered by inspecting the bytes the
//! `ostree` tool writes. [`BufSource`] buffers an `rt::File` into the
//! `futures-io` [`AsyncBufRead`](futures_io::AsyncBufRead) that
//! `async-compression`'s DEFLATE decoder consumes, pulling bounded chunks of
//! input so no whole blob is buffered. The decoder produces bounded chunks of
//! decompressed payload in-task inside `poll_read`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use async_compression::futures::bufread::DeflateDecoder;
use futures_io::{AsyncBufRead, AsyncRead};
use ostrya_rt::File as RtFile;
use pin_project_lite::pin_project;

/// The input read-ahead buffer size. Input is pulled from the underlying
/// reader in chunks of at most this size, bounding memory regardless of the
/// compressed object's size.
const IN_CHUNK: usize = 16 * 1024;

pin_project! {
    /// A bounded read-ahead buffer presenting an [`AsyncRead`] as an
    /// [`AsyncBufRead`] for the DEFLATE decoder to consume.
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
        BufSource {
            inner,
            buf: vec![0u8; IN_CHUNK].into_boxed_slice(),
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

/// The archive payload decoder: raw-DEFLATE over a buffered `rt::File`.
pub(crate) type ArchiveDecoder = DeflateDecoder<BufSource<RtFile>>;

/// Wrap a content-object file (positioned at the raw-DEFLATE payload) in a
/// streaming decoder.
pub(crate) fn archive_decoder(file: RtFile) -> ArchiveDecoder {
    DeflateDecoder::new(BufSource::new(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_compression::futures::bufread::DeflateEncoder;
    use futures_lite::future::block_on;
    use futures_lite::io::{AsyncReadExt, Cursor};

    /// Compress `data` as raw DEFLATE, then decompress it through the same
    /// `BufSource` + decoder pipeline the archive read path uses, a few bytes
    /// at a time.
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
