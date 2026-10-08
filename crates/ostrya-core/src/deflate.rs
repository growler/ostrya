//! The raw-DEFLATE encoders of archive-mode content objects.
//!
//! `DeflateSink` and `DeflateReader` use the same compressor setup and the
//! same `compress` step. Both give the same bytes for the same input at the
//! same level. The golden hashes of the tests hold this output fixed.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_io::{AsyncBufRead, AsyncRead, AsyncWrite};
use miniz_oxide::deflate::core::CompressorOxide;
use miniz_oxide::deflate::stream::deflate;
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

/// The size of the output buffer of [`DeflateSink`], and of the input buffer
/// and the output buffer of [`DeflateReader`].
const DEFLATE_CHUNK: usize = 64 * 1024;

/// A streaming raw-DEFLATE encoder over an async writer.
///
/// The sink is the encoder of archive-mode content objects. The stored
/// `.filez` payload is its output.
///
/// Each `poll_write` compresses the chunk of the caller into an output buffer
/// of 64 KiB. The sink writes this buffer to the inner writer, so a payload of
/// any size goes through in pieces of a fixed size.
///
/// `poll_flush` ends the current DEFLATE block with a sync flush, so a flush
/// changes the compressed bytes. `poll_close` ends the stream, flushes the
/// inner writer, and leaves it open. A caller can then still write to the
/// inner writer, for example to patch a header in front of the stream.
///
/// [`reset`](DeflateSink::reset) starts a new stream in the same compressor
/// and output buffer, so one sink can encode many objects in turn.
pub struct DeflateSink<W> {
    inner: W,
    compressor: Box<CompressorOxide>,
    /// The output buffer that the compressor fills.
    out: Vec<u8>,
    /// The number of bytes of `out` that `inner` took.
    sent: usize,
    /// The number of bytes of `out` that the compressor filled.
    filled: usize,
    /// `true` while a sync flush is under way. A resumed `poll_flush` then
    /// runs only the steps that take the remaining output, with no second
    /// sync step.
    syncing: bool,
    /// `true` if the current DEFLATE block is closed and no input arrived
    /// after the close.
    flushed: bool,
    /// `true` if the compressor reached the end of the stream.
    done: bool,
}

impl<W> DeflateSink<W> {
    /// Creates a raw-DEFLATE encoder that writes to `inner` at `level`.
    ///
    /// An archive-mode repository uses a level from 1 through 9. The sink
    /// passes `level` to the encoder with no check, and no level causes a
    /// panic.
    pub fn new(inner: W, level: u8) -> DeflateSink<W> {
        DeflateSink {
            inner,
            compressor: compressor(level),
            out: vec![0u8; DEFLATE_CHUNK],
            sent: 0,
            filled: 0,
            syncing: false,
            flushed: true,
            done: false,
        }
    }

    /// Starts a new stream into `inner` at `level` and returns the previous
    /// writer.
    ///
    /// The sink resets the compressor in place with `level` and keeps the
    /// output buffer. A caller that compresses many objects can keep one sink
    /// with no new allocation.
    ///
    /// The sink discards the compressed bytes that it holds and did not write
    /// to the previous writer. A caller that needs the whole previous stream
    /// closes the sink before the reset.
    pub fn reset(&mut self, inner: W, level: u8) -> W {
        restart(&mut self.compressor, level);
        self.sent = 0;
        self.filled = 0;
        self.syncing = false;
        self.flushed = true;
        self.done = false;
        std::mem::replace(&mut self.inner, inner)
    }

    /// Returns the inner writer.
    ///
    /// The sink discards the compressed bytes that it holds and did not write.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin> DeflateSink<W> {
    /// Writes the compressed bytes in `out` to `inner`.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.sent < self.filled {
            let n = std::task::ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.out[self.sent..self.filled])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write returned zero",
                )));
            }
            self.sent += n;
        }
        self.sent = 0;
        self.filled = 0;
        Poll::Ready(Ok(()))
    }

    /// Runs the compressor once over `input` with `flush`, into an empty
    /// output buffer.
    ///
    /// The step drains the buffer first, so a `Pending` return leaves the
    /// compressor untouched. The caller then repeats the same step.
    ///
    /// Returns three values:
    ///
    /// - the number of bytes of `input` that the compressor took
    /// - the number of bytes that it produced
    /// - `true` if it reached the end of the stream
    ///
    /// A `Buf` result reports that the compressor made no progress. The flush
    /// and close sequences read this result as the end of the output that
    /// they wait for.
    fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        input: &[u8],
        flush: MZFlush,
    ) -> Poll<io::Result<(usize, usize, bool)>> {
        std::task::ready!(self.poll_drain(cx))?;
        let step = compress(&mut self.compressor, input, &mut self.out, flush)?;
        self.filled = step.1;
        Poll::Ready(Ok(step))
    }
}

/// Creates a raw-DEFLATE compressor at `level`.
fn compressor(level: u8) -> Box<CompressorOxide> {
    let mut compressor = Box::<CompressorOxide>::default();
    compressor.set_format_and_level(DataFormat::Raw, level);
    compressor
}

/// Starts a new stream in `compressor` at `level`.
fn restart(compressor: &mut CompressorOxide, level: u8) {
    compressor.reset();
    compressor.set_format_and_level(DataFormat::Raw, level);
}

/// Runs `compressor` once over `input` with `flush` into `out`.
///
/// Returns three values:
///
/// - the number of bytes of `input` that the compressor took
/// - the number of bytes that it wrote to `out`
/// - `true` if it reached the end of the stream
///
/// A `Buf` result reports that the compressor made no progress.
fn compress(
    compressor: &mut CompressorOxide,
    input: &[u8],
    out: &mut [u8],
    flush: MZFlush,
) -> io::Result<(usize, usize, bool)> {
    let res = deflate(compressor, input, out, flush);
    let end = match res.status {
        Ok(MZStatus::StreamEnd) => true,
        Ok(_) | Err(MZError::Buf) => false,
        Err(e) => {
            return Err(io::Error::other(format!(
                "the DEFLATE encoder failed: {e:?}"
            )));
        }
    };
    Ok((res.bytes_consumed, res.bytes_written, end))
}

impl<W: AsyncWrite + Unpin> AsyncWrite for DeflateSink<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let me = self.get_mut();
        loop {
            let (taken, produced, _) = std::task::ready!(me.poll_step(cx, buf, MZFlush::None))?;
            // The compressor ran over the chunk of the caller, so the block is
            // open, and the sink abandons a flush that was under way. A
            // `Pending` return from the step leaves both flags unchanged.
            me.flushed = false;
            me.syncing = false;
            if taken > 0 {
                return Poll::Ready(Ok(taken));
            }
            if produced == 0 {
                return Poll::Ready(Err(io::Error::other(
                    "the DEFLATE encoder took no input and produced no output",
                )));
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // A sync step ends the block. The next steps take the remaining
        // output of the compressor, until a step produces nothing.
        while !me.flushed {
            let flush = if me.syncing {
                MZFlush::None
            } else {
                MZFlush::Sync
            };
            let (_, produced, _) = std::task::ready!(me.poll_step(cx, &[], flush))?;
            me.syncing = true;
            if produced == 0 {
                me.flushed = true;
                me.syncing = false;
            }
        }
        std::task::ready!(me.poll_drain(cx))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        while !me.done {
            let (_, _, end) = std::task::ready!(me.poll_step(cx, &[], MZFlush::Finish))?;
            me.done = end;
        }
        std::task::ready!(me.poll_drain(cx))?;
        // The stream ends here. The inner writer stays open, so a caller can
        // still patch a header in front of the stream.
        Pin::new(&mut me.inner).poll_flush(cx)
    }
}

fn stalled() -> io::Error {
    io::Error::other("the DEFLATE encoder stalled with no output")
}

/// A raw-DEFLATE encoder that reads uncompressed bytes from a source.
///
/// A read returns the compressed form of the source bytes. End of file comes
/// after the end of the stream.
///
/// If the caller of a [`DeflateSink`] does not flush, the sink and the reader
/// give the same bytes for one input and level. The reader
/// runs the compressor in the same sequence of steps, each into an empty
/// output buffer. The reader does not flush the stream before its end,
/// because a flush changes the bytes.
///
/// The reader holds one compressor, an input buffer of 64 KiB, and an output
/// buffer of 64 KiB. Its memory does not grow with the size of the source.
/// The reader returns the compressed bytes that it holds before it reads the
/// source again. [`reset`](DeflateReader::reset) starts a new stream in the
/// same compressor and buffers, so one reader can encode many objects in turn.
///
/// The reader implements `AsyncBufRead`. A caller that reads through
/// `poll_fill_buf` and `consume` takes the compressed bytes from the output
/// buffer with no copy.
pub struct DeflateReader<R> {
    source: R,
    compressor: Box<CompressorOxide>,
    /// The source bytes that the reader read and did not compress yet:
    /// `input[pos..len]`.
    input: Box<[u8]>,
    pos: usize,
    len: usize,
    /// The compressed bytes that the caller did not read yet:
    /// `out[out_pos..out_len]`.
    out: Box<[u8]>,
    out_pos: usize,
    out_len: usize,
    /// `true` if the source reached end of file.
    eof: bool,
    /// `true` if the compressor reached the end of the stream.
    done: bool,
}

impl<R> DeflateReader<R> {
    /// Creates a raw-DEFLATE encoder that reads from `source` at `level`.
    ///
    /// `level` has the meaning that [`DeflateSink::new`] states.
    pub fn new(source: R, level: u8) -> DeflateReader<R> {
        DeflateReader {
            source,
            compressor: compressor(level),
            input: vec![0u8; DEFLATE_CHUNK].into_boxed_slice(),
            pos: 0,
            len: 0,
            out: vec![0u8; DEFLATE_CHUNK].into_boxed_slice(),
            out_pos: 0,
            out_len: 0,
            eof: false,
            done: false,
        }
    }

    /// Starts a new stream over `source` at `level` and returns the previous
    /// source.
    ///
    /// The reader resets the compressor in place with `level` and keeps the
    /// buffers. The reader discards the source bytes and the compressed bytes
    /// of the previous stream that it holds.
    pub fn reset(&mut self, source: R, level: u8) -> R {
        restart(&mut self.compressor, level);
        self.pos = 0;
        self.len = 0;
        self.out_pos = 0;
        self.out_len = 0;
        self.eof = false;
        self.done = false;
        std::mem::replace(&mut self.source, source)
    }

    /// Returns a shared reference to the source.
    pub fn get_ref(&self) -> &R {
        &self.source
    }

    /// Returns a mutable reference to the source.
    ///
    /// Bytes that a caller reads from the source through this reference do
    /// not reach the stream.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.source
    }

    /// Returns the source.
    ///
    /// The reader discards the source bytes and the compressed bytes that it
    /// holds.
    pub fn into_inner(self) -> R {
        self.source
    }
}

impl<R: AsyncRead + Unpin> DeflateReader<R> {
    /// Runs the encoder until the output buffer holds unread bytes or the
    /// stream ends.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.out_pos < self.out_len || self.done {
                return Poll::Ready(Ok(()));
            }
            self.out_pos = 0;
            self.out_len = 0;
            if self.pos < self.len {
                let (taken, written, _) = compress(
                    &mut self.compressor,
                    &self.input[self.pos..self.len],
                    &mut self.out,
                    MZFlush::None,
                )?;
                if taken == 0 && written == 0 {
                    return Poll::Ready(Err(stalled()));
                }
                self.pos += taken;
                self.out_len = written;
                continue;
            }
            if !self.eof {
                let n =
                    std::task::ready!(Pin::new(&mut self.source).poll_read(cx, &mut self.input))?;
                if n == 0 {
                    self.eof = true;
                } else {
                    self.pos = 0;
                    self.len = n;
                }
                continue;
            }
            let (_, written, end) =
                compress(&mut self.compressor, &[], &mut self.out, MZFlush::Finish)?;
            if !end && written == 0 {
                return Poll::Ready(Err(stalled()));
            }
            self.out_len = written;
            self.done = end;
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncBufRead for DeflateReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let me = self.get_mut();
        std::task::ready!(me.poll_fill(cx))?;
        Poll::Ready(Ok(&me.out[me.out_pos..me.out_len]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let me = self.get_mut();
        me.out_pos = (me.out_pos + amt).min(me.out_len);
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for DeflateReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let me = self.get_mut();
        std::task::ready!(me.poll_fill(cx))?;
        let n = buf.len().min(me.out_len - me.out_pos);
        buf[..n].copy_from_slice(&me.out[me.out_pos..me.out_pos + n]);
        me.out_pos += n;
        Poll::Ready(Ok(n))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures_lite::future::block_on;
    use futures_lite::io::AsyncWriteExt;
    use sha2::{Digest, Sha256};

    use super::{DEFLATE_CHUNK, DeflateReader, DeflateSink};
    use crate::Checksum;

    /// The SHA-256 of the encoder output over [`golden_payload`], one entry
    /// per `[archive] zlib-level`: index 0 holds level 1, index 8 holds level
    /// 9. The nine entries differ, because `miniz_oxide` gives each level its
    /// own match-search depth and its own choice of greedy or lazy parsing.
    ///
    /// A mismatch states that the encoder output changed, which changes the
    /// bytes stored in every archive-mode content object at that level. Find
    /// the cause -- a `miniz_oxide` release, or an edit to [`DeflateSink`].
    /// Then check the stored bytes against the bytes of the `ostree` command
    /// with `archive_objects_are_byte_identical_to_the_fixture` in
    /// `crates/ostrya/tests/write.rs` before you record a constant here again.
    const GOLDEN: [&str; 9] = [
        "a1fd96479b110a51c3b9c333da0ff6879cd295fc27a98b48c88b70a0ea558bb4",
        "7964fd5c5e4ffb18bf953852b31704681eaf7a4590d488a01be5f213978c0876",
        "e5ff230c2f7715f8883cbd5c19ee1255f165c7e25fc886516c290b0d246954a0",
        "7ae743a6aa5027a1ef08604f6c0a4e6062d39f73879dd0789780aca2e8027932",
        "95b7d927a18b71b941598bf6411029653910307881528355a5b18cccfd3dea0a",
        "b9b31232e8e4458ff831e1de64ba695c0c07b630215e2ce01d372fa2fd8bbcc3",
        "8436585ce3c3eea757ab9d5020de4b41c3f32ac29fdd8b5c02ec8ec51df9067d",
        "c1bc0d4abcb002a3e15241b86c7f200ddc4c71ff30752a7ce933755433ceb88c",
        "b6ddd39fc7e629dfcc81b42ba9706eb6e4e46cd4f90527d3e1ccda0d072faca7",
    ];

    /// The SHA-256 of the encoder output over [`golden_payload`] at the
    /// default level 6 when the caller flushes once, at the halfway point of
    /// the payload. The content writer of `ostrya` passes a flush on to the
    /// encoder, and the encoder ends the DEFLATE block with a sync flush. A
    /// caller that flushes then stores different bytes for the same content.
    ///
    /// The identity of the object is over the uncompressed bytes, so both
    /// forms carry the same checksum and the `ostree` command reads both. The
    /// ingest paths of `ostrya` write straight through and reach [`GOLDEN`].
    const GOLDEN_FLUSHED: &str = "009e2fd466deb6af8f1828281fccd0a7be5fef1356215f1eaa10708a86caa4b3";

    /// One xorshift32 step.
    fn xorshift(state: &mut u32) -> u32 {
        *state ^= *state << 13;
        *state ^= *state >> 17;
        *state ^= *state << 5;
        *state
    }

    /// A payload of one and a half [`DEFLATE_CHUNK`] in three half-chunk
    /// blocks. The first block uses a four-symbol alphabet. Its long match
    /// chains let the search depth of a level change the output. The other
    /// two blocks hold an xorshift32 stream that the encoder cannot compress.
    ///
    /// The output holds literal and match coding, spans more than one
    /// [`DEFLATE_CHUNK`], and takes nine distinct forms over the nine levels.
    fn golden_payload() -> Vec<u8> {
        const BLOCK: usize = DEFLATE_CHUNK / 2;
        let mut out = Vec::with_capacity(3 * BLOCK);
        let mut state: u32 = 0x1234_5678;
        // Two bits per byte, sixteen bytes per step, over `A` to `D`.
        for _ in 0..BLOCK / 16 {
            let word = xorshift(&mut state);
            for k in 0..16 {
                out.push(b'A' + ((word >> (2 * k)) & 3) as u8);
            }
        }
        for _ in 0..2 * BLOCK {
            out.push((xorshift(&mut state) >> 24) as u8);
        }
        out
    }

    /// The encoder output over `data` at `level`, driven in `chunk`-byte
    /// writes and ended with a close, the way the content writer of `ostrya`
    /// ends it.
    fn encode(data: &[u8], level: u8, chunk: usize) -> Vec<u8> {
        block_on(async {
            let mut sink = DeflateSink::new(Vec::new(), level);
            for part in data.chunks(chunk) {
                sink.write_all(part).await.unwrap();
            }
            sink.close().await.unwrap();
            sink.into_inner()
        })
    }

    /// A sink that encoded a first stream at a different level and was then
    /// reset to `level`. The first stream is closed, or it is abandoned
    /// mid-stream when `abandon` is set. Returns the old writer and the output
    /// of the second stream over `data`, in 4093-byte writes.
    fn encode_after_reset(data: &[u8], level: u8, abandon: bool) -> (Vec<u8>, Vec<u8>) {
        block_on(async {
            let mut sink = DeflateSink::new(Vec::new(), level % 9 + 1);
            sink.write_all(&data[..data.len() / 3]).await.unwrap();
            if !abandon {
                sink.close().await.unwrap();
            }
            let old = sink.reset(Vec::new(), level);
            for part in data.chunks(4093) {
                sink.write_all(part).await.unwrap();
            }
            sink.close().await.unwrap();
            (old, sink.into_inner())
        })
    }

    /// A writer that takes `budget` bytes and then stays `Pending`.
    struct Stall {
        taken: Vec<u8>,
        budget: usize,
    }

    impl futures_io::AsyncWrite for Stall {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let me = self.get_mut();
            let n = buf.len().min(me.budget - me.taken.len());
            if n == 0 {
                return Poll::Pending;
            }
            me.taken.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A sink whose first stream, at a different level, stalls on a writer
    /// that stops taking bytes, and which is then reset to `level`. The reset
    /// comes while the output buffer holds compressed bytes that did not reach
    /// the stalled writer. Returns the output of the second stream over
    /// `data`, in 4093-byte writes.
    fn encode_after_a_stalled_reset(data: &[u8], level: u8) -> Vec<u8> {
        block_on(async {
            let mut sink = DeflateSink::new(
                Stall {
                    taken: Vec::new(),
                    budget: 1000,
                },
                level % 9 + 1,
            );
            // The compressor holds its output back until its own buffer is
            // full. The first stream takes the payload twice, so that it
            // produces bytes before its input ends.
            let first = data.repeat(2);
            assert!(
                futures_lite::future::poll_once(sink.write_all(&first))
                    .await
                    .is_none(),
                "level {level}: the first stream stalls"
            );
            assert!(
                sink.sent < sink.filled,
                "level {level}: the output buffer holds unsent bytes at the reset"
            );
            let old = sink.reset(
                Stall {
                    taken: Vec::new(),
                    budget: usize::MAX,
                },
                level,
            );
            assert_eq!(old.taken.len(), 1000);
            for part in data.chunks(4093) {
                sink.write_all(part).await.unwrap();
            }
            sink.close().await.unwrap();
            sink.into_inner().taken
        })
    }

    /// The encoder output over `data` at the default level when the caller
    /// flushes once, at the halfway point of the payload. With `reset` set,
    /// the sink first encodes and closes a stream at level 1 and is then
    /// reset to level 6.
    fn encode_with_a_flush(data: &[u8], reset: bool) -> Vec<u8> {
        block_on(async {
            let mut sink = if reset {
                let mut sink = DeflateSink::new(Vec::new(), 1);
                sink.write_all(data).await.unwrap();
                sink.close().await.unwrap();
                sink.reset(Vec::new(), 6);
                sink
            } else {
                DeflateSink::new(Vec::new(), 6)
            };
            let (head, tail) = data.split_at(data.len() / 2);
            sink.write_all(head).await.unwrap();
            sink.flush().await.unwrap();
            sink.write_all(tail).await.unwrap();
            sink.close().await.unwrap();
            sink.into_inner()
        })
    }

    fn hash(bytes: &[u8]) -> String {
        Checksum::from_bytes(Sha256::digest(bytes).into()).to_hex()
    }

    #[test]
    fn deflate_output_matches_the_golden_hashes() {
        let data = golden_payload();
        assert!(
            data.len() > DEFLATE_CHUNK,
            "the payload spans more than one chunk"
        );
        assert_eq!(
            GOLDEN.iter().collect::<BTreeSet<_>>().len(),
            GOLDEN.len(),
            "each level reaches its own bytes"
        );
        for (i, &want) in GOLDEN.iter().enumerate() {
            let level = i as u8 + 1;
            let out = encode(&data, level, 1);
            assert!(
                out.len() > DEFLATE_CHUNK,
                "level {level}: output spans more than one chunk"
            );
            // The write sizes of the ingest path do not change the output of
            // the encoder. These sizes all give the same bytes:
            // - one byte at a time
            // - an odd size that divides neither the payload nor the chunk
            // - the whole payload in one write
            for chunk in [4093, data.len()] {
                assert_eq!(
                    encode(&data, level, chunk),
                    out,
                    "level {level}, {chunk}-byte writes"
                );
            }
            // A sink reset after an earlier stream, closed or abandoned,
            // gives the bytes of a new sink.
            let (old, after_close) = encode_after_reset(&data, level, false);
            assert!(
                !old.is_empty(),
                "level {level}: reset returns the old writer"
            );
            assert_eq!(after_close, out, "level {level}, reset after a close");
            let (_, after_abandon) = encode_after_reset(&data, level, true);
            assert_eq!(after_abandon, out, "level {level}, reset mid-stream");
            assert_eq!(
                encode_after_a_stalled_reset(&data, level),
                out,
                "level {level}, reset with unsent bytes"
            );
            assert_eq!(hash(&out), want, "DEFLATE level {level} output hash");
        }

        let flushed = hash(&encode_with_a_flush(&data, false));
        assert_eq!(
            flushed, GOLDEN_FLUSHED,
            "DEFLATE level 6 output hash after a flush"
        );
        assert_ne!(
            flushed, GOLDEN[5],
            "a flush ends the DEFLATE block, so it reaches the output"
        );
        assert_eq!(
            hash(&encode_with_a_flush(&data, true)),
            GOLDEN_FLUSHED,
            "DEFLATE level 6 output hash after a reset and a flush"
        );
    }

    /// A source that gives one byte for each read and is `Pending` before
    /// each byte.
    struct Trickle<'a> {
        data: &'a [u8],
        ready: bool,
    }

    impl futures_io::AsyncRead for Trickle<'_> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let me = self.get_mut();
            if !me.ready {
                me.ready = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            me.ready = false;
            let n = buf.len().min(me.data.len()).min(1);
            buf[..n].copy_from_slice(&me.data[..n]);
            me.data = &me.data[n..];
            Poll::Ready(Ok(n))
        }
    }

    /// The rest of the stream of `reader`, in reads of `size` bytes.
    fn read_all<R: futures_io::AsyncRead + Unpin>(
        reader: &mut DeflateReader<R>,
        size: usize,
    ) -> Vec<u8> {
        block_on(async {
            use futures_lite::io::AsyncReadExt;
            let mut out = Vec::new();
            let mut buf = vec![0u8; size];
            loop {
                let n = reader.read(&mut buf).await.unwrap();
                if n == 0 {
                    return out;
                }
                out.extend_from_slice(&buf[..n]);
            }
        })
    }

    /// The rest of the stream of `reader`, through `fill_buf` and `consume`.
    fn read_buffered<R: futures_io::AsyncRead + Unpin>(reader: &mut DeflateReader<R>) -> Vec<u8> {
        block_on(async {
            use futures_lite::io::AsyncBufReadExt;
            let mut out = Vec::new();
            loop {
                let chunk = reader.fill_buf().await.unwrap();
                if chunk.is_empty() {
                    return out;
                }
                assert!(chunk.len() <= DEFLATE_CHUNK, "a chunk fits one buffer");
                let n = chunk.len();
                out.extend_from_slice(chunk);
                reader.consume(n);
            }
        })
    }

    #[test]
    fn deflate_reader_output_matches_the_golden_hashes() {
        let data = golden_payload();
        for (i, &want) in GOLDEN.iter().enumerate() {
            let level = i as u8 + 1;
            let out = read_all(&mut DeflateReader::new(&data[..], level), 4093);
            assert_eq!(hash(&out), want, "level {level}: reader output hash");
            assert_eq!(out, encode(&data, level, 4093), "level {level}: sink bytes");
            for size in [1, DEFLATE_CHUNK + 7, 4 * data.len()] {
                assert_eq!(
                    read_all(&mut DeflateReader::new(&data[..], level), size),
                    out,
                    "level {level}, {size}-byte reads"
                );
            }
            assert_eq!(
                read_buffered(&mut DeflateReader::new(&data[..], level)),
                out,
                "level {level}, buffered reads"
            );
            let trickle = Trickle {
                data: &data,
                ready: false,
            };
            assert_eq!(
                read_all(&mut DeflateReader::new(trickle, level), 4093),
                out,
                "level {level}, a source of one byte after each Pending"
            );

            // A reset after a complete stream, and after a stream read
            // halfway, gives the bytes of a new reader.
            let mut reader = DeflateReader::new(&data[..data.len() / 3], level % 9 + 1);
            assert!(!read_all(&mut reader, 4093).is_empty());
            let old = reader.reset(&data[..], level);
            assert!(
                old.is_empty(),
                "reset returns the old source, read to its end"
            );
            assert_eq!(
                read_all(&mut reader, 4093),
                out,
                "level {level}, reset after the end"
            );

            let mut reader = DeflateReader::new(&data[..], level % 9 + 1);
            block_on(async {
                use futures_lite::io::AsyncReadExt;
                let mut buf = vec![0u8; 1000];
                reader.read_exact(&mut buf).await.unwrap();
            });
            reader.reset(&data[..], level);
            assert_eq!(
                read_buffered(&mut reader),
                out,
                "level {level}, reset mid-stream"
            );

            // An empty source gives the empty stream of the sink.
            let empty = read_all(&mut DeflateReader::new(&[][..], level), 4093);
            assert_eq!(empty, encode(&[], level, 1), "level {level}, empty input");
            assert!(!empty.is_empty(), "the empty stream still ends");
            assert_eq!(
                read_all(&mut reader, 4093),
                Vec::<u8>::new(),
                "end of file after the end of the stream"
            );
        }
    }

    /// A source that gives its data, then is `Pending` with no wake until
    /// `open` is set, and then reaches end of file.
    struct Held<'a> {
        data: &'a [u8],
        open: bool,
    }

    impl futures_io::AsyncRead for Held<'_> {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let me = self.get_mut();
            if me.data.is_empty() && !me.open {
                return Poll::Pending;
            }
            let n = buf.len().min(me.data.len());
            buf[..n].copy_from_slice(&me.data[..n]);
            me.data = &me.data[n..];
            Poll::Ready(Ok(n))
        }
    }

    #[test]
    fn deflate_reader_gives_its_output_before_it_waits_on_the_source() {
        use futures_io::AsyncBufRead;
        use miniz_oxide::deflate::core::CompressorOxide;
        use miniz_oxide::deflate::stream::deflate;
        use miniz_oxide::{DataFormat, MZFlush};

        let mut state = 7;
        let data: Vec<u8> = (0..4 * DEFLATE_CHUNK)
            .map(|_| xorshift(&mut state) as u8)
            .collect();
        // The bytes the compressor gives for the whole input with no flush,
        // run over the input in pieces of the reader's input buffer.
        let mut compressor = Box::<CompressorOxide>::default();
        compressor.set_format_and_level(DataFormat::Raw, 1);
        let mut out = vec![0u8; DEFLATE_CHUNK];
        let mut ready = 0;
        for piece in data.chunks(DEFLATE_CHUNK) {
            let mut pos = 0;
            while pos < piece.len() {
                let res = deflate(&mut compressor, &piece[pos..], &mut out, MZFlush::None);
                pos += res.bytes_consumed;
                ready += res.bytes_written;
            }
        }
        assert!(ready > 0);

        let mut reader = DeflateReader::new(
            Held {
                data: &data,
                open: false,
            },
            1,
        );
        let mut got = Vec::new();
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        while let Poll::Ready(chunk) = Pin::new(&mut reader).poll_fill_buf(&mut cx) {
            let chunk = chunk.unwrap();
            assert!(!chunk.is_empty(), "no end of file while the source waits");
            let n = chunk.len();
            got.extend_from_slice(chunk);
            Pin::new(&mut reader).consume(n);
        }
        assert_eq!(got.len(), ready, "every compressed byte before the wait");
        reader.get_mut().open = true;
        got.extend(read_all(&mut reader, 4093));
        assert_eq!(got, encode(&data, 1, 4093));
    }

    #[test]
    fn deflate_reader_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DeflateReader<&[u8]>>();
    }
}
