//! A streaming raw-DEFLATE encoder over an async writer, and the same encoder
//! over an async reader.
//!
//! [`DeflateSink`] is the encoder behind archive-mode content objects: the
//! stored `.filez` payload is its output. It compresses into one output
//! buffer of a fixed size, so a payload of any size goes through in bounded
//! pieces. [`DeflateSink::reset`] starts a new stream in the same compressor
//! and buffer.
//!
//! [`DeflateReader`] reads uncompressed bytes from a source and gives the
//! bytes a [`DeflateSink`] writes for the same input at the same level.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_io::{AsyncBufRead, AsyncRead, AsyncWrite};
use miniz_oxide::deflate::core::CompressorOxide;
use miniz_oxide::deflate::stream::deflate;
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

/// The size of the output buffer [`DeflateSink`] compresses into before it
/// writes the compressed bytes through to the writer under it.
const DEFLATE_CHUNK: usize = 64 * 1024;

/// A streaming raw-DEFLATE encoder over an async writer.
///
/// Each `poll_write` compresses the caller's chunk into a bounded output
/// buffer and passes that buffer on to the writer under it, so a payload of
/// any size goes through in fixed-size pieces. `poll_flush` ends the current
/// DEFLATE block with a sync flush. `poll_close` ends the stream and leaves
/// the writer under it open, so a caller can still write to it, for example to
/// patch a header in front of the stream.
///
/// [`reset`](DeflateSink::reset) starts a new stream in the same compressor
/// and output buffer, so one sink can encode many objects in turn.
pub struct DeflateSink<W> {
    inner: W,
    compressor: Box<CompressorOxide>,
    /// The compressed bytes the compressor has produced.
    out: Vec<u8>,
    /// How many bytes of `out` have reached `inner`.
    sent: usize,
    /// How many bytes of `out` the compressor filled.
    filled: usize,
    /// Whether a sync flush is under way, so the sequence resumes with the
    /// drain steps that follow the sync step rather than a second sync step.
    syncing: bool,
    /// Whether the current DEFLATE block is closed and no input has arrived
    /// since.
    flushed: bool,
    /// Whether the compressor has reached the end of the stream.
    done: bool,
}

impl<W> DeflateSink<W> {
    /// A raw-DEFLATE encoder over `inner` at `level`, which the format holds to
    /// 1 through 9.
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

    /// Start a new stream into `inner` at `level`, and return the writer the
    /// sink held until now.
    ///
    /// The compressor is reset in place and takes `level`, and the output
    /// buffer is kept, so a caller that compresses many objects keeps one sink
    /// and allocates neither again. Compressed bytes that the sink holds and
    /// has not written to the old writer are discarded: a caller that needs
    /// the whole old stream closes the sink before the reset.
    pub fn reset(&mut self, inner: W, level: u8) -> W {
        restart(&mut self.compressor, level);
        self.sent = 0;
        self.filled = 0;
        self.syncing = false;
        self.flushed = true;
        self.done = false;
        std::mem::replace(&mut self.inner, inner)
    }

    /// The writer under the encoder.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin> DeflateSink<W> {
    /// Pass the compressed bytes held in `out` on to `inner`.
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

    /// Run the compressor once over `input` under `flush`, into an empty output
    /// buffer. The step drains first, so a `Pending` return leaves the
    /// compressor untouched and the caller repeats the same step.
    ///
    /// Returns the bytes of `input` the compressor took, the bytes it produced,
    /// and whether it reached the end of the stream. A `Buf` result reports
    /// that the compressor made no progress, which the flush and close
    /// sequences read as the end of the output they wait for.
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

/// A raw-DEFLATE compressor at `level`.
fn compressor(level: u8) -> Box<CompressorOxide> {
    let mut compressor = Box::<CompressorOxide>::default();
    compressor.set_format_and_level(DataFormat::Raw, level);
    compressor
}

/// Start a new stream in `compressor` at `level`.
fn restart(compressor: &mut CompressorOxide, level: u8) {
    compressor.reset();
    compressor.set_format_and_level(DataFormat::Raw, level);
}

/// Run `compressor` once over `input` under `flush` into `out`.
///
/// Returns the bytes of `input` the compressor took, the bytes it wrote to
/// `out`, and whether it reached the end of the stream. A `Buf` result
/// reports that the compressor made no progress.
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
            // The compressor has now run over the caller's chunk, so the block
            // is open and a flush sequence that was under way is abandoned. A
            // `Pending` return above leaves both flags as they stood.
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
        // End the block with a sync step, then take the rest of the output the
        // compressor still holds until a step produces nothing.
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
        // The stream ends here; the writer under the encoder stays open, so a
        // caller can still patch a header in front of the stream.
        Pin::new(&mut me.inner).poll_flush(cx)
    }
}

fn stalled() -> io::Error {
    io::Error::other("the DEFLATE encoder stalled with no output")
}

/// A raw-DEFLATE encoder that reads uncompressed bytes from a source.
///
/// A read gives the compressed form of the source bytes, and end of file
/// follows the end of the stream. The output is the bytes a [`DeflateSink`]
/// writes for the same input at the same level: the reader runs the
/// compressor in the same sequence of steps, each into an empty output
/// buffer. The reader never flushes the stream before its end, because a
/// flush changes the bytes.
///
/// The reader holds one compressor, an input buffer of 64 KiB, and an output
/// buffer of 64 KiB, so a source of any size goes through in bounded memory.
/// It gives the compressed bytes it holds before it reads the source again.
/// [`reset`](DeflateReader::reset) starts a new stream in the same compressor
/// and buffers, so one reader can encode many objects in turn.
///
/// The reader implements `AsyncBufRead`. A caller that reads through
/// `poll_fill_buf` and `consume` takes the compressed bytes from the output
/// buffer with no copy.
pub struct DeflateReader<R> {
    source: R,
    compressor: Box<CompressorOxide>,
    /// The source bytes read and not yet compressed: `input[pos..len]`.
    input: Box<[u8]>,
    pos: usize,
    len: usize,
    /// The compressed bytes not yet read: `out[out_pos..out_len]`.
    out: Box<[u8]>,
    out_pos: usize,
    out_len: usize,
    /// Whether the source has reached end of file.
    eof: bool,
    /// Whether the compressor has reached the end of the stream.
    done: bool,
}

impl<R> DeflateReader<R> {
    /// A raw-DEFLATE encoder over `source` at `level`, which the format holds
    /// to 1 through 9.
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

    /// Start a new stream over `source` at `level`, and return the source the
    /// reader held until now.
    ///
    /// The compressor is reset in place and takes `level`, and the buffers
    /// are kept. Source bytes and compressed bytes of the old stream that the
    /// reader holds are discarded.
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

    /// The source.
    pub fn get_ref(&self) -> &R {
        &self.source
    }

    /// The source. Bytes read from it here do not reach the stream.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.source
    }

    /// The source.
    pub fn into_inner(self) -> R {
        self.source
    }
}

impl<R: AsyncRead + Unpin> DeflateReader<R> {
    /// Run the encoder until the output buffer holds unread bytes or the
    /// stream has ended.
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
    /// Then check the stored bytes against the tool's own with
    /// `archive_objects_are_byte_identical_to_the_fixture` in
    /// `crates/ostrya/tests/write.rs` before you record a constant here
    /// again.
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
    /// encoder, which ends the DEFLATE block with a sync flush, so a caller
    /// that flushes stores different bytes for the same content. The identity
    /// of the object is over the uncompressed bytes, so both forms carry the
    /// same checksum and the tool reads both. The ingest paths of `ostrya`
    /// write straight through and reach [`GOLDEN`] instead.
    const GOLDEN_FLUSHED: &str = "009e2fd466deb6af8f1828281fccd0a7be5fef1356215f1eaa10708a86caa4b3";

    /// One xorshift32 step.
    fn xorshift(state: &mut u32) -> u32 {
        *state ^= *state << 13;
        *state ^= *state >> 17;
        *state ^= *state << 5;
        *state
    }

    /// A payload of one and a half [`DEFLATE_CHUNK`] in three half-chunk
    /// blocks: one block over a four-symbol alphabet, whose long match chains
    /// let the search depth of a level change the output, then two blocks of
    /// an xorshift32 stream the encoder cannot compress. The output holds
    /// literal and match coding, spans more than one [`DEFLATE_CHUNK`], and
    /// takes nine distinct forms over the nine levels.
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
            // full, so the first stream takes the payload twice to produce
            // bytes before its input ends.
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
            // The write sizes the ingest path gives the encoder do not change
            // its output: one byte at a time, an odd size that divides neither
            // the payload nor the chunk, and the whole payload in one write
            // all agree.
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
