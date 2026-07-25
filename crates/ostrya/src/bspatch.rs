//! bspatch for static-delta `B` (bspatch) operations, streaming its output.
//!
//! The `B` opcode carries a bsdiff patch produced by the `ostree` tool. The
//! stream is the classic bsdiff patch with its three streams interleaved and
//! stored uncompressed (the enclosing delta part is xz-compressed as a whole,
//! so the patch bytes are not separately compressed). The layout, recovered by
//! observing the tool (see `format-reference.md`, "Static delta wire format"),
//! is a sequence of blocks, each:
//!
//! - a 24-byte control block of three signed 64-bit integers in bsdiff's
//!   `offtin` encoding -- `diff_len`, `extra_len`, and a source `seek`;
//! - `diff_len` bytes, each added (wrapping) to the corresponding source byte
//!   at the current source position;
//! - `extra_len` bytes copied verbatim;
//!
//! after which the source position advances by `diff_len` and then by `seek`.
//! Blocks are consumed until the output reaches `new_size`, which the delta's
//! `open` operation supplies. There is no header and no block count: `new_size`
//! is the sole terminator.
//!
//! The output is produced strictly forward, so it is streamed to the caller's
//! writer in bounded pieces rather than materializing the whole target object.
//! The random-access `source` is the read-source object; a large one is a
//! memory map, so indexing it reads demand-paged file cache rather than heap.
//!
//! The `offtin` encoding is little-endian sign-magnitude: the eight bytes hold
//! the magnitude little-endian, and the top bit of the last byte is a sign flag
//! (set means negative), so it is not two's complement.

use futures_io::AsyncWrite;
use futures_lite::AsyncWriteExt;

use crate::error::{Error, Result};

/// The bounded staging buffer for a diff run's overlaid bytes.
const OUT_CHUNK: usize = 128 * 1024;

/// Decode one bsdiff `offtin` 64-bit integer (little-endian magnitude, top bit
/// of the final byte a sign flag).
fn offtin(buf: &[u8; 8]) -> i64 {
    let mut y = i64::from(buf[7] & 0x7f);
    for i in (0..7).rev() {
        y = y * 256 + i64::from(buf[i]);
    }
    if buf[7] & 0x80 != 0 { -y } else { y }
}

/// Apply a bspatch `stream` against `source`, writing exactly `new_size` bytes
/// to `out`. `source` is the whole content of the read-source object; `stream`
/// is the `B` operation's slice of the delta part's data source.
///
/// Every offset is bounds-checked, so a malformed patch fails with
/// [`Error::InvalidFormat`] rather than panicking or reading out of range. The
/// produced object's checksum is asserted separately by the delta's `close`
/// operation, so a patch that applies cleanly but yields the wrong bytes is
/// still caught downstream.
pub(crate) async fn bspatch<W: AsyncWrite + Unpin>(
    source: &[u8],
    stream: &[u8],
    new_size: usize,
    out: &mut W,
) -> Result<()> {
    let mut produced: usize = 0;
    let mut spos: usize = 0;
    let mut cur: usize = 0;
    let mut scratch = vec![0u8; OUT_CHUNK];
    while produced < new_size {
        let ctrl_end = cur
            .checked_add(24)
            .ok_or_else(|| bad("bspatch control offset overflow"))?;
        if ctrl_end > stream.len() {
            return Err(bad("bspatch stream truncated at control block"));
        }
        let diff_len = offtin(&stream[cur..cur + 8].try_into().unwrap());
        let extra_len = offtin(&stream[cur + 8..cur + 16].try_into().unwrap());
        let seek = offtin(&stream[cur + 16..cur + 24].try_into().unwrap());
        cur = ctrl_end;

        let diff_len = to_len(diff_len, "diff")?;
        let extra_len = to_len(extra_len, "extra")?;

        // The two data runs must fit in the stream, and the whole output in
        // new_size.
        let diff_end = cur
            .checked_add(diff_len)
            .ok_or_else(|| bad("bspatch diff run overflow"))?;
        let extra_end = diff_end
            .checked_add(extra_len)
            .ok_or_else(|| bad("bspatch extra run overflow"))?;
        if extra_end > stream.len() {
            return Err(bad("bspatch stream truncated at data run"));
        }
        if produced + diff_len + extra_len > new_size {
            return Err(bad("bspatch output exceeds declared size"));
        }

        // Diff run: source bytes plus the diff overlay, produced and written in
        // bounded chunks so neither the target object nor the overlay is fully
        // buffered.
        let src_end = spos
            .checked_add(diff_len)
            .ok_or_else(|| bad("bspatch source run overflow"))?;
        if src_end > source.len() {
            return Err(bad("bspatch reads past end of source"));
        }
        let mut i = 0;
        while i < diff_len {
            let n = (diff_len - i).min(OUT_CHUNK);
            for j in 0..n {
                scratch[j] = source[spos + i + j].wrapping_add(stream[cur + i + j]);
            }
            out.write_all(&scratch[..n]).await.map_err(Error::Io)?;
            i += n;
        }
        spos = src_end;
        cur = diff_end;

        // Extra run: verbatim bytes, written in bounded chunks.
        for chunk in stream[cur..extra_end].chunks(OUT_CHUNK) {
            out.write_all(chunk).await.map_err(Error::Io)?;
        }
        cur = extra_end;
        produced += diff_len + extra_len;

        // Seek the source, staying within bounds.
        spos = apply_seek(spos, seek)?;
        if spos > source.len() {
            return Err(bad("bspatch source seek past end"));
        }
    }
    Ok(())
}

/// Convert an `offtin` length to a `usize`, rejecting negatives.
fn to_len(v: i64, which: &str) -> Result<usize> {
    if v < 0 {
        return Err(Error::InvalidFormat(format!(
            "bspatch negative {which} length"
        )));
    }
    Ok(v as usize)
}

/// Apply a signed source seek to a position, rejecting an out-of-range result.
fn apply_seek(pos: usize, seek: i64) -> Result<usize> {
    let next = i128::from(pos as u64) + i128::from(seek);
    if next < 0 {
        return Err(bad("bspatch source seek before start"));
    }
    Ok(next as usize)
}

fn bad(msg: &str) -> Error {
    Error::InvalidFormat(msg.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_rt::block_on;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A minimal in-memory `futures-io` writer collecting the bspatch output.
    struct VecSink(Vec<u8>);

    impl AsyncWrite for VecSink {
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

    /// Run bspatch to completion and return the produced bytes.
    fn apply(source: &[u8], stream: &[u8], new_size: usize) -> Result<Vec<u8>> {
        block_on(async {
            let mut sink = VecSink(Vec::new());
            bspatch(source, stream, new_size, &mut sink).await?;
            Ok(sink.0)
        })
    }

    /// A real bspatch stream the `ostree` tool wrote for the `/usr/bin/app`
    /// object of a from->to delta: one control block `(20, 12, 3)`, a 20-byte
    /// zero diff, and the 12 extra bytes "two changed\n". The source is the old
    /// content "hello world version one\n"; the patch reproduces the new content
    /// "hello world version two changed\n".
    #[test]
    fn tool_vector_app() {
        let source = b"hello world version one\n";
        let mut stream = Vec::new();
        stream.extend_from_slice(&20i64.to_le_bytes()); // diff_len
        stream.extend_from_slice(&12i64.to_le_bytes()); // extra_len
        stream.extend_from_slice(&3i64.to_le_bytes()); // seek
        stream.extend_from_slice(&[0u8; 20]); // diff run: verbatim source
        stream.extend_from_slice(b"two changed\n"); // extra run
        let out = apply(source, &stream, 32).unwrap();
        assert_eq!(out, b"hello world version two changed\n");
    }

    /// offtin is sign-magnitude, not two's complement.
    #[test]
    fn offtin_sign_magnitude() {
        assert_eq!(offtin(&[0, 0, 0, 0, 0, 0, 0, 0]), 0);
        assert_eq!(offtin(&[1, 0, 0, 0, 0, 0, 0, 0]), 1);
        // Negative one is magnitude 1 with the sign bit set, not 0xFFFF...FF.
        assert_eq!(offtin(&[1, 0, 0, 0, 0, 0, 0, 0x80]), -1);
        assert_eq!(offtin(&[0x2c, 1, 0, 0, 0, 0, 0, 0]), 300);
    }

    /// A negative seek walks the source backwards; a pure-diff block with a
    /// zero overlay copies the source verbatim.
    #[test]
    fn negative_seek_rewinds_source() {
        let source = b"ABCDEF";
        let mut stream = Vec::new();
        // Block 1: copy 3 source bytes (ABC), no extra, seek back to 0.
        stream.extend_from_slice(&3i64.to_le_bytes());
        stream.extend_from_slice(&0i64.to_le_bytes());
        let mut seek = 3i64.to_le_bytes();
        seek[7] |= 0x80; // -3
        stream.extend_from_slice(&seek);
        stream.extend_from_slice(&[0u8; 3]);
        // Block 2: copy 3 source bytes from position 0 again (ABC).
        stream.extend_from_slice(&3i64.to_le_bytes());
        stream.extend_from_slice(&0i64.to_le_bytes());
        stream.extend_from_slice(&0i64.to_le_bytes());
        stream.extend_from_slice(&[0u8; 3]);
        let out = apply(source, &stream, 6).unwrap();
        assert_eq!(out, b"ABCABC");
    }

    #[test]
    fn truncated_stream_errors() {
        let source = b"AAAA";
        // Control claims a 10-byte diff run but the stream has none.
        let mut stream = Vec::new();
        stream.extend_from_slice(&10i64.to_le_bytes());
        stream.extend_from_slice(&0i64.to_le_bytes());
        stream.extend_from_slice(&0i64.to_le_bytes());
        assert!(apply(source, &stream, 10).is_err());
    }
}
