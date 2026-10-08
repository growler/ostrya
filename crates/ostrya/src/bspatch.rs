//! A bspatch decoder for the `B` (bspatch) operation of a static delta.
//!
//! The `B` opcode carries a bsdiff patch that the `ostree` command writes. The
//! patch is the classic bsdiff patch with its three streams interleaved. The
//! patch bytes have no compression of their own, because the whole enclosing
//! delta part is xz-compressed.
//!
//! The layout comes from observation of the `ostree` command. The patch is a
//! sequence of blocks, and each block holds these parts:
//!
//! - A 24-byte control block of three signed 64-bit integers in the bsdiff
//!   `offtin` encoding: `diff_len`, `extra_len`, and a source `seek`.
//! - `diff_len` bytes. The decoder adds each byte (wrapping) to the source
//!   byte at the current source position.
//! - `extra_len` bytes, copied verbatim.
//!
//! After each block, the source position advances by `diff_len` and then by
//! `seek`. The decoder reads blocks until the output reaches `new_size`. The
//! `open` operation of the delta supplies `new_size`. The patch has no header
//! and no block count, so `new_size` is the only terminator.
//!
//! Because the decoder makes the output strictly forward, it streams the
//! output to the writer of the caller in bounded pieces. It never holds the
//! whole target object in memory.
//!
//! The random-access `source` is the read-source object. A large read-source
//! object is a memory map, so an index into it reads the demand-paged file
//! cache and uses no heap memory.
//!
//! The `offtin` encoding is little-endian sign-magnitude. The eight bytes hold
//! the magnitude in little-endian order, and the top bit of the last byte is
//! the sign flag. A set flag means a negative value. This encoding is not
//! two's complement.

use futures_io::AsyncWrite;
use futures_lite::AsyncWriteExt;

use crate::error::{Error, Result};

/// The size of the staging buffer for the overlaid bytes of a diff run.
const OUT_CHUNK: usize = 128 * 1024;

/// Decodes one 64-bit integer in the bsdiff `offtin` encoding.
fn offtin(buf: &[u8; 8]) -> i64 {
    let mut y = i64::from(buf[7] & 0x7f);
    for i in (0..7).rev() {
        y = y * 256 + i64::from(buf[i]);
    }
    if buf[7] & 0x80 != 0 { -y } else { y }
}

/// Applies the bspatch `stream` to `source` and writes the output to `out`.
///
/// `source` is the whole content of the read-source object. `stream` is the
/// slice of the data source of the delta part that the `B` operation uses.
/// `out` receives exactly `new_size` bytes.
///
/// The function checks the bounds of every offset, so a malformed patch does
/// not cause a panic or a read out of range. The `close` operation of the
/// delta verifies the checksum of the produced object. That verification
/// catches a patch that applies without error but gives wrong bytes.
///
/// # Errors
///
/// - [`Error::InvalidFormat`] if the patch is malformed:
///   - a truncated control block or data run
///   - a negative length or an offset overflow
///   - output past `new_size`
///   - a source read or seek out of range
/// - [`Error::Io`] if a write to `out` fails.
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

        // The two data runs must fit in the stream. The whole output must fit
        // in `new_size`.
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

        // Diff run: the source bytes plus the diff overlay. The loop writes
        // them in bounded chunks, so it never buffers the whole target object
        // or the whole overlay.
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

        // Seek the source. The position must stay within the source.
        spos = apply_seek(spos, seek)?;
        if spos > source.len() {
            return Err(bad("bspatch source seek past end"));
        }
    }
    Ok(())
}

/// Converts an `offtin` length to a `usize` and refuses a negative length.
fn to_len(v: i64, which: &str) -> Result<usize> {
    if v < 0 {
        return Err(Error::InvalidFormat(format!(
            "bspatch negative {which} length"
        )));
    }
    Ok(v as usize)
}

/// Applies a signed source seek to a position and refuses a negative result.
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

    /// An in-memory `futures-io` writer that collects the bspatch output.
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

    /// Runs bspatch to completion and returns the produced bytes.
    fn apply(source: &[u8], stream: &[u8], new_size: usize) -> Result<Vec<u8>> {
        block_on(async {
            let mut sink = VecSink(Vec::new());
            bspatch(source, stream, new_size, &mut sink).await?;
            Ok(sink.0)
        })
    }

    /// A bspatch stream that the `ostree` command wrote for the `/usr/bin/app`
    /// object of a from->to delta. The stream holds one control block
    /// `(20, 12, 3)`, a 20-byte zero diff, and the 12 extra bytes
    /// "two changed\n". The source is the old content "hello world version
    /// one\n". The patch gives the new content "hello world version two
    /// changed\n".
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

    /// The `offtin` encoding is sign-magnitude. It is not two's complement.
    #[test]
    fn offtin_sign_magnitude() {
        assert_eq!(offtin(&[0, 0, 0, 0, 0, 0, 0, 0]), 0);
        assert_eq!(offtin(&[1, 0, 0, 0, 0, 0, 0, 0]), 1);
        // Negative one is magnitude 1 with the sign bit set. It is not
        // 0xFFFF...FF.
        assert_eq!(offtin(&[1, 0, 0, 0, 0, 0, 0, 0x80]), -1);
        assert_eq!(offtin(&[0x2c, 1, 0, 0, 0, 0, 0, 0]), 300);
    }

    /// A negative seek moves the source position back. A pure-diff block with
    /// a zero overlay copies the source verbatim.
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
        // The control block declares a 10-byte diff run. The stream holds no
        // data run.
        let mut stream = Vec::new();
        stream.extend_from_slice(&10i64.to_le_bytes());
        stream.extend_from_slice(&0i64.to_le_bytes());
        stream.extend_from_slice(&0i64.to_le_bytes());
        assert!(apply(source, &stream, 10).is_err());
    }
}
