//! The PROXY protocol header at the start of a connection, versions 1 and 2.
//!
//! A proxy that forwards a TCP connection can send one header before the
//! bytes of the client. The header states the source address of the client.
//! [`parse`] reads the header from the bytes of the connection that the
//! server holds. [`read_header`] reads the bytes from the stream, in chunks
//! of at most 4 KiB, into one buffer of 4 KiB. It keeps the bytes that it
//! reads until [`parse`] gives a result, which comes at the end of the
//! address block of a version 2 header. It reads the rest of the TLVs
//! through the buffer and keeps none of them. The bytes after the header
//! stay in a [`Rewind`], which gives them first to the next read.
//!
//! Version 1 is a text line:
//!
//! - The line starts with `PROXY ` and ends at its first CRLF. The line has
//!   at most 107 bytes, the CRLF included.
//! - `TCP4 SRC DST SPORT DPORT` and `TCP6 SRC DST SPORT DPORT` give the
//!   source address `SRC`. One space separates two fields. An address is of
//!   the family of the protocol. A port is decimal digits alone, with a value
//!   of at most 65535.
//! - `UNKNOWN` gives no address, and the rest of the line has no effect.
//!
//! Version 2 is binary: a 12-byte signature, the version and the command, the
//! family, a 16-bit big-endian length, and that number of bytes.
//!
//! - The version is 2. The command `LOCAL` gives no address, and the server
//!   ignores its family. The command `PROXY` reads the address block of the
//!   family.
//! - Under `PROXY`, the family `UNSPEC` gives no address. TCP over IPv4 gives
//!   the source address of the first 12 bytes, and TCP over IPv6 of the first
//!   36 bytes. A stream over a UNIX socket, with a block of 216 bytes, gives
//!   no address. Each other family, for example a datagram family, is
//!   invalid.
//! - The bytes after the address block are TLVs, and the server ignores
//!   them.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::{AsyncReadExt, future};
use ostrya_fetch::WriteVectored;
use ostrya_rt as rt;

/// The prefix of a version 1 header.
const V1_PREFIX: &[u8] = b"PROXY ";

/// The most bytes of a version 1 header, the CRLF included.
const V1_MAX: usize = 107;

/// The signature of a version 2 header.
const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

/// The bytes of a version 2 header before its address block.
const V2_FIXED: usize = 16;

/// The largest read of [`read_header`] from the stream.
const READ_CHUNK: usize = 4096;

/// The result of [`parse`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Parsed {
    /// The bytes are a strict prefix of a valid header, and end before the
    /// end of its address block.
    Incomplete,
    /// The bytes do not start with a valid header.
    Invalid,
    /// The bytes start with a valid header of `len` bytes, or with the part
    /// of a version 2 header up to the end of its address block. `source` is
    /// the source address of the header, or `None` when the header gives no
    /// address.
    Done { source: Option<IpAddr>, len: usize },
}

/// Reads the PROXY header at the start of `bytes`.
///
/// The result of a version 2 header is known at the end of its address
/// block, because the server ignores the TLVs after it. So `len` of
/// [`Parsed::Done`] can be more than the length of `bytes`.
pub(crate) fn parse(bytes: &[u8]) -> Parsed {
    let first = bytes.len().min(V2_SIGNATURE.len());
    if bytes[..first] == V2_SIGNATURE[..first] {
        return if first < V2_SIGNATURE.len() {
            Parsed::Incomplete
        } else {
            parse_v2(bytes)
        };
    }
    let first = bytes.len().min(V1_PREFIX.len());
    if bytes[..first] == V1_PREFIX[..first] {
        return if first < V1_PREFIX.len() {
            Parsed::Incomplete
        } else {
            parse_v1(bytes)
        };
    }
    Parsed::Invalid
}

/// Reads a version 1 header. `bytes` starts with [`V1_PREFIX`].
fn parse_v1(bytes: &[u8]) -> Parsed {
    let window = &bytes[..bytes.len().min(V1_MAX)];
    let Some(lf) = window.iter().position(|&b| b == b'\n') else {
        return if bytes.len() < V1_MAX {
            Parsed::Incomplete
        } else {
            Parsed::Invalid
        };
    };
    if window[lf - 1] != b'\r' {
        return Parsed::Invalid;
    }
    let len = lf + 1;
    let Ok(line) = std::str::from_utf8(&window[V1_PREFIX.len()..lf - 1]) else {
        return Parsed::Invalid;
    };
    if line == "UNKNOWN" || line.starts_with("UNKNOWN ") {
        return Parsed::Done { source: None, len };
    }
    let fields: Vec<&str> = line.split(' ').collect();
    let [protocol, source, destination, source_port, destination_port] = fields[..] else {
        return Parsed::Invalid;
    };
    let addrs = match protocol {
        "TCP4" => source
            .parse::<Ipv4Addr>()
            .ok()
            .zip(destination.parse::<Ipv4Addr>().ok())
            .map(|(source, _)| IpAddr::V4(source)),
        "TCP6" => source
            .parse::<Ipv6Addr>()
            .ok()
            .zip(destination.parse::<Ipv6Addr>().ok())
            .map(|(source, _)| IpAddr::V6(source)),
        _ => None,
    };
    match addrs {
        Some(source) if is_port(source_port) && is_port(destination_port) => Parsed::Done {
            source: Some(source.to_canonical()),
            len,
        },
        _ => Parsed::Invalid,
    }
}

/// Returns `true` if `text` is a port of version 1: decimal digits alone,
/// with a value of at most 65535.
fn is_port(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) && text.parse::<u16>().is_ok()
}

/// Reads a version 2 header up to the end of its address block. `bytes`
/// starts with [`V2_SIGNATURE`].
fn parse_v2(bytes: &[u8]) -> Parsed {
    let Some(&version_command) = bytes.get(12) else {
        return Parsed::Incomplete;
    };
    if version_command >> 4 != 2 {
        return Parsed::Invalid;
    }
    let proxy = match version_command & 0x0f {
        0 => false,
        1 => true,
        _ => return Parsed::Invalid,
    };
    let Some(&family) = bytes.get(13) else {
        return Parsed::Incomplete;
    };
    // The least length of the address block of the family, and the length of
    // the source address at the start of the block, or 0 for no address.
    let (least, source_len) = match (proxy, family) {
        (false, _) | (true, 0x00) => (0, 0),
        (true, 0x11) => (12, 4),
        (true, 0x21) => (36, 16),
        (true, 0x31) => (216, 0),
        (true, _) => return Parsed::Invalid,
    };
    let Some(length) = bytes.get(14..V2_FIXED) else {
        return Parsed::Incomplete;
    };
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    if length < least {
        return Parsed::Invalid;
    }
    let len = V2_FIXED + length;
    let Some(block) = bytes.get(V2_FIXED..V2_FIXED + least) else {
        return Parsed::Incomplete;
    };
    let source = match source_len {
        4 => <[u8; 4]>::try_from(&block[..4])
            .ok()
            .map(|octets| IpAddr::V4(Ipv4Addr::from(octets))),
        16 => <[u8; 16]>::try_from(&block[..16])
            .ok()
            .map(|octets| IpAddr::V6(Ipv6Addr::from(octets)).to_canonical()),
        _ => None,
    };
    Parsed::Done { source, len }
}

/// A stream that gives the bytes of `prefix` first, then the bytes of
/// `inner`. A write goes to `inner`.
pub(crate) struct Rewind<S> {
    prefix: Vec<u8>,
    /// The count of the bytes of `prefix` that a read gave.
    taken: usize,
    inner: S,
}

impl<S> Rewind<S> {
    /// A stream with no prefix.
    pub(crate) fn new(inner: S) -> Rewind<S> {
        Rewind::with_prefix(Vec::new(), inner)
    }

    /// A stream that gives `prefix` before the bytes of `inner`.
    fn with_prefix(prefix: Vec<u8>, inner: S) -> Rewind<S> {
        Rewind {
            prefix,
            taken: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let rest = &this.prefix[this.taken..];
        if rest.is_empty() || buf.is_empty() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        this.taken += n;
        if this.taken == this.prefix.len() {
            this.prefix = Vec::new();
            this.taken = 0;
        }
        Poll::Ready(Ok(n))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

impl<S: WriteVectored> WriteVectored for Rewind<S> {
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Reads the PROXY header at the start of `stream`, within `timeout`.
///
/// The result is the source address of the header, or `None` when the
/// header gives no address, and the stream with the bytes after the header.
/// The function gives `None` when the stream does not start with a valid
/// header, ends before the end of the header, fails, or does not give the
/// header within `timeout`.
pub(crate) async fn read_header<S: AsyncRead + Unpin>(
    stream: S,
    timeout: Duration,
) -> Option<(Option<IpAddr>, Rewind<S>)> {
    future::or(read(stream), async {
        rt::Timer::after(timeout).await;
        None
    })
    .await
}

/// [`read_header`] with no time limit.
async fn read<S: AsyncRead + Unpin>(mut stream: S) -> Option<(Option<IpAddr>, Rewind<S>)> {
    let mut chunk = [0u8; READ_CHUNK];
    // The bytes up to the end of the address block. The result is known
    // before the bytes pass the end of the largest address block, so the
    // buffer holds at most that and one chunk.
    let mut bytes = Vec::new();
    let (source, len) = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..n]);
        match parse(&bytes) {
            Parsed::Incomplete => {}
            Parsed::Invalid => return None,
            Parsed::Done { source, len } => break (source, len),
        }
    };
    if let Some(rest) = bytes.get(len..) {
        // The prefix holds the bytes after the header alone.
        return Some((source, Rewind::with_prefix(rest.to_vec(), stream)));
    }
    // The TLVs of a version 2 header go through `chunk`, and the call keeps
    // the bytes after them alone.
    let mut left = len - bytes.len();
    drop(bytes);
    loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        if n < left {
            left -= n;
            continue;
        }
        return Some((source, Rewind::with_prefix(chunk[left..n].to_vec(), stream)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`parse`], which gives [`Parsed::Incomplete`] until `bytes` hold the
    /// whole header.
    fn parse_whole(bytes: &[u8]) -> Parsed {
        match parse(bytes) {
            Parsed::Done { len, .. } if bytes.len() < len => Parsed::Incomplete,
            parsed => parsed,
        }
    }

    /// A version 2 header with the command byte `command`, the family
    /// `family`, and the address block `block`.
    fn v2(command: u8, family: u8, block: &[u8]) -> Vec<u8> {
        let mut bytes = V2_SIGNATURE.to_vec();
        bytes.push(command);
        bytes.push(family);
        bytes.extend_from_slice(&u16::try_from(block.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(block);
        bytes
    }

    /// The IPv4 address block of TCP from 192.0.2.1:56324 to
    /// 198.51.100.2:443.
    fn inet() -> Vec<u8> {
        let mut block = vec![192, 0, 2, 1, 198, 51, 100, 2];
        block.extend_from_slice(&56324u16.to_be_bytes());
        block.extend_from_slice(&443u16.to_be_bytes());
        block
    }

    /// The IPv6 address block of TCP from 2001:db8::1 to 2001:db8::2.
    fn inet6() -> Vec<u8> {
        let mut block = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec();
        block.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        block.extend_from_slice(&[0xdc, 0x04, 0x01, 0xbb]);
        block
    }

    fn done(source: Option<&str>, len: usize) -> Parsed {
        Parsed::Done {
            source: source.map(|text| text.parse().unwrap()),
            len,
        }
    }

    /// Each valid header of the tests, and its source address.
    fn valid() -> Vec<(Vec<u8>, Option<&'static str>)> {
        let worst = b"PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff \
                      ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let longest_tcp6 = b"PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff \
                             ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let mut with_tlvs = inet();
        with_tlvs.extend_from_slice(&[0x04, 0x00, 0x03, b'a', b'b', b'c']);
        vec![
            (
                b"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n".to_vec(),
                Some("192.168.0.1"),
            ),
            (
                b"PROXY TCP6 2001:db8::1 2001:db8::2 56324 443\r\n".to_vec(),
                Some("2001:db8::1"),
            ),
            (
                b"PROXY TCP6 ::ffff:192.0.2.1 ::1 1 2\r\n".to_vec(),
                Some("192.0.2.1"),
            ),
            (worst.to_vec(), None),
            (
                longest_tcp6.to_vec(),
                Some("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ),
            (b"PROXY UNKNOWN\r\n".to_vec(), None),
            (
                b"PROXY UNKNOWN ffff:f::ffff 1.2.3.4 65535 x\r\n".to_vec(),
                None,
            ),
            (v2(0x20, 0x00, &[]), None),
            (v2(0x20, 0x11, &inet()), None),
            // LOCAL ignores the family, also a family that PROXY refuses.
            (v2(0x20, 0x12, &inet()), None),
            (v2(0x21, 0x11, &inet()), Some("192.0.2.1")),
            (v2(0x21, 0x21, &inet6()), Some("2001:db8::1")),
            (v2(0x21, 0x00, &[]), None),
            (v2(0x21, 0x00, &[1, 2, 3]), None),
            (v2(0x21, 0x31, &[b'/'; 216]), None),
            (v2(0x21, 0x11, &with_tlvs), Some("192.0.2.1")),
        ]
    }

    /// The examples of the specification give their source address and
    /// their length. The worst case of version 1 has 107 bytes.
    #[test]
    fn each_valid_header_gives_its_source_and_length() {
        let headers = valid();
        assert_eq!(headers[3].0.len(), V1_MAX);
        for (bytes, source) in headers {
            assert_eq!(parse_whole(&bytes), done(source, bytes.len()), "{bytes:?}");
            let mut longer = bytes.clone();
            longer.extend_from_slice(b"GET / HTTP/1.1\r\n");
            assert_eq!(parse_whole(&longer), done(source, bytes.len()), "{bytes:?}");
        }
    }

    /// Each strict prefix of a valid header is incomplete.
    #[test]
    fn each_strict_prefix_is_incomplete() {
        for (bytes, _) in valid() {
            for end in 0..bytes.len() {
                assert_eq!(
                    parse_whole(&bytes[..end]),
                    Parsed::Incomplete,
                    "{bytes:?} {end}"
                );
            }
        }
    }

    #[test]
    fn a_bad_version_1_header_is_invalid() {
        let mut long = b"PROXY UNKNOWN ".to_vec();
        long.resize(V1_MAX - 1, b'x');
        long.extend_from_slice(b"\r\n");
        assert_eq!(long.len(), V1_MAX + 1);
        let no_crlf = [b"PROXY UNKNOWN ".to_vec(), vec![b'x'; 200]].concat();
        for bytes in [
            &long[..],
            &no_crlf,
            b"PROXY TCP4 192.0.2.1 192.0.2.2 1 2\n",
            b"PROXY TCP4 192.0.2.1  192.0.2.2 1 2\r\n",
            b"PROXY TCP4 192.0.2.1 192.0.2.2 1 2 \r\n",
            b"PROXY  TCP4 192.0.2.1 192.0.2.2 1 2\r\n",
            b"PROXY tcp4 192.0.2.1 192.0.2.2 1 2\r\n",
            b"PROXY UDP4 192.0.2.1 192.0.2.2 1 2\r\n",
            b"PROXY TCP4 2001:db8::1 192.0.2.2 1 2\r\n",
            b"PROXY TCP6 192.0.2.1 2001:db8::1 1 2\r\n",
            b"PROXY TCP4 192.0.2.1 192.0.2.2 65536 2\r\n",
            b"PROXY TCP4 192.0.2.1 192.0.2.2 +80 2\r\n",
            b"PROXY TCP4 192.0.2.1 192.0.2.2 1 2 3\r\n",
            b"PROXY TCP4 192.0.2.1 192.0.2.2 1\r\n",
            b"PROXY TCP4 192.0.2.1 192.0.2.2 1 -2\r\n",
            b"PROXY TCP4 192.0.2.1 192.0.2.2 1 2\r\r\n",
            b"PROXY UNKNOWNX\r\n",
            b"PROXY \r\n",
            b"proxy UNKNOWN\r\n",
            b"GET / HTTP/1.1\r\n",
            b"\r\n\r\n\x00\r\nQUIT\r",
        ] {
            assert_eq!(
                parse_whole(bytes),
                Parsed::Invalid,
                "{:?}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn a_bad_version_2_header_is_invalid() {
        for bytes in [
            // UDP over IPv4 and over IPv6, and a datagram over UNIX.
            v2(0x21, 0x12, &inet()),
            v2(0x21, 0x22, &inet6()),
            v2(0x21, 0x32, &[0; 216]),
            // Version 1, and the command 2.
            v2(0x11, 0x11, &inet()),
            v2(0x22, 0x11, &inet()),
            // An unknown family.
            v2(0x21, 0x41, &inet()),
            v2(0x21, 0x10, &inet()),
            // A block too short for the family.
            v2(0x21, 0x11, &inet()[..11]),
            v2(0x21, 0x21, &inet6()[..35]),
            v2(0x21, 0x31, &[0; 215]),
        ] {
            assert_eq!(parse_whole(&bytes), Parsed::Invalid, "{bytes:?}");
            // The header is invalid before its address block arrives.
            assert_eq!(
                parse_whole(&bytes[..V2_FIXED]),
                Parsed::Invalid,
                "{bytes:?}"
            );
        }
    }

    /// The largest version 2 header has 16 + 65535 bytes. Its result is
    /// known at the end of its address block.
    #[test]
    fn a_version_2_header_has_up_to_64_kib_of_block() {
        let mut block = inet();
        block.resize(usize::from(u16::MAX), 0);
        let bytes = v2(0x21, 0x11, &block);
        assert_eq!(
            parse_whole(&bytes),
            done(Some("192.0.2.1"), V2_FIXED + 65535)
        );
        assert_eq!(parse_whole(&bytes[..bytes.len() - 1]), Parsed::Incomplete);
        let end = V2_FIXED + inet().len();
        assert_eq!(
            parse(&bytes[..end]),
            done(Some("192.0.2.1"), V2_FIXED + 65535)
        );
        assert_eq!(parse(&bytes[..end - 1]), Parsed::Incomplete);
    }

    /// A stream of the bytes of `bytes`, which then ends.
    fn stream(bytes: Vec<u8>) -> futures_lite::io::Cursor<Vec<u8>> {
        futures_lite::io::Cursor::new(bytes)
    }

    /// The bytes after the header come first from the stream that
    /// [`read_header`] gives, also when one read held the header and these
    /// bytes. A header longer than one read chunk is read whole.
    #[test]
    fn the_bytes_after_the_header_stay() {
        let request = b"GET / HTTP/1.1\r\nhost: x\r\n\r\n";
        let mut block = inet();
        block.resize(3 * READ_CHUNK, 7);
        for header in [
            b"PROXY TCP4 192.0.2.1 192.0.2.2 1 2\r\n".to_vec(),
            v2(0x21, 0x11, &block),
        ] {
            let bytes = [header, request.to_vec()].concat();
            let (source, mut rest) =
                rt::block_on(read_header(stream(bytes), Duration::from_secs(5))).unwrap();
            assert_eq!(source, Some("192.0.2.1".parse().unwrap()));
            let mut out = Vec::new();
            rt::block_on(rest.read_to_end(&mut out)).unwrap();
            assert_eq!(out, request);
        }
    }

    /// A header that ends with the bytes of the stream leaves an empty
    /// prefix, also after a version 2 header of 64 KiB.
    #[test]
    fn a_long_header_leaves_no_buffer() {
        let mut block = inet();
        block.resize(usize::from(u16::MAX), 0);
        let bytes = v2(0x21, 0x11, &block);
        let (source, rest) =
            rt::block_on(read_header(stream(bytes), Duration::from_secs(5))).unwrap();
        assert_eq!(source, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(rest.prefix.capacity(), 0);
    }

    /// A stream that gives one byte for each read.
    struct ByteByByte {
        bytes: Vec<u8>,
        at: usize,
    }

    impl AsyncRead for ByteByByte {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if buf.is_empty() || this.at == this.bytes.len() {
                return Poll::Ready(Ok(0));
            }
            buf[0] = this.bytes[this.at];
            this.at += 1;
            Poll::Ready(Ok(1))
        }
    }

    /// A version 2 header with the largest TLV area, and the bytes of the
    /// application after it.
    fn largest_v2_and_payload() -> (Vec<u8>, Vec<u8>) {
        let mut block = inet();
        block.resize(usize::from(u16::MAX), 0xa5);
        let payload: Vec<u8> = (0..3 * READ_CHUNK + 17).map(|i| i as u8).collect();
        (v2(0x21, 0x11, &block), payload)
    }

    /// The bytes after a version 2 header with the largest TLV area come
    /// first from the stream, each one time and in order. The prefix of the
    /// stream holds at most one read chunk.
    #[test]
    fn the_bytes_after_a_largest_tlv_area_stay() {
        let (header, payload) = largest_v2_and_payload();
        let bytes = [header, payload.clone()].concat();
        let (source, mut rest) =
            rt::block_on(read_header(stream(bytes), Duration::from_secs(5))).unwrap();
        assert_eq!(source, Some("192.0.2.1".parse().unwrap()));
        assert!(rest.prefix.capacity() <= READ_CHUNK);
        let mut out = Vec::new();
        rt::block_on(rest.read_to_end(&mut out)).unwrap();
        assert_eq!(out, payload);
    }

    /// A header that arrives one byte at a time gives its source, and the
    /// bytes after it stay.
    #[test]
    fn a_header_read_byte_by_byte_gives_its_source() {
        let request = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        let (largest, payload) = largest_v2_and_payload();
        for (header, after) in [
            (
                b"PROXY TCP4 192.0.2.1 192.0.2.2 1 2\r\n".to_vec(),
                request.clone(),
            ),
            (v2(0x21, 0x11, &inet()), request.clone()),
            (largest, payload),
        ] {
            let bytes = [header, after.clone()].concat();
            let slow = ByteByByte { bytes, at: 0 };
            let (source, mut rest) =
                rt::block_on(read_header(slow, Duration::from_secs(5))).unwrap();
            assert_eq!(source, Some("192.0.2.1".parse().unwrap()));
            let mut out = Vec::new();
            rt::block_on(rest.read_to_end(&mut out)).unwrap();
            assert_eq!(out, after);
        }
    }

    /// A stream that ends inside the header, a bad header, and an empty
    /// stream give no result.
    #[test]
    fn a_short_or_bad_stream_gives_nothing() {
        for bytes in [
            &b""[..],
            b"PROXY TCP4 192.0.2.1",
            b"GET / HTTP/1.1\r\n\r\n",
            &V2_SIGNATURE[..5],
            &largest_v2_and_payload().0[..2 * READ_CHUNK],
        ] {
            let read = rt::block_on(read_header(stream(bytes.to_vec()), Duration::from_secs(5)));
            assert!(read.is_none(), "{bytes:?}");
        }
    }

    /// A stream that gives no byte within the timeout gives no result.
    #[test]
    fn a_silent_stream_times_out() {
        struct Silent;
        impl AsyncRead for Silent {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }
        }
        let started = std::time::Instant::now();
        let read = rt::block_on(read_header(Silent, Duration::from_millis(50)));
        assert!(read.is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// A read into an empty buffer gives zero bytes and keeps the prefix.
    #[test]
    fn the_rewind_gives_the_prefix_in_parts() {
        let mut rewind = Rewind::with_prefix(b"abc".to_vec(), stream(b"def".to_vec()));
        let mut two = [0u8; 2];
        let mut out = Vec::new();
        rt::block_on(async {
            assert_eq!(rewind.read(&mut []).await.unwrap(), 0);
            assert_eq!(rewind.read(&mut two).await.unwrap(), 2);
            out.extend_from_slice(&two);
            rewind.read_to_end(&mut out).await.unwrap();
        });
        assert_eq!(out, b"abcdef");
    }
}
