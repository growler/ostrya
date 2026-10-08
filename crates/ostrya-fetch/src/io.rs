//! Adapters between hyper and the runtime-neutral stream surface.
//!
//! hyper uses its own traits for I/O, for background tasks, and for the
//! keep-alive pings of HTTP/2. The adapters implement these traits over the
//! runtime:
//!
//! - `FuturesIo` presents a `futures-io` stream as a hyper stream. The stream
//!   is a plain TCP stream or a TLS session over one.
//! - `RtExecutor` gives the tasks of hyper to `rt::spawn`.
//! - `RtTimer` gives the delays of hyper to `rt::Deadline`.
//!
//! The fetcher, the TLS layer, and all streams under them use only
//! `futures-io` and `ostrya-rt`. The adapters are public, so an HTTP server
//! over `ostrya-rt` drives the server connections of hyper with them.
//! `WriteVectored` has implementations for the plain TCP stream and for the two
//! TLS stream types of `futures-rustls`.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use futures_io::{AsyncRead, AsyncWrite};

/// The largest read that `FuturesIo` asks of the inner stream in one call.
///
/// hyper asks for as many bytes as its read strategy wants at that time. This
/// limit bounds the copy through the scratch buffer, so a large request cannot
/// grow the buffer without limit.
const MAX_READ: usize = 64 * 1024;

/// A stream that states if its vectored write takes more than the first slice.
///
/// hyper asks this before it gives a list of slices. If the answer is `false`,
/// hyper joins the slices itself. The `futures-io` write trait has no such
/// query, and the tokio and std write traits have one. Each stream type states
/// its answer with this trait, and `FuturesIo` gives the answer to hyper.
pub trait WriteVectored {
    /// Returns `true` if a vectored write takes more than the first slice.
    fn is_write_vectored(&self) -> bool;
}

impl WriteVectored for ostrya_rt::TcpStream {
    fn is_write_vectored(&self) -> bool {
        ostrya_rt::TcpStream::is_write_vectored(self)
    }
}

impl<S> WriteVectored for futures_rustls::client::TlsStream<S> {
    fn is_write_vectored(&self) -> bool {
        // The rustls session writer copies all slices into the record that it
        // builds. The socket under the session has no effect on this answer.
        true
    }
}

impl<S> WriteVectored for futures_rustls::server::TlsStream<S> {
    fn is_write_vectored(&self) -> bool {
        // The server session writer copies the slices into its record, as the
        // client session writer does.
        true
    }
}

/// An adapter that presents a `futures-io` stream as a hyper stream.
pub struct FuturesIo<S> {
    inner: S,
    /// The buffer that receives each read before the copy into the cursor.
    ///
    /// hyper gives a cursor over memory that can be uninitialized. The only
    /// safe way to fill this cursor is `ReadBufCursor::put_slice`. A read of
    /// `AsyncRead::poll_read` into the uninitialized bytes needs `unsafe`,
    /// which this crate forbids. As a result, each read makes one more copy of
    /// the bytes that are already in memory.
    scratch: Vec<u8>,
}

impl<S> FuturesIo<S> {
    /// Creates an adapter over `inner`.
    pub fn new(inner: S) -> FuturesIo<S> {
        FuturesIo {
            inner,
            scratch: Vec::new(),
        }
    }

    /// Returns the inner stream, for use after hyper releases the adapter.
    ///
    /// A `CONNECT` tunnel gets its socket back this way. hyper gives the
    /// upgraded I/O back as the type that the handshake used.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> hyper::rt::Read for FuturesIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let want = buf.remaining().min(MAX_READ);
        // hyper reserves capacity before each read, so it never asks for zero
        // bytes. With this branch, the inner stream never gets a zero-length
        // slice. A stream can answer a zero-length slice with `Ok(0)`, the end
        // of stream. hyper also reads an empty fill as the end of stream, so
        // the two results agree on an input that hyper does not produce. The
        // branch returns `Poll::Ready`, because it has no waker to register.
        // A pending result with no registered waker stops the connection task.
        if want == 0 {
            return Poll::Ready(Ok(()));
        }
        let me = self.get_mut();
        if me.scratch.len() < want {
            me.scratch.resize(want, 0);
        }
        let n = ready!(Pin::new(&mut me.inner).poll_read(cx, &mut me.scratch[..want]))?;
        buf.put_slice(&me.scratch[..n]);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + WriteVectored + Unpin> hyper::rt::Write for FuturesIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
}

/// An executor that gives the connection tasks of hyper to the runtime backend.
#[derive(Clone, Copy, Debug)]
pub struct RtExecutor;

impl<F> hyper::rt::Executor<F> for RtExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        // The task continues to run after the drop of its handle. A connection
        // driver needs this, because it lives longer than the request that
        // opened it.
        drop(ostrya_rt::spawn(future));
    }
}

/// A timer that gives the delays of hyper to the runtime backend.
///
/// An HTTP/2 connection uses it to schedule its keep-alive ping and the wait
/// for the reply.
#[derive(Clone, Copy, Debug)]
pub struct RtTimer;

impl hyper::rt::Timer for RtTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        Box::pin(RtSleep {
            deadline: ostrya_rt::Deadline::new(duration),
        })
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        // If the deadline is in the past, the delay has zero length and
        // expires on its first poll.
        self.sleep(deadline.saturating_duration_since(Instant::now()))
    }
}

/// One delay, as a future that hyper can hold.
struct RtSleep {
    deadline: ostrya_rt::Deadline,
}

impl Future for RtSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.get_mut().deadline.poll_expired(cx)
    }
}

impl hyper::rt::Sleep for RtSleep {}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::io::Cursor;
    use hyper::rt::{Read, Write};
    use ostrya_rt::block_on;

    /// `std::io::Cursor<Vec<u8>>` implements `write_vectored`, and futures-lite
    /// forwards the vectored write to it, so each slice arrives.
    impl WriteVectored for Cursor<Vec<u8>> {
        fn is_write_vectored(&self) -> bool {
            true
        }
    }

    /// A sink that keeps the `futures-io` default of `poll_write_vectored`,
    /// which writes only the first non-empty slice.
    struct PlainSink(Vec<u8>);

    impl AsyncWrite for PlainSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl WriteVectored for PlainSink {
        fn is_write_vectored(&self) -> bool {
            false
        }
    }

    /// hyper gets the vectored-write answer of the inner stream. If the stream
    /// does not take all slices, hyper joins the slices itself.
    #[test]
    fn the_vectored_write_answer_comes_from_the_stream() {
        let vectored = FuturesIo::new(Cursor::new(Vec::new()));
        assert!(Write::is_write_vectored(&vectored));
        let plain = FuturesIo::new(PlainSink(Vec::new()));
        assert!(!Write::is_write_vectored(&plain));
    }

    /// Calls `poll_read` once through the hyper cursor and returns the bytes.
    fn read_once<S: AsyncRead + Unpin>(io: &mut FuturesIo<S>, cap: usize) -> Vec<u8> {
        block_on(async {
            let mut buf = Vec::with_capacity(cap);
            let mut hyper_buf = hyper::rt::ReadBuf::uninit(buf.spare_capacity_mut());
            std::future::poll_fn(|cx| Pin::new(&mut *io).poll_read(cx, hyper_buf.unfilled()))
                .await
                .unwrap();
            hyper_buf.filled().to_vec()
        })
    }

    #[test]
    fn reads_through_hypers_cursor_in_bounded_chunks() {
        let mut io = FuturesIo::new(Cursor::new(b"abcdefgh".to_vec()));
        assert_eq!(read_once(&mut io, 3), b"abc");
        assert_eq!(read_once(&mut io, 5), b"defgh");
        // At EOF, the cursor stays empty. hyper reads this as end of stream.
        assert!(read_once(&mut io, 4).is_empty());
    }

    /// hyper never gives a cursor with no room, because it reserves capacity
    /// before each read. The branch protects the inner stream, which never gets
    /// a zero-length slice.
    #[test]
    fn a_zero_capacity_cursor_reads_nothing() {
        let mut io = FuturesIo::new(Cursor::new(b"data".to_vec()));
        assert!(read_once(&mut io, 0).is_empty());
        // The read did not touch the stream, so the bytes are still there.
        assert_eq!(read_once(&mut io, 4), b"data");
    }

    #[test]
    fn writes_and_shutdown_reach_the_inner_stream() {
        block_on(async {
            let mut io = FuturesIo::new(Cursor::new(Vec::new()));
            std::future::poll_fn(|cx| Pin::new(&mut io).poll_write(cx, b"sent"))
                .await
                .unwrap();
            std::future::poll_fn(|cx| Pin::new(&mut io).poll_flush(cx))
                .await
                .unwrap();
            std::future::poll_fn(|cx| Pin::new(&mut io).poll_shutdown(cx))
                .await
                .unwrap();
            assert_eq!(io.inner.into_inner(), b"sent");
        });
    }
}
