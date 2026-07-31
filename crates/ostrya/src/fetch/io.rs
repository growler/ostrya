//! Glue between hyper and the runtime-neutral stream surface.
//!
//! hyper drives its connections over its own I/O traits, spawns its background
//! work through its own executor trait, and schedules its HTTP/2 keep-alive
//! pings through its own timer trait. [`FuturesIo`] presents a `futures-io`
//! stream -- a plain TCP stream or a TLS session over one -- as a hyper stream,
//! [`RtExecutor`] hands hyper's tasks to `rt::spawn`, and [`RtTimer`] hands its
//! delays to `rt::Deadline`. All three are thin: the fetcher, the TLS layer, and
//! every stream below them stay written against `futures-io` and `ostrya-rt`.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use futures_io::{AsyncRead, AsyncWrite};

/// The largest read hyper's buffer request is honored with in one go. hyper
/// asks for as much as its read strategy currently wants; the copy below is
/// bounded so a large request cannot size the scratch buffer without limit.
const MAX_READ: usize = 64 * 1024;

/// Whether a stream's vectored write takes more than the first slice.
///
/// hyper asks this before it hands over a slice list, and coalesces the pieces
/// itself when the answer is no. The `futures-io` write trait carries no such
/// query -- unlike the tokio and std ones -- so the answer is stated per stream
/// type here and travels with the stream into [`FuturesIo`].
pub(crate) trait WriteVectored {
    fn is_write_vectored(&self) -> bool;
}

impl WriteVectored for ostrya_rt::TcpStream {
    fn is_write_vectored(&self) -> bool {
        ostrya_rt::TcpStream::is_write_vectored(self)
    }
}

impl<S> WriteVectored for futures_rustls::client::TlsStream<S> {
    fn is_write_vectored(&self) -> bool {
        // The slices go to the rustls session writer, which copies them into
        // the record it is building whatever the socket below does with them.
        true
    }
}

/// A `futures-io` stream presented as a hyper stream.
pub(crate) struct FuturesIo<S> {
    inner: S,
    /// Reads land here first and are copied into hyper's cursor.
    ///
    /// hyper hands out a cursor over possibly-uninitialized memory, and the
    /// only safe way to fill it is [`put_slice`](hyper::rt::ReadBufCursor). The
    /// alternative -- exposing the uninitialized bytes to
    /// [`AsyncRead::poll_read`] -- needs `unsafe`, which this crate forbids, so
    /// a read costs one extra copy of the bytes already in memory.
    scratch: Vec<u8>,
}

impl<S> FuturesIo<S> {
    pub(crate) fn new(inner: S) -> FuturesIo<S> {
        FuturesIo {
            inner,
            scratch: Vec::new(),
        }
    }
}

impl<S: AsyncRead + Unpin> hyper::rt::Read for FuturesIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let want = buf.remaining().min(MAX_READ);
        // hyper reserves capacity before every read, so it never asks for zero;
        // the branch exists so the read below is never handed a zero-length
        // slice, which a stream may answer with `Ok(0)` -- end of stream. Filling
        // nothing is what hyper reads as end of stream too, so the two agree on
        // an input hyper does not produce. `Poll::Pending` would be worse: there
        // is no waker to register, so the connection task would never be woken.
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

/// Hands hyper's connection tasks to the runtime backend.
#[derive(Clone, Copy)]
pub(crate) struct RtExecutor;

impl<F> hyper::rt::Executor<F> for RtExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        // Dropping the handle leaves the task running, which is what a
        // connection driver needs: it outlives the request that opened it.
        drop(ostrya_rt::spawn(future));
    }
}

/// Hands hyper's delays to the runtime backend. An HTTP/2 connection needs one
/// to schedule its keep-alive ping and the wait for the reply.
#[derive(Clone, Copy)]
pub(crate) struct RtTimer;

impl hyper::rt::Timer for RtTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        Box::pin(RtSleep {
            deadline: ostrya_rt::Deadline::new(duration),
        })
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        // A deadline already past is a zero-length window, which expires on its
        // first poll.
        self.sleep(deadline.saturating_duration_since(Instant::now()))
    }
}

/// One delay, as a future hyper can hold.
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
    /// forwards the vectored write to it, so every slice lands.
    impl WriteVectored for Cursor<Vec<u8>> {
        fn is_write_vectored(&self) -> bool {
            true
        }
    }

    /// A sink that leaves `poll_write_vectored` at the `futures-io` default,
    /// which writes the first non-empty slice and no more.
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

    /// What hyper is told about vectored writes is what the stream underneath
    /// says, so hyper coalesces the slices itself when they would not all be
    /// taken.
    #[test]
    fn the_vectored_write_answer_comes_from_the_stream() {
        let vectored = FuturesIo::new(Cursor::new(Vec::new()));
        assert!(Write::is_write_vectored(&vectored));
        let plain = FuturesIo::new(PlainSink(Vec::new()));
        assert!(!Write::is_write_vectored(&plain));
    }

    /// Drive `poll_read` once through hyper's cursor and report what landed.
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
        // At EOF the cursor stays empty, which is how hyper sees end of stream.
        assert!(read_once(&mut io, 4).is_empty());
    }

    /// A cursor with no room is an input hyper does not produce, since it
    /// reserves capacity before every read. What the branch is there for is the
    /// stream below it, which is never handed a zero-length slice.
    #[test]
    fn a_zero_capacity_cursor_reads_nothing() {
        let mut io = FuturesIo::new(Cursor::new(b"data".to_vec()));
        assert!(read_once(&mut io, 0).is_empty());
        // The stream is untouched, so the bytes are still there.
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
