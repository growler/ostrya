//! The response body of the server.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_io::AsyncRead;
use hyper::body::{Body, Bytes, Frame, SizeHint};

use crate::receive::ReplyBody;
use crate::stall::Tracker;

/// The largest frame a stream body yields.
const MAX_FRAME: usize = 64 * 1024;

/// The bytes a stream body gives in one run of polls before it yields to the
/// executor, so a body whose reader is always ready, such as a `.filez` built
/// on request, does not hold the executor thread for long.
const YIELD_AFTER: usize = 256 * 1024;

/// A response body: empty, bytes held whole, a stream read in frames, or the
/// reply of a commit of the receive endpoint.
pub(crate) enum ServeBody {
    Empty,
    /// The bytes, until the one frame that carries them is taken.
    Full(Option<Bytes>),
    Stream(StreamBody),
    Reply(ReplyBody),
}

impl ServeBody {
    /// A body over `reader`. With `len`, the body ends after `len` bytes, and
    /// a reader that ends sooner fails the body, so a short body is never
    /// sent as a whole one. `tracker` records each frame hyper takes.
    pub(crate) fn stream(
        reader: Box<dyn AsyncRead + Unpin + Send>,
        len: Option<u64>,
        tracker: Tracker,
    ) -> ServeBody {
        ServeBody::Stream(StreamBody {
            reader,
            remaining: len,
            buf: Vec::new(),
            run: 0,
            tracker,
        })
    }
}

/// A body read from a stream in frames of at most [`MAX_FRAME`] bytes.
pub(crate) struct StreamBody {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    /// The bytes still to give, when the length is known.
    remaining: Option<u64>,
    /// The buffer the next read lands in. A read that completes moves it
    /// into its frame, so the bytes are not copied again.
    buf: Vec<u8>,
    /// The bytes given since the body last returned `Pending`.
    run: usize,
    tracker: Tracker,
}

impl StreamBody {
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let want = match self.remaining {
            Some(0) => return Poll::Ready(None),
            Some(n) => n.min(MAX_FRAME as u64) as usize,
            None => MAX_FRAME,
        };
        if self.run >= YIELD_AFTER {
            self.run = 0;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.buf.len() < want {
            self.buf.resize(want, 0);
        }
        let read = Pin::new(&mut self.reader).poll_read(cx, &mut self.buf[..want]);
        let n = match read {
            Poll::Pending => {
                self.run = 0;
                self.tracker.reading();
                return Poll::Pending;
            }
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
        };
        if n == 0 {
            return Poll::Ready(self.remaining.map(|_| {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the file ended before its length",
                ))
            }));
        }
        if let Some(remaining) = &mut self.remaining {
            *remaining -= n as u64;
        }
        self.run += n;
        self.tracker.progress();
        let mut data = std::mem::take(&mut self.buf);
        data.truncate(n);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(data)))))
    }
}

/// The response body of
/// [`ReceiveEndpoint::handle`](crate::ReceiveEndpoint::handle). It is `Send`
/// and `Unpin`. A body is empty or holds one frame of the push protocol,
/// whole. The body of a `CommitReply` gives the report of the commit to
/// [`EndpointOptions::on_report`](crate::EndpointOptions::on_report) when
/// it drops.
pub struct ReceiveBody(pub(crate) ServeBody);

impl ReceiveBody {
    /// The body as a response body of the server.
    pub(crate) fn into_serve(self) -> ServeBody {
        self.0
    }
}

/// The body is opaque.
impl fmt::Debug for ReceiveBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiveBody").finish_non_exhaustive()
    }
}

impl Body for ReceiveBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        Pin::new(&mut self.get_mut().0).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

impl Body for ServeBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        match self.get_mut() {
            ServeBody::Empty => Poll::Ready(None),
            ServeBody::Full(bytes) => Poll::Ready(bytes.take().map(|b| Ok(Frame::data(b)))),
            ServeBody::Stream(stream) => stream.poll_frame(cx),
            ServeBody::Reply(reply) => Poll::Ready(reply.poll_frame().map(Ok)),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ServeBody::Empty => true,
            ServeBody::Full(bytes) => bytes.is_none(),
            ServeBody::Stream(stream) => stream.remaining == Some(0),
            ServeBody::Reply(reply) => reply.remaining() == 0,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            ServeBody::Empty => SizeHint::with_exact(0),
            ServeBody::Full(bytes) => {
                SizeHint::with_exact(bytes.as_ref().map_or(0, |b| b.len() as u64))
            }
            ServeBody::Stream(stream) => stream
                .remaining
                .map_or_else(SizeHint::default, SizeHint::with_exact),
            ServeBody::Reply(reply) => SizeHint::with_exact(reply.remaining()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};
    use std::time::Duration;

    use super::*;
    use crate::stall::Stall;
    use futures_lite::io::Cursor;
    use ostrya_rt::block_on;

    /// Every frame of `body`, or the error that ended it.
    pub(crate) async fn frames(mut body: ServeBody) -> io::Result<Vec<Bytes>> {
        let mut out = Vec::new();
        while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
        {
            out.push(frame?.into_data().unwrap());
        }
        Ok(out)
    }

    fn reader(bytes: Vec<u8>) -> Box<dyn AsyncRead + Unpin + Send> {
        Box::new(Cursor::new(bytes))
    }

    /// A tracker of a connection whose deadline never matters to the test.
    pub(crate) fn tracker() -> Tracker {
        Stall::new(Duration::from_secs(3600)).track()
    }

    fn stream(bytes: Vec<u8>, len: Option<u64>) -> ServeBody {
        ServeBody::stream(reader(bytes), len, tracker())
    }

    #[test]
    fn a_stream_yields_frames_of_at_most_64_kib() {
        let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        for len in [None, Some(200_000)] {
            let frames = block_on(frames(stream(data.clone(), len))).unwrap();
            assert!(frames.iter().all(|f| f.len() <= MAX_FRAME && !f.is_empty()));
            assert_eq!(frames.concat(), data);
        }
    }

    /// A known length ends the body there, and a reader that ends sooner
    /// fails it.
    #[test]
    fn a_known_length_bounds_the_body() {
        let body = stream(b"0123456789".to_vec(), Some(4));
        assert_eq!(body.size_hint().exact(), Some(4));
        assert_eq!(block_on(frames(body)).unwrap().concat(), b"0123");
        let err = block_on(frames(stream(b"012".to_vec(), Some(4)))).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(stream(Vec::new(), Some(0)).is_end_stream());
        assert_eq!(stream(b"x".to_vec(), None).size_hint().exact(), None);
    }

    /// Counts the wakes of a waker.
    struct CountWakes(AtomicUsize);

    impl Wake for CountWakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A body whose reader is always ready gives 256 KiB in one run of
    /// polls, then wakes its task and returns `Pending` once.
    #[test]
    fn a_ready_stream_yields_after_256_kib() {
        let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut body = stream(vec![7u8; 1024 * 1024], None);
        let mut given = 0;
        loop {
            match Pin::new(&mut body).poll_frame(&mut cx) {
                Poll::Ready(Some(frame)) => given += frame.unwrap().into_data().unwrap().len(),
                Poll::Pending => break,
                Poll::Ready(None) => panic!("the body ended before it yielded"),
            }
        }
        assert_eq!(given, YIELD_AFTER);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Ready(Some(Ok(_)))
        ));
    }
}
