//! The request bodies of the receive endpoint.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_io::AsyncRead;
use futures_lite::future;
use futures_lite::io::AsyncReadExt;
use hyper::body::{Body, Buf, Bytes};
use ostrya::push;
use ostrya::push::proto::{Kind, MAX_FRAME, Message};
use ostrya_rt as rt;

use crate::session::BodyTrack;

/// The most bytes of a request body the server reads and drops before it
/// answers a request that it refuses before the body.
const MAX_DRAIN: u64 = 1024 * 1024;

/// The longest time the server reads and drops a request body before it
/// answers a request that it refuses before the body. A shorter idle
/// timeout of the sessions bounds the read too.
const MAX_DRAIN_TIME: Duration = Duration::from_secs(5);

/// The most frames that give no bytes, empty data frames and trailers, that
/// one read takes before it gives the task back to the runtime.
const MAX_EMPTY_FRAMES: usize = 64;

/// A request body as an `AsyncRead`. One read takes the frames that the
/// body has ready until the buffer of the read is full, and the bytes of a
/// frame that a read does not take wait for the next read. Trailers are
/// ignored. A read gives the task back to the runtime after
/// [`MAX_EMPTY_FRAMES`] frames that give no bytes. With a tracker, the body
/// records in its session when it starts to wait for the client, when it
/// delivers bytes again, and when it fails.
/// A body that the server does not poll does not wait, and a read that
/// returns bytes does not wait either.
pub(crate) struct RequestBody<B> {
    inner: B,
    /// The bytes of the last frame that no read took yet.
    rest: Bytes,
    ended: bool,
    track: Option<BodyTrack>,
    /// The tracker holds the body as waiting.
    waiting: bool,
}

impl<B> RequestBody<B> {
    pub(crate) fn new(inner: B, track: Option<BodyTrack>) -> RequestBody<B> {
        RequestBody {
            inner,
            rest: Bytes::new(),
            ended: false,
            track,
            waiting: false,
        }
    }

    /// Record a change of the wait for the client in the session.
    fn set_waiting(&mut self, waiting: bool) {
        if self.waiting == waiting {
            return;
        }
        self.waiting = waiting;
        if let Some(track) = &self.track {
            if waiting {
                track.waiting();
            } else {
                track.progress();
            }
        }
    }
}

impl<B> AsyncRead for RequestBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let mut n = 0;
        let mut empty = 0;
        loop {
            if !me.rest.is_empty() {
                let take = me.rest.len().min(buf.len() - n);
                buf[n..n + take].copy_from_slice(&me.rest[..take]);
                me.rest.advance(take);
                n += take;
            }
            if me.ended || n == buf.len() {
                return Poll::Ready(Ok(n));
            }
            match Pin::new(&mut me.inner).poll_frame(cx) {
                Poll::Pending if n > 0 => return Poll::Ready(Ok(n)),
                Poll::Pending => {
                    me.set_waiting(true);
                    return Poll::Pending;
                }
                Poll::Ready(None) => {
                    me.ended = true;
                    me.set_waiting(false);
                }
                Poll::Ready(Some(Err(e))) => {
                    if let Some(track) = &me.track {
                        track.cut();
                    }
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    match frame.into_data() {
                        Ok(data) => {
                            if data.is_empty() {
                                empty += 1;
                            }
                            me.rest = data;
                            me.set_waiting(false);
                        }
                        Err(_) => empty += 1,
                    }
                    if empty == MAX_EMPTY_FRAMES {
                        if n > 0 {
                            return Poll::Ready(Ok(n));
                        }
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
            }
        }
    }
}

fn protocol(message: impl Into<String>) -> push::Error {
    push::Error::Protocol(message.into())
}

/// Read the one message of `body`: one frame of at most [`MAX_FRAME`]
/// bytes, and then the end of the body. An empty body, a body that ends
/// inside its frame, and a byte after the frame are `protocol`. The buffer
/// of the frame grows with the bytes that arrive, and not with the length
/// that the frame states.
pub(crate) async fn read_message<B>(body: &mut RequestBody<B>) -> Result<Message, push::Error>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut prefix = [0u8; 4];
    let mut got = 0;
    while got < prefix.len() {
        let n = body.read(&mut prefix[got..]).await?;
        if n == 0 {
            return Err(protocol(if got == 0 {
                "the request body holds no message"
            } else {
                "the request body ends inside its frame"
            }));
        }
        got += n;
    }
    let len = u32::from_be_bytes(prefix);
    if len == 0 {
        return Err(protocol("frame of length 0"));
    }
    if len > MAX_FRAME {
        return Err(push::Error::LimitExceeded(format!(
            "frame of {len} bytes is over the limit {MAX_FRAME}"
        )));
    }
    let mut frame = Vec::new();
    (&mut *body)
        .take(u64::from(len))
        .read_to_end(&mut frame)
        .await?;
    if frame.len() < len as usize {
        return Err(protocol("the request body ends inside its frame"));
    }
    let mut byte = [0u8];
    if body.read(&mut byte).await? != 0 {
        return Err(protocol("bytes follow the message of the request body"));
    }
    Message::decode(Kind::from_u8(frame[0])?, &frame[1..])
}

/// The time [`drain`] reads a body for, with the session idle timeout
/// `idle`: the shorter of `idle` and [`MAX_DRAIN_TIME`].
fn drain_time(idle: Duration) -> Duration {
    idle.min(MAX_DRAIN_TIME)
}

/// Read and drop the bytes of `body`, up to [`MAX_DRAIN`] bytes and for at
/// most the shorter of `idle` and [`MAX_DRAIN_TIME`]. `true` when the body
/// reached its end.
pub(crate) async fn drain<B>(mut body: B, idle: Duration) -> bool
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if body.is_end_stream() {
        return true;
    }
    let limit = drain_time(idle);
    let read = async {
        let mut taken = 0u64;
        loop {
            match poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
                None => return true,
                Some(Err(_)) => return false,
                Some(Ok(frame)) => {
                    // A frame that gives no bytes counts as one byte, so
                    // that the limit also ends a body of such frames.
                    taken += match frame.into_data() {
                        Ok(data) => (data.len() as u64).max(1),
                        Err(_) => 1,
                    };
                    if taken > MAX_DRAIN {
                        return false;
                    }
                }
            }
        }
    };
    future::or(read, async {
        rt::Timer::after(limit).await;
        false
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::pin;
    use std::task::Waker;

    use hyper::HeaderMap;
    use hyper::body::Frame;
    use ostrya::push::proto::FrameWriter;
    use ostrya_rt::block_on;

    use super::*;

    /// A body that gives its frames in order. A `None` step returns
    /// `Pending` once and wakes the task at once.
    struct Script(VecDeque<Option<Bytes>>);

    impl Script {
        fn new(steps: impl IntoIterator<Item = Option<Vec<u8>>>) -> RequestBody<Script> {
            let steps = steps.into_iter().map(|s| s.map(Bytes::from)).collect();
            RequestBody::new(Script(steps), None)
        }
    }

    impl Body for Script {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
            match self.0.pop_front() {
                None => Poll::Ready(None),
                Some(None) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Some(Some(bytes)) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            }
        }
    }

    /// A body that gives `first` as one data frame when it is not empty,
    /// and then frames that give no bytes without end: trailers when
    /// `trailers` is set, and empty data frames otherwise. `polls` counts
    /// the frames that the body gave.
    struct Endless {
        first: Bytes,
        trailers: bool,
        polls: usize,
    }

    impl Endless {
        fn new(first: &[u8], trailers: bool) -> Endless {
            Endless {
                first: Bytes::copy_from_slice(first),
                trailers,
                polls: 0,
            }
        }
    }

    impl Body for Endless {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
            self.polls += 1;
            let frame = if !self.first.is_empty() {
                Frame::data(std::mem::take(&mut self.first))
            } else if self.trailers {
                Frame::trailers(HeaderMap::new())
            } else {
                Frame::data(Bytes::new())
            };
            Poll::Ready(Some(Ok(frame)))
        }
    }

    /// A read of a body that gives frames without bytes without end gives
    /// the task back after [`MAX_EMPTY_FRAMES`] such frames. The read is
    /// `Pending` when it has no bytes, and gives the bytes that it has
    /// otherwise.
    #[test]
    fn a_read_yields_on_frames_without_bytes() {
        let mut cx = Context::from_waker(Waker::noop());
        for trailers in [false, true] {
            let mut body = RequestBody::new(Endless::new(b"", trailers), None);
            {
                let read = pin!(read_message(&mut body));
                assert!(read.poll(&mut cx).is_pending());
            }
            assert_eq!(body.inner.polls, MAX_EMPTY_FRAMES);

            let mut body = RequestBody::new(Endless::new(b"ab", trailers), None);
            let mut buf = [0u8; 4];
            let read = Pin::new(&mut body).poll_read(&mut cx, &mut buf);
            assert!(matches!(read, Poll::Ready(Ok(2))), "{read:?}");
            assert_eq!(&buf[..2], b"ab");
            assert_eq!(body.inner.polls, 1 + MAX_EMPTY_FRAMES);
        }
    }

    /// A drain of a body that gives frames without bytes without end stops
    /// at the byte limit, because each frame counts as one byte at least.
    #[test]
    fn a_drain_stops_on_frames_without_bytes() {
        for trailers in [false, true] {
            let body = Endless::new(b"", trailers);
            assert!(!block_on(drain(body, Duration::from_secs(300))));
        }
    }

    /// The drain of a refusal reads for the idle timeout when it is short,
    /// and for 5 seconds at most.
    #[test]
    fn the_drain_time_is_the_idle_timeout_up_to_5_seconds() {
        let ms = Duration::from_millis;
        assert_eq!(drain_time(ms(500)), ms(500));
        assert_eq!(drain_time(ms(5000)), ms(5000));
        assert_eq!(drain_time(ms(5001)), MAX_DRAIN_TIME);
        assert_eq!(drain_time(Duration::from_secs(300)), MAX_DRAIN_TIME);
        assert_eq!(MAX_DRAIN_TIME, Duration::from_secs(5));
    }

    /// One read takes the frames that are ready until its buffer is full,
    /// and returns the bytes it has when the body waits.
    #[test]
    fn a_read_takes_every_ready_frame() {
        let frame = |b: u8| Some(vec![b; 16 * 1024]);
        let mut body = Script::new([frame(1), frame(2), frame(3), frame(4), frame(5)]);
        let mut buf = vec![0u8; 64 * 1024];
        assert_eq!(block_on(body.read(&mut buf)).unwrap(), 64 * 1024);
        assert_eq!(buf[16 * 1024], 2);
        assert_eq!(buf[64 * 1024 - 1], 4);
        assert_eq!(block_on(body.read(&mut buf)).unwrap(), 16 * 1024);
        assert_eq!(buf[0], 5);
        assert_eq!(block_on(body.read(&mut buf)).unwrap(), 0);

        let mut body = Script::new([frame(1), frame(2), None, frame(3)]);
        assert_eq!(block_on(body.read(&mut buf)).unwrap(), 32 * 1024);
        assert_eq!(block_on(body.read(&mut buf)).unwrap(), 16 * 1024);
        assert_eq!(buf[0], 3);

        let mut body = Script::new([Some(b"abcdef".to_vec())]);
        let mut small = [0u8; 4];
        assert_eq!(block_on(body.read(&mut small)).unwrap(), 4);
        assert_eq!(block_on(body.read(&mut small)).unwrap(), 2);
        assert_eq!(&small[..2], b"ef");
    }

    fn frame_of(message: &Message) -> Vec<u8> {
        let mut writer = FrameWriter::new(Vec::new());
        block_on(writer.write_message(message)).unwrap();
        writer.into_inner()
    }

    fn read(steps: Vec<Option<Vec<u8>>>) -> Result<Message, push::Error> {
        block_on(read_message(&mut Script::new(steps)))
    }

    /// A body of one frame gives its message, also in pieces. An empty
    /// body, a body that ends inside its frame, a frame of length 0, and a
    /// byte after the frame are `protocol`, and a frame past the limit is
    /// `limit-exceeded` before its body arrives.
    #[test]
    fn a_body_holds_one_message() {
        let have = frame_of(&Message::Have(Vec::new()));
        let pieces = have.chunks(2).map(|c| Some(c.to_vec())).collect();
        assert!(matches!(read(pieces).unwrap(), Message::Have(_)));

        let protocol = |steps: Vec<Option<Vec<u8>>>, text: &str| match read(steps) {
            Err(push::Error::Protocol(m)) => assert!(m.contains(text), "{m}"),
            other => panic!("{text}: {other:?}"),
        };
        protocol(Vec::new(), "holds no message");
        protocol(vec![Some(vec![0, 0])], "ends inside its frame");
        protocol(
            vec![Some(have[..have.len() - 1].to_vec())],
            "ends inside its frame",
        );
        protocol(vec![Some(vec![0, 0, 0, 0])], "length 0");
        let mut trailing = have.clone();
        trailing.push(0);
        protocol(vec![Some(trailing)], "bytes follow");

        let over = (MAX_FRAME + 1).to_be_bytes().to_vec();
        assert!(matches!(
            read(vec![Some(over)]),
            Err(push::Error::LimitExceeded(_))
        ));
        let stated = MAX_FRAME.to_be_bytes().to_vec();
        protocol(
            vec![Some(stated), Some(vec![3; 10])],
            "ends inside its frame",
        );
    }
}
