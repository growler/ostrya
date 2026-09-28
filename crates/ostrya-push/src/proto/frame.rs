//! The frame codec and the chunked object stream.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

use super::{ABANDON, Kind, MAX_FRAME_LIMIT, MIN_FRAME_LIMIT, Message, protocol};
use crate::error::{Error, Result};

fn clamp_limit(limit: u32) -> u32 {
    limit.clamp(MIN_FRAME_LIMIT, MAX_FRAME_LIMIT)
}

fn eof() -> Error {
    Error::Io(io::ErrorKind::UnexpectedEof.into())
}

fn limit_exceeded(what: &str, len: u32, limit: u32) -> Error {
    Error::LimitExceeded(format!("{what} of {len} bytes is over the limit {limit}"))
}

#[derive(Debug)]
enum ReadState {
    Frames,
    /// Inside an object. `remaining` is what is left of the current chunk.
    /// At 0 the next chunk length is read, and `prefix` holds the `got`
    /// bytes of it already read.
    Object {
        remaining: u32,
        prefix: [u8; 4],
        got: u8,
    },
}

impl ReadState {
    fn object() -> ReadState {
        ReadState::Object {
            remaining: 0,
            prefix: [0; 4],
            got: 0,
        }
    }
}

/// One step of the object stream.
enum Step {
    Data(usize),
    End,
    /// The abandon marker. The `Abort` frame that must follow is not read.
    Marker,
}

/// The result of one [`FrameReader::read_object_data`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectRead {
    /// This number of object bytes is at the start of the buffer.
    Data(usize),
    /// The object ended. Frames follow.
    End,
    /// The sender abandoned the object, and the `Abort` frame that must
    /// follow the marker was read.
    Abandoned,
}

/// Reads frames and object chunks from a stream.
///
/// Wrap a raw socket or pipe in a buffered reader: a frame takes three reads
/// and a chunk two. A buffered reader that passes a large read through to
/// the stream does not copy the object bytes a second time.
///
/// The futures of the reader are not cancel-safe. A call that is dropped
/// before it completes can leave part of a frame or a chunk prefix read, and
/// the next call then reads from the middle of it. After a cancelled call,
/// drop the reader.
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    limit: u32,
    state: ReadState,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// A reader with the limit [`MIN_FRAME_LIMIT`].
    pub fn new(inner: R) -> Self {
        FrameReader {
            inner,
            limit: MIN_FRAME_LIMIT,
            state: ReadState::Frames,
        }
    }

    /// Set the frame and chunk limit. The value is clamped to
    /// `MIN_FRAME_LIMIT..=MAX_FRAME_LIMIT`.
    ///
    /// The reader allocates the body of a frame in full, up to the limit. A
    /// client keeps its own read limit, for example [`MAX_FRAME`], and does
    /// not take the `max-frame` of the server here. The client gives that
    /// value to its [`FrameWriter`] alone.
    ///
    /// [`MAX_FRAME`]: super::MAX_FRAME
    pub fn set_limit(&mut self, limit: u32) {
        self.limit = clamp_limit(limit);
    }

    /// The frame and chunk limit.
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Read the next message. `Ok(None)` is an end of file at a frame
    /// boundary. An end of file inside a frame is an [`Error::Io`] of kind
    /// `UnexpectedEof`. After an `ObjectHeader`, the object bytes must be read
    /// to their end with [`read_object_data`](Self::read_object_data) before
    /// the next message.
    pub async fn read_message(&mut self) -> Result<Option<Message>> {
        if let ReadState::Object { .. } = self.state {
            return Err(protocol("object data not read to its end"));
        }
        let mut prefix = [0u8; 4];
        let mut got = 0;
        while got < prefix.len() {
            let n = self.inner.read(&mut prefix[got..]).await?;
            if n == 0 {
                return if got == 0 { Ok(None) } else { Err(eof()) };
            }
            got += n;
        }
        let len = u32::from_be_bytes(prefix);
        if len == 0 {
            return Err(protocol("frame of length 0"));
        }
        if len > self.limit {
            return Err(limit_exceeded("frame", len, self.limit));
        }
        let mut kind = [0u8; 1];
        self.inner.read_exact(&mut kind).await?;
        let kind = Kind::from_u8(kind[0])?;
        let mut body = vec![0u8; len as usize - 1];
        self.inner.read_exact(&mut body).await?;
        let msg = Message::decode(kind, &body)?;
        if let Message::ObjectHeader(_) = msg {
            self.state = ReadState::object();
        }
        Ok(Some(msg))
    }

    /// The bytes of the current object as an `AsyncRead`. See [`ObjectBody`].
    pub fn object_body(&mut self) -> ObjectBody<'_, R> {
        ObjectBody {
            reader: self,
            state: BodyState::Reading,
            error: None,
        }
    }

    /// Read object bytes into `buf`. A chunk longer than `buf` arrives over
    /// several calls, so `buf` bounds the memory. An empty `buf` reads
    /// nothing and returns `Data(0)`. Outside an object the call is the error
    /// `protocol`.
    pub async fn read_object_data(&mut self, buf: &mut [u8]) -> Result<ObjectRead> {
        match poll_fn(|cx| self.poll_step(cx, buf)).await? {
            Step::Data(n) => Ok(ObjectRead::Data(n)),
            Step::End => Ok(ObjectRead::End),
            Step::Marker => self.read_abort().await.map(|()| ObjectRead::Abandoned),
        }
    }

    /// Read the frame that must follow the abandon marker: `Abort`, or the
    /// error `protocol`.
    async fn read_abort(&mut self) -> Result<()> {
        match self.read_message().await? {
            Some(Message::Abort) => Ok(()),
            Some(other) => {
                // An ObjectHeader sets the object state. The error leaves the
                // reader between frames.
                self.state = ReadState::Frames;
                Err(protocol(format!(
                    "{:?} after the abandon marker",
                    other.kind()
                )))
            }
            None => Err(eof()),
        }
    }

    /// Read the next step of the object stream into `buf`. A partial chunk
    /// length is kept in the state, so a pending read loses no byte.
    fn poll_step(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<Step>> {
        let FrameReader {
            inner,
            limit,
            state,
        } = self;
        let ReadState::Object {
            remaining,
            prefix,
            got,
        } = state
        else {
            return Poll::Ready(Err(protocol("no object to read")));
        };
        if buf.is_empty() {
            return Poll::Ready(Ok(Step::Data(0)));
        }
        if *remaining == 0 {
            while usize::from(*got) < prefix.len() {
                let n =
                    ready!(Pin::new(&mut *inner).poll_read(cx, &mut prefix[usize::from(*got)..]))?;
                if n == 0 {
                    return Poll::Ready(Err(eof()));
                }
                *got += n as u8;
            }
            *got = 0;
            match u32::from_be_bytes(*prefix) {
                0 => {
                    *state = ReadState::Frames;
                    return Poll::Ready(Ok(Step::End));
                }
                ABANDON => {
                    *state = ReadState::Frames;
                    return Poll::Ready(Ok(Step::Marker));
                }
                len if len > *limit => {
                    return Poll::Ready(Err(limit_exceeded("chunk", len, *limit)));
                }
                len => *remaining = len,
            }
        }
        let want = buf.len().min(*remaining as usize);
        let n = ready!(Pin::new(&mut *inner).poll_read(cx, &mut buf[..want]))?;
        if n == 0 {
            return Poll::Ready(Err(eof()));
        }
        *remaining -= n as u32;
        Poll::Ready(Ok(Step::Data(n)))
    }

    /// The underlying stream.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyState {
    Reading,
    Finished,
    Abandoned,
    /// A read failed with an error of this kind, which every later read
    /// repeats.
    Failed(io::ErrorKind),
}

/// The bytes of one object, read from a [`FrameReader`] as an `AsyncRead`.
///
/// A read returns object bytes until the chunk of length 0, and then end of
/// file. A read that meets the abandon marker, a codec error, or an error of
/// the stream fails with an `io::Error`, and every later read fails too.
/// After the abandon marker, [`is_abandoned`](Self::is_abandoned) is true, and
/// [`finish_abandon`](Self::finish_abandon) reads the `Abort` frame that must
/// follow. After another failure, [`take_error`](Self::take_error) gives the
/// error of the reader, with its wire code.
///
/// The body keeps a partial chunk length in the reader, so a read that returns
/// `Pending` loses no byte. A read that is dropped before it completes leaves
/// the reader in a consistent state.
#[derive(Debug)]
pub struct ObjectBody<'a, R> {
    reader: &'a mut FrameReader<R>,
    state: BodyState,
    error: Option<Error>,
}

impl<R: AsyncRead + Unpin> ObjectBody<'_, R> {
    /// Whether the object ended with the chunk of length 0.
    pub fn is_finished(&self) -> bool {
        self.state == BodyState::Finished
    }

    /// Whether the sender abandoned the object with the abandon marker.
    pub fn is_abandoned(&self) -> bool {
        self.state == BodyState::Abandoned
    }

    /// The error of the reader that failed a read: a codec error, such as
    /// `limit-exceeded` for a chunk over the limit, or [`Error::Io`] for an
    /// error of the stream. `None` when no read failed that way.
    pub fn take_error(&mut self) -> Option<Error> {
        self.error.take()
    }

    /// After the abandon marker, read the frame that must follow it. `Abort`
    /// gives `Ok`, and any other frame is the error `protocol`. Before the
    /// marker the call is the error `protocol`.
    pub async fn finish_abandon(self) -> Result<()> {
        if self.state != BodyState::Abandoned {
            return Err(protocol("the object was not abandoned"));
        }
        self.reader.read_abort().await
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ObjectBody<'_, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        match me.state {
            BodyState::Reading => {}
            BodyState::Finished => return Poll::Ready(Ok(0)),
            BodyState::Abandoned => return Poll::Ready(Err(io::Error::other("object abandoned"))),
            BodyState::Failed(kind) => {
                return Poll::Ready(Err(io::Error::new(kind, "object stream failed")));
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Fill `buf` across chunk boundaries while the stream has bytes ready,
        // so small chunks do not make small reads. Bytes already in `buf` are
        // returned before a pending read, the end, the marker, or an error,
        // which the next read then reports.
        let mut filled = 0;
        loop {
            let step = match me.reader.poll_step(cx, &mut buf[filled..]) {
                Poll::Ready(step) => step,
                Poll::Pending if filled > 0 => return Poll::Ready(Ok(filled)),
                Poll::Pending => return Poll::Pending,
            };
            match step {
                Ok(Step::Data(n)) => {
                    filled += n;
                    if filled == buf.len() {
                        return Poll::Ready(Ok(filled));
                    }
                }
                Ok(Step::End) => {
                    me.state = BodyState::Finished;
                    return Poll::Ready(Ok(filled));
                }
                Ok(Step::Marker) => {
                    me.state = BodyState::Abandoned;
                    if filled > 0 {
                        return Poll::Ready(Ok(filled));
                    }
                    return Poll::Ready(Err(io::Error::other("object abandoned")));
                }
                Err(e) => {
                    let io = match &e {
                        Error::Io(io) => io::Error::new(io.kind(), io.to_string()),
                        other => io::Error::other(other.to_string()),
                    };
                    me.error = Some(e);
                    me.state = BodyState::Failed(io.kind());
                    if filled > 0 {
                        return Poll::Ready(Ok(filled));
                    }
                    return Poll::Ready(Err(io));
                }
            }
        }
    }
}

/// Writes frames and object chunks to a stream.
///
/// The writer does not flush and holds no object bytes. The caller flushes
/// with [`flush`](Self::flush), or wraps the stream in a buffered writer.
/// A frame is one write, and a chunk is two: the length and the data. Wrap
/// a raw socket or pipe in a buffered writer.
///
/// The futures of the writer are not cancel-safe. A call that is dropped
/// before it completes can leave part of a frame or a chunk written. After a
/// cancelled call, drop the writer.
#[derive(Debug)]
pub struct FrameWriter<W> {
    inner: W,
    limit: u32,
    in_object: bool,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    /// A writer with the limit [`MIN_FRAME_LIMIT`].
    pub fn new(inner: W) -> Self {
        FrameWriter {
            inner,
            limit: MIN_FRAME_LIMIT,
            in_object: false,
        }
    }

    /// Set the limit of the peer: the `max-frame` it announced. The value is
    /// clamped to `MIN_FRAME_LIMIT..=MAX_FRAME_LIMIT`.
    pub fn set_limit(&mut self, limit: u32) {
        self.limit = clamp_limit(limit);
    }

    /// Write one message as a frame. A frame over the limit is the error
    /// `limit-exceeded`, and nothing is written. Inside an object the call is
    /// the error `protocol`.
    pub async fn write_message(&mut self, msg: &Message) -> Result<()> {
        if self.in_object {
            return Err(protocol("message inside an object"));
        }
        let body = msg.encode_body()?;
        let len = u32::try_from(body.len() + 1)
            .ok()
            .filter(|len| *len <= self.limit)
            .ok_or_else(|| {
                Error::LimitExceeded(format!(
                    "frame of {} bytes is over the limit {}",
                    body.len() + 1,
                    self.limit
                ))
            })?;
        let mut frame = Vec::with_capacity(4 + len as usize);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.push(msg.kind().as_u8());
        frame.extend_from_slice(&body);
        self.inner.write_all(&frame).await?;
        self.in_object = matches!(msg, Message::ObjectHeader(_));
        Ok(())
    }

    /// Write object bytes as chunks of at most the limit. An empty `data`
    /// writes nothing. Outside an object the call is the error `protocol`.
    ///
    /// Each call with data writes one chunk or more, and each chunk costs 4
    /// bytes of framing and one read call on the peer. Give the object bytes in large
    /// pieces, 64 KiB or more.
    pub async fn write_object_data(&mut self, data: &[u8]) -> Result<()> {
        if !self.in_object {
            return Err(protocol("object data outside an object"));
        }
        for chunk in data.chunks(self.limit as usize) {
            self.inner
                .write_all(&(chunk.len() as u32).to_be_bytes())
                .await?;
            self.inner.write_all(chunk).await?;
        }
        Ok(())
    }

    /// End the object with a chunk of length 0.
    pub async fn end_object(&mut self) -> Result<()> {
        if !self.in_object {
            return Err(protocol("no object to end"));
        }
        self.inner.write_all(&0u32.to_be_bytes()).await?;
        self.in_object = false;
        Ok(())
    }

    /// Abandon the object: write the marker [`ABANDON`] and then the `Abort`
    /// frame.
    pub async fn abandon_object(&mut self) -> Result<()> {
        if !self.in_object {
            return Err(protocol("no object to abandon"));
        }
        self.inner.write_all(&ABANDON.to_be_bytes()).await?;
        self.in_object = false;
        self.write_message(&Message::Abort).await
    }

    /// Flush the underlying stream.
    pub async fn flush(&mut self) -> Result<()> {
        self.inner.flush().await?;
        Ok(())
    }

    /// The underlying stream.
    pub fn into_inner(self) -> W {
        self.inner
    }
}
