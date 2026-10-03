//! The frame codec, the chunked object stream, and the pull bodies.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

use super::message::{get_reply_frame, object_header_frame};
use super::{
    ABANDON, ErrorMessage, GetReply, Kind, MAX_FRAME_LIMIT, MIN_FRAME_LIMIT, Message, protocol,
};
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

/// The kind of a body: the frame that follows the abandon marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    /// An object of the push, after `ObjectHeader`. `Abort` follows the
    /// marker.
    Object,
    /// A body of the pull, after `GetReply` with found true. `Error` follows
    /// the marker.
    Pull,
}

impl BodyKind {
    /// The kind of body that follows `msg`, or `None` when no body follows.
    fn after(msg: &Message) -> Option<BodyKind> {
        match msg {
            Message::ObjectHeader(_) => Some(BodyKind::Object),
            Message::GetReply(GetReply { found: true, .. }) => Some(BodyKind::Pull),
            _ => None,
        }
    }
}

#[derive(Debug)]
enum ReadState {
    Frames,
    /// Inside a body of `kind`. `remaining` is what is left of the current
    /// chunk. At 0 the next chunk length is read, and `prefix` holds the
    /// `got` bytes of it already read.
    Body {
        kind: BodyKind,
        remaining: u32,
        prefix: [u8; 4],
        got: u8,
    },
}

impl ReadState {
    fn body(kind: BodyKind) -> ReadState {
        ReadState::Body {
            kind,
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
    /// The abandon marker in a body of this kind. The frame that must follow
    /// is not read.
    Marker(BodyKind),
}

/// The result of one [`FrameReader::read_object_data`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectRead {
    /// This number of body bytes is at the start of the buffer.
    Data(usize),
    /// The body ended. Frames follow.
    End,
    /// The sender abandoned an object of the push, and the `Abort` frame that
    /// must follow the marker was read. An abandoned body of the pull gives
    /// the error of its `Error` frame in place of this value.
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
    /// `UnexpectedEof`. After an `ObjectHeader`, and after a `GetReply` with
    /// found true, the body bytes must be read to their end with
    /// [`read_object_data`](Self::read_object_data) or
    /// [`object_body`](Self::object_body) before the next message.
    pub async fn read_message(&mut self) -> Result<Option<Message>> {
        if let ReadState::Body { .. } = self.state {
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
        if let Some(kind) = BodyKind::after(&msg) {
            self.state = ReadState::body(kind);
        }
        Ok(Some(msg))
    }

    /// The bytes of the current object or pull body as an `AsyncRead`. See
    /// [`ObjectBody`].
    pub fn object_body(&mut self) -> ObjectBody<'_, R> {
        ObjectBody {
            reader: self,
            state: BodyState::Reading,
            error: None,
        }
    }

    /// Read the bytes of an object or of a pull body into `buf`. A chunk
    /// longer than `buf` arrives over several calls, so `buf` bounds the
    /// memory. An empty `buf` reads nothing and returns `Data(0)`. Outside a
    /// body the call is the error `protocol`.
    ///
    /// After the abandon marker the call reads the frame that must follow
    /// it. In an object of the push, `Abort` gives
    /// [`ObjectRead::Abandoned`]. In a body of the pull, `Error` gives the
    /// error of its code, for example [`Error::Internal`]. Any other frame is
    /// the error `protocol`.
    pub async fn read_object_data(&mut self, buf: &mut [u8]) -> Result<ObjectRead> {
        match poll_fn(|cx| self.poll_step(cx, buf)).await? {
            Step::Data(n) => Ok(ObjectRead::Data(n)),
            Step::End => Ok(ObjectRead::End),
            Step::Marker(kind) => self
                .read_after_marker(kind)
                .await
                .map(|()| ObjectRead::Abandoned),
        }
    }

    /// Read the frame that must follow the abandon marker in a body of
    /// `kind`: `Abort` after an object, which gives `Ok`, and `Error` after a
    /// pull body, which gives the error of its code. Another frame is the
    /// error `protocol`.
    async fn read_after_marker(&mut self, kind: BodyKind) -> Result<()> {
        match (kind, self.read_message().await?) {
            (BodyKind::Object, Some(Message::Abort)) => Ok(()),
            (BodyKind::Pull, Some(Message::Error(e))) => Err(e.into()),
            (_, Some(other)) => {
                // An ObjectHeader or a GetReply with found true sets the body
                // state. The error leaves the reader between frames.
                self.state = ReadState::Frames;
                Err(protocol(format!(
                    "{:?} after the abandon marker",
                    other.kind()
                )))
            }
            (_, None) => Err(eof()),
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
        let ReadState::Body {
            kind,
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
                    let kind = *kind;
                    *state = ReadState::Frames;
                    return Poll::Ready(Ok(Step::Marker(kind)));
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

    /// A reference to the underlying stream. A caller that wraps the stream
    /// in a buffered reader can look at the bytes the buffer holds, for
    /// example to learn whether a whole frame waits there, with no read.
    pub fn get_ref(&self) -> &R {
        &self.inner
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
    Abandoned(BodyKind),
    /// A read failed with an error of this kind, which every later read
    /// repeats.
    Failed(io::ErrorKind),
}

/// The bytes of one object of the push, or of one body of the pull, read
/// from a [`FrameReader`] as an `AsyncRead`.
///
/// A read returns body bytes until the chunk of length 0, and then end of
/// file. A read that meets the abandon marker, a codec error, or an error of
/// the stream fails with an `io::Error`, and every later read fails too.
/// After the abandon marker, [`is_abandoned`](Self::is_abandoned) is true, and
/// [`finish_abandon`](Self::finish_abandon) reads the frame that must
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

    /// Whether the sender abandoned the body with the abandon marker.
    pub fn is_abandoned(&self) -> bool {
        matches!(self.state, BodyState::Abandoned(_))
    }

    /// The error of the reader that failed a read: a codec error, such as
    /// `limit-exceeded` for a chunk over the limit, or [`Error::Io`] for an
    /// error of the stream. `None` when no read failed that way.
    pub fn take_error(&mut self) -> Option<Error> {
        self.error.take()
    }

    /// After the abandon marker, read the frame that must follow it. In an
    /// object of the push, `Abort` gives `Ok`. In a body of the pull, `Error`
    /// gives the error of its code, for example [`Error::Internal`]. Any
    /// other frame is the error `protocol`. Before the marker the call is the
    /// error `protocol`.
    pub async fn finish_abandon(self) -> Result<()> {
        let BodyState::Abandoned(kind) = self.state else {
            return Err(protocol("the object was not abandoned"));
        };
        self.reader.read_after_marker(kind).await
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
            BodyState::Abandoned(_) => {
                return Poll::Ready(Err(io::Error::other("object abandoned")));
            }
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
                Ok(Step::Marker(kind)) => {
                    me.state = BodyState::Abandoned(kind);
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

/// The frame of `msg`: the length, the kind, and the body. A frame over
/// `limit` is the error `limit-exceeded`. A caller that sends the frame as
/// one buffer takes it from here with no copy of its own.
pub(crate) fn encode_frame(msg: &Message, limit: u32) -> Result<Vec<u8>> {
    let body = msg.encode_body()?;
    let len = u32::try_from(body.len() + 1)
        .ok()
        .filter(|len| *len <= limit)
        .ok_or_else(|| {
            Error::LimitExceeded(format!(
                "frame of {} bytes is over the limit {limit}",
                body.len() + 1
            ))
        })?;
    let mut frame = Vec::with_capacity(4 + len as usize);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.push(msg.kind().as_u8());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Writes frames, object chunks, and the chunks of pull bodies to a stream.
///
/// The writer enters the body state when it writes an `ObjectHeader` or a
/// `GetReply` with found true. [`write_object_data`](Self::write_object_data)
/// and [`end_object`](Self::end_object) serve both body kinds.
/// [`abandon_object`](Self::abandon_object) abandons an object of the push,
/// and [`abandon_body`](Self::abandon_body) a body of the pull.
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
    body: Option<BodyKind>,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    /// A writer with the limit [`MIN_FRAME_LIMIT`].
    pub fn new(inner: W) -> Self {
        FrameWriter {
            inner,
            limit: MIN_FRAME_LIMIT,
            body: None,
        }
    }

    /// Set the limit of the peer: the `max-frame` it announced. The value is
    /// clamped to `MIN_FRAME_LIMIT..=MAX_FRAME_LIMIT`.
    pub fn set_limit(&mut self, limit: u32) {
        self.limit = clamp_limit(limit);
    }

    /// Write one message as a frame. A frame over the limit is the error
    /// `limit-exceeded`, and nothing is written. Inside an object or a pull
    /// body the call is the error `protocol`. After an `ObjectHeader`, and
    /// after a `GetReply` with found true, the writer is in the body state.
    pub async fn write_message(&mut self, msg: &Message) -> Result<()> {
        if self.body.is_some() {
            return Err(protocol("message inside an object"));
        }
        // An object stream writes one `ObjectHeader` for each object, and a
        // pull session one `GetReply` for each path, so their frames are
        // built on the stack. Each frame is below every limit.
        if let Message::ObjectHeader(header) = msg {
            let frame = object_header_frame(header)?;
            self.inner.write_all(&frame).await?;
        } else if let Message::GetReply(reply) = msg {
            let (frame, used) = get_reply_frame(reply)?;
            self.inner.write_all(&frame[..used]).await?;
        } else {
            let frame = encode_frame(msg, self.limit)?;
            self.inner.write_all(&frame).await?;
        }
        self.body = BodyKind::after(msg);
        Ok(())
    }

    /// Write the bytes of an object or of a pull body as chunks of at most
    /// the limit. An empty `data` writes nothing. Outside a body the call is
    /// the error `protocol`.
    ///
    /// Each call with data writes one chunk or more, and each chunk costs 4
    /// bytes of framing and one read call on the peer. Give the object bytes in large
    /// pieces, 64 KiB or more.
    pub async fn write_object_data(&mut self, data: &[u8]) -> Result<()> {
        if self.body.is_none() {
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

    /// End the object or the pull body with a chunk of length 0.
    pub async fn end_object(&mut self) -> Result<()> {
        if self.body.is_none() {
            return Err(protocol("no object to end"));
        }
        self.inner.write_all(&0u32.to_be_bytes()).await?;
        self.body = None;
        Ok(())
    }

    /// Abandon an object of the push: write the marker [`ABANDON`] and then
    /// the `Abort` frame. Outside an object, a pull body included, the call
    /// is the error `protocol`.
    pub async fn abandon_object(&mut self) -> Result<()> {
        if self.body != Some(BodyKind::Object) {
            return Err(protocol("no object to abandon"));
        }
        self.inner.write_all(&ABANDON.to_be_bytes()).await?;
        self.body = None;
        self.write_message(&Message::Abort).await
    }

    /// Abandon a body of the pull: write the marker [`ABANDON`] and then the
    /// `Error` frame of `error`. The caller gives the code, `internal` for a
    /// read of the file that failed. Outside a pull body, an object of the
    /// push included, the call is the error `protocol`. An `error` that does
    /// not encode, or whose frame is over the limit, is an error, and nothing
    /// is written.
    pub async fn abandon_body(&mut self, error: &ErrorMessage) -> Result<()> {
        if self.body != Some(BodyKind::Pull) {
            return Err(protocol("no pull body to abandon"));
        }
        let frame = encode_frame(&Message::Error(error.clone()), self.limit)?;
        self.inner.write_all(&ABANDON.to_be_bytes()).await?;
        self.body = None;
        self.inner.write_all(&frame).await?;
        Ok(())
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
