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

/// The kind of a body. It sets the message that must follow the abandon
/// marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyKind {
    /// An object of the push, after an `ObjectHeader`. An `Abort` message
    /// follows the marker.
    Object,
    /// A body of the pull, after a `GetReply` whose `found` is `true`. An
    /// `Error` message follows the marker.
    Pull,
}

impl BodyKind {
    /// Returns the kind of body that follows `msg`, or `None` if no body
    /// follows.
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
    /// Inside a body of `kind`. `remaining` is the number of bytes of the
    /// current chunk that are not read. If it is 0, the next read starts
    /// with the chunk length, and `prefix` holds the `got` bytes of it that
    /// are read.
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
pub(crate) enum Step {
    Data(usize),
    End,
    /// The abandon marker in a body of this kind. The message that must
    /// follow the marker is not read.
    Marker(BodyKind),
}

/// The result of one [`FrameReader::read_object_data`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectRead {
    /// The number of body bytes at the start of the buffer.
    Data(usize),
    /// The end of the body, after which frames follow.
    End,
    /// An object of the push that the sender abandoned.
    ///
    /// The call read the `Abort` message that must follow the marker. If the
    /// sender abandons a body of the pull, the call returns the [`Error`]
    /// variant of the code in the `Error` message.
    Abandoned,
}

/// A reader of frames, object chunks, and pull bodies on a stream.
///
/// A frame takes three reads and a chunk takes two, so a caller wraps a raw
/// socket or pipe in a buffered reader. A buffered reader that passes a large
/// read through to the stream does not copy the object bytes a second time.
///
/// The futures of the reader are not cancel-safe. A call that is dropped
/// before it completes can leave part of a frame or of a chunk length read.
/// The next call then reads from the middle of it. After a canceled call,
/// the caller must drop the reader.
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    limit: u32,
    state: ReadState,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// Creates a reader with the limit [`MIN_FRAME_LIMIT`].
    pub fn new(inner: R) -> Self {
        FrameReader {
            inner,
            limit: MIN_FRAME_LIMIT,
            state: ReadState::Frames,
        }
    }

    /// Sets the frame and chunk limit of the reader.
    ///
    /// The value is clamped to [`MIN_FRAME_LIMIT`]`..=`[`MAX_FRAME_LIMIT`].
    /// A client sets a read limit of its own here, for example
    /// [`MAX_FRAME`], and gives the `max-frame` of the server to its
    /// [`FrameWriter`] alone. The [frame rules](crate::proto#frames) give
    /// the reason.
    ///
    /// [`MAX_FRAME`]: super::MAX_FRAME
    pub fn set_limit(&mut self, limit: u32) {
        self.limit = clamp_limit(limit);
    }

    /// Returns the frame and chunk limit.
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Reads the next message.
    ///
    /// `Ok(None)` is an end of file at a frame boundary. After an
    /// `ObjectHeader`, and after a `GetReply` whose `found` is `true`, the
    /// caller must read the body to its end before the next message. It reads
    /// the body with [`read_object_data`](Self::read_object_data) or
    /// [`object_body`](Self::object_body).
    ///
    /// # Errors
    ///
    /// - [`Error::Protocol`] if the body of the previous message is not read to
    ///   its end.
    /// - [`Error::Protocol`] if the frame length is 0, if the kind byte is not
    ///   a known kind, or if the body does not decode.
    /// - [`Error::LimitExceeded`] if the frame length is more than the limit.
    /// - [`Error::Io`] of kind `UnexpectedEof` if the stream ends inside a
    ///   frame.
    /// - [`Error::Io`] if a read of the stream fails.
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

    /// Returns an [`ObjectBody`] that reads the current object or pull body.
    pub fn object_body(&mut self) -> ObjectBody<'_, R> {
        ObjectBody {
            reader: self,
            state: BodyState::Reading,
            error: None,
        }
    }

    /// Reads bytes of the current object or pull body into `buf`.
    ///
    /// A chunk longer than `buf` arrives over several calls, so `buf` bounds
    /// the memory. Inside a body, an empty `buf` reads nothing and gives
    /// `ObjectRead::Data(0)`.
    ///
    /// If the call meets the abandon marker, it reads the message that must
    /// follow the marker. In an object of the push, an `Abort` message gives
    /// [`ObjectRead::Abandoned`].
    ///
    /// # Errors
    ///
    /// - [`Error::Protocol`] if the reader is not inside a body.
    /// - [`Error::LimitExceeded`] if a chunk length is more than the limit.
    /// - In a body of the pull, the [`Error`] variant of the code in the
    ///   `Error` message after the marker, for example [`Error::Internal`].
    /// - [`Error::Protocol`] if a message of another kind follows the
    ///   marker.
    /// - [`Error::Io`] of kind `UnexpectedEof` if the stream ends inside a
    ///   chunk, or after the marker and before the next message.
    /// - [`Error::Io`] if a read of the stream fails.
    /// - The errors of [`read_message`](Self::read_message) for the message
    ///   after the marker.
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

    /// Reads the message that must follow the abandon marker in a body of
    /// `kind`. After an object, an `Abort` message gives `Ok`. After a pull
    /// body, an `Error` message gives the [`Error`] variant of its code.
    /// Another message gives [`Error::Protocol`].
    async fn read_after_marker(&mut self, kind: BodyKind) -> Result<()> {
        match (kind, self.read_message().await?) {
            (BodyKind::Object, Some(Message::Abort)) => Ok(()),
            (BodyKind::Pull, Some(Message::Error(e))) => Err(e.into()),
            (_, Some(other)) => {
                // An ObjectHeader or a GetReply whose `found` is `true` sets
                // the body state. This reset leaves the reader between frames.
                self.state = ReadState::Frames;
                Err(protocol(format!(
                    "{:?} after the abandon marker",
                    other.kind()
                )))
            }
            (_, None) => Err(eof()),
        }
    }

    /// Reads the next step of the object stream into `buf`. The state keeps
    /// a partial chunk length, so a pending read loses no byte.
    pub(crate) fn poll_step(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<Step>> {
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

    /// Returns a reference to the underlying stream.
    ///
    /// If the stream is a buffered reader, a caller can look at the bytes in
    /// the buffer with no read. An example is a check for a whole frame in
    /// the buffer.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Returns the underlying stream.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyState {
    Reading,
    Finished,
    Abandoned(BodyKind),
    /// A read failed with an error of this kind. Every later read fails with
    /// the same kind.
    Failed(io::ErrorKind),
}

/// One object or pull body of a [`FrameReader`], read as an `AsyncRead`.
///
/// A read returns body bytes until the chunk of length 0, and then end of
/// file. A read that meets the abandon marker, a codec error, or an error of
/// the stream fails with an `io::Error`, and every later read fails too.
///
/// - After the abandon marker, [`is_abandoned`](Self::is_abandoned) returns
///   `true`, and [`finish_abandon`](Self::finish_abandon) reads the message
///   that must follow the marker.
/// - After another failure, [`take_error`](Self::take_error) returns the
///   [`Error`] of the reader. The `io::Error` of the read does not keep the
///   variant or its wire code.
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
    /// Returns `true` if the body ended with the chunk of length 0.
    pub fn is_finished(&self) -> bool {
        self.state == BodyState::Finished
    }

    /// Returns `true` if the sender abandoned the body with the abandon
    /// marker.
    pub fn is_abandoned(&self) -> bool {
        matches!(self.state, BodyState::Abandoned(_))
    }

    /// Takes the [`Error`] of the read that failed.
    ///
    /// The error is a codec error, for example [`Error::LimitExceeded`] for a
    /// chunk over the limit, or an [`Error::Io`] from the stream. The call
    /// returns `None` if no read failed, if the abandon marker is the only
    /// failure, or if an earlier call took the error.
    pub fn take_error(&mut self) -> Option<Error> {
        self.error.take()
    }

    /// Reads the message that must follow the abandon marker.
    ///
    /// In an object of the push, an `Abort` message gives `Ok`. In a body of
    /// the pull, an `Error` message gives the [`Error`] variant of its code.
    ///
    /// # Errors
    ///
    /// - [`Error::Protocol`] if no read met the abandon marker.
    /// - In a body of the pull, the [`Error`] variant of the code in the
    ///   `Error` message, for example [`Error::Internal`].
    /// - [`Error::Protocol`] if a message of another kind follows the
    ///   marker.
    /// - [`Error::Io`] of kind `UnexpectedEof` if the stream ends before the
    ///   message.
    /// - The errors of [`FrameReader::read_message`] for the message.
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
        // The loop fills `buf` across chunk boundaries while the stream has
        // bytes ready, so small chunks do not make small reads. If `buf` holds
        // bytes at a pending read, the end, the marker, or an error, the read
        // returns those bytes. The next read reports the end, the marker, or
        // the error.
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

/// Returns the frame of `msg`: the length, the kind, and the body. A frame
/// over `limit` is [`Error::LimitExceeded`]. A caller that sends the frame as
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

/// A writer of frames, object chunks, and pull bodies on a stream.
///
/// The writer enters the body state when it writes an `ObjectHeader`, or a
/// `GetReply` whose `found` is `true`.
///
/// - [`write_object_data`](Self::write_object_data) and
///   [`end_object`](Self::end_object) serve both body kinds.
/// - [`abandon_object`](Self::abandon_object) abandons an object of the
///   push.
/// - [`abandon_body`](Self::abandon_body) abandons a body of the pull.
///
/// The writer holds no object bytes and does not flush. The caller flushes
/// with [`flush`](Self::flush), or wraps the stream in a buffered writer.
/// A frame is one write, and a chunk is two: the length and the data. A
/// caller wraps a raw socket or pipe in a buffered writer.
///
/// The futures of the writer are not cancel-safe. A call that is dropped
/// before it completes can leave part of a frame or a chunk written. After a
/// canceled call, the caller must drop the writer.
#[derive(Debug)]
pub struct FrameWriter<W> {
    inner: W,
    limit: u32,
    body: Option<BodyKind>,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    /// Creates a writer with the limit [`MIN_FRAME_LIMIT`].
    pub fn new(inner: W) -> Self {
        FrameWriter {
            inner,
            limit: MIN_FRAME_LIMIT,
            body: None,
        }
    }

    /// Sets the frame and chunk limit to the `max-frame` that the peer
    /// announced.
    ///
    /// The value is clamped to [`MIN_FRAME_LIMIT`]`..=`[`MAX_FRAME_LIMIT`].
    /// [`HelloReply::max_frame`](super::HelloReply::max_frame) holds the
    /// announced value, and the [frame rules](crate::proto#frames) apply
    /// the limit.
    pub fn set_limit(&mut self, limit: u32) {
        self.limit = clamp_limit(limit);
    }

    /// Writes one message as a frame.
    ///
    /// After an `ObjectHeader`, and after a `GetReply` whose `found` is
    /// `true`, the writer is in the body state.
    ///
    /// # Errors
    ///
    /// If the call returns [`Error::Protocol`] or [`Error::LimitExceeded`],
    /// it writes nothing.
    ///
    /// - [`Error::Protocol`] if the writer is inside an object or a pull
    ///   body.
    /// - [`Error::Protocol`] if `msg` holds a value that its kind cannot
    ///   carry, for example a `GetReply` whose `found` is `false` with a
    ///   length.
    /// - [`Error::LimitExceeded`] if the frame is over the limit.
    /// - [`Error::Io`] if a write to the stream fails.
    pub async fn write_message(&mut self, msg: &Message) -> Result<()> {
        if self.body.is_some() {
            return Err(protocol("message inside an object"));
        }
        // An object stream writes one `ObjectHeader` for each object, and a
        // pull session one `GetReply` for each path, so the writer builds
        // their frames on the stack. Each of these frames is shorter than
        // `MIN_FRAME_LIMIT`.
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

    /// Writes `frame`, which [`encode_frame`] built for a message that opens
    /// no body. If the writer is inside an object or a pull body, the call
    /// returns [`Error::Protocol`].
    pub(crate) async fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        if self.body.is_some() {
            return Err(protocol("message inside an object"));
        }
        self.inner.write_all(frame).await?;
        Ok(())
    }

    /// Writes bytes of the current object or pull body as chunks.
    ///
    /// Each chunk holds at most the limit. Inside a body, an empty `data`
    /// writes nothing. Each call with data writes one chunk or more, and each
    /// chunk costs 4 bytes of framing and one read call on the peer. A caller
    /// gives the object bytes in pieces of 64 KiB or more.
    ///
    /// # Errors
    ///
    /// - [`Error::Protocol`] if the writer is not inside a body.
    /// - [`Error::Io`] if a write to the stream fails.
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

    /// Ends the current object or pull body with a chunk of length 0.
    ///
    /// # Errors
    ///
    /// - [`Error::Protocol`] if the writer is not inside a body.
    /// - [`Error::Io`] if a write to the stream fails.
    pub async fn end_object(&mut self) -> Result<()> {
        if self.body.is_none() {
            return Err(protocol("no object to end"));
        }
        self.inner.write_all(&0u32.to_be_bytes()).await?;
        self.body = None;
        Ok(())
    }

    /// Abandons the current object of the push.
    ///
    /// The call writes the marker [`ABANDON`] and then an `Abort` message.
    ///
    /// # Errors
    ///
    /// - [`Error::Protocol`] if the writer is not inside an object of the
    ///   push, for example if it is inside a body of the pull.
    /// - [`Error::Io`] if a write to the stream fails.
    pub async fn abandon_object(&mut self) -> Result<()> {
        if self.body != Some(BodyKind::Object) {
            return Err(protocol("no object to abandon"));
        }
        self.inner.write_all(&ABANDON.to_be_bytes()).await?;
        self.body = None;
        self.write_message(&Message::Abort).await
    }

    /// Abandons the current body of the pull.
    ///
    /// The call writes the marker [`ABANDON`] and then `error` as an `Error`
    /// message. The caller gives the code, for example `internal` for a
    /// failed read of the file.
    ///
    /// # Errors
    ///
    /// - [`Error::Protocol`] if the writer is not inside a body of the pull,
    ///   for example if it is inside an object of the push.
    /// - [`Error::Protocol`] if `error` does not encode. The call writes
    ///   nothing.
    /// - [`Error::LimitExceeded`] if the frame of `error` is over the limit.
    ///   The call writes nothing.
    /// - [`Error::Io`] if a write to the stream fails.
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

    /// Flushes the underlying stream.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the flush of the stream fails.
    pub async fn flush(&mut self) -> Result<()> {
        self.inner.flush().await?;
        Ok(())
    }

    /// Returns the underlying stream.
    pub fn into_inner(self) -> W {
        self.inner
    }
}
