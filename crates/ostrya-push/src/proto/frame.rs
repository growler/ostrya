//! The frame codec and the chunked object stream.

use std::io;

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
    Object { remaining: u32 },
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
            self.state = ReadState::Object { remaining: 0 };
        }
        Ok(Some(msg))
    }

    /// Read object bytes into `buf`. A chunk longer than `buf` arrives over
    /// several calls, so `buf` bounds the memory. An empty `buf` reads
    /// nothing and returns `Data(0)`. Outside an object the call is the error
    /// `protocol`.
    pub async fn read_object_data(&mut self, buf: &mut [u8]) -> Result<ObjectRead> {
        let ReadState::Object { remaining } = self.state else {
            return Err(protocol("no object to read"));
        };
        if buf.is_empty() {
            return Ok(ObjectRead::Data(0));
        }
        let remaining = if remaining == 0 {
            let mut prefix = [0u8; 4];
            self.inner.read_exact(&mut prefix).await?;
            match u32::from_be_bytes(prefix) {
                0 => {
                    self.state = ReadState::Frames;
                    return Ok(ObjectRead::End);
                }
                ABANDON => {
                    self.state = ReadState::Frames;
                    return match self.read_message().await? {
                        Some(Message::Abort) => Ok(ObjectRead::Abandoned),
                        Some(other) => {
                            // An ObjectHeader sets the object state. The
                            // error leaves the reader between frames.
                            self.state = ReadState::Frames;
                            Err(protocol(format!(
                                "{:?} after the abandon marker",
                                other.kind()
                            )))
                        }
                        None => Err(eof()),
                    };
                }
                len if len > self.limit => {
                    return Err(limit_exceeded("chunk", len, self.limit));
                }
                len => len,
            }
        } else {
            remaining
        };
        let want = buf.len().min(remaining as usize);
        let n = self.inner.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(eof());
        }
        self.state = ReadState::Object {
            remaining: remaining - n as u32,
        };
        Ok(ObjectRead::Data(n))
    }

    /// The underlying stream.
    pub fn into_inner(self) -> R {
        self.inner
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
