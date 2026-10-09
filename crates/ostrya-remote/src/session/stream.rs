//! The stream transport of a session: the frame codec over a pair of byte
//! streams, and the object stream that the session writes to it.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::{BufReader, BufWriter};

use super::progress::Counters;
use super::writer::{Counting, ObjectWriter, Pass, Stop, Upload};
use crate::error::{Error, Result};
use crate::proto::{FrameReader, Message, protocol};

/// The buffer size of the input of the stream.
const STREAM_BUFFER: usize = 64 * 1024;

/// The buffer size of the output of the stream: 64 KiB.
///
/// 64 KiB is the default capacity of a Linux pipe, so a full buffer goes into
/// an empty pipe in one write. A full chunk of `CHUNK_PAYLOAD` bytes and its
/// 4-byte length fill the buffer exactly. Each chunk is shorter than the
/// buffer, so the chunk goes through the buffer. Because of this, a write to
/// the transport never holds a chunk length alone.
pub(super) const WRITE_BUFFER: usize = 64 * 1024;

pub(crate) type Input = Box<dyn AsyncRead + Unpin + Send>;
pub(crate) type Output = Box<dyn AsyncWrite + Unpin + Send>;

/// The frame codec of a session over one pair of byte streams.
pub(super) struct Stream {
    reader: FrameReader<BufReader<Input>>,
    writer: ObjectWriter<BufWriter<Counting<Output>>>,
    /// The longest wait for a pending message after a failed write. `None`
    /// waits with no limit.
    pending_limit: Option<Duration>,
}

impl Stream {
    pub(super) fn new(input: Input, output: Output, counters: Arc<Counters>) -> Stream {
        let counting = Counting::new(output, Arc::clone(&counters));
        Stream {
            reader: FrameReader::new(BufReader::with_capacity(STREAM_BUFFER, input)),
            writer: ObjectWriter::new(BufWriter::with_capacity(WRITE_BUFFER, counting), counters),
            pending_limit: None,
        }
    }

    /// Sets the longest wait for a pending message after a failed write to
    /// `limit`.
    pub(super) fn set_pending_limit(&mut self, limit: Duration) {
        self.pending_limit = Some(limit);
    }

    /// Sets the frame limit and the chunk limit of the writer to `limit`, the
    /// `max-frame` value of the server.
    pub(super) fn set_write_limit(&mut self, limit: u32) {
        self.writer.frames().set_limit(limit);
    }

    /// Writes `msg` and flushes the writer. The call returns a failure
    /// unchanged.
    pub(super) async fn write_raw(&mut self, msg: &Message) -> Result<()> {
        let frames = self.writer.frames();
        frames.write_message(msg).await?;
        frames.flush().await
    }

    /// Writes `msg` and flushes the writer.
    ///
    /// If the write fails and the server sent an `Error` message before it
    /// closed the stream, the call returns the [`Error`] variant of its code.
    /// Otherwise the call returns the error of the write.
    pub(super) async fn request(&mut self, msg: &Message) -> Result<()> {
        match self.write_raw(msg).await {
            Ok(()) => Ok(()),
            Err(e) => Err(self.after_write_error(e).await),
        }
    }

    /// Returns the error that the server sent before it closed the stream, or
    /// `e`.
    ///
    /// The call reads a pending message only if `e` is an [`Error::Io`]. If
    /// that message is an `Error` message, the call returns the [`Error`]
    /// variant of its code. Otherwise it returns `e`.
    pub(super) async fn after_write_error(&mut self, e: Error) -> Error {
        match self.pending_message(&e).await {
            Some(Message::Error(sent)) => sent.into(),
            _ => e,
        }
    }

    /// Reads one message after the write failure `e`.
    ///
    /// The call returns `None` in four cases:
    ///
    /// - `e` is not an [`Error::Io`], so the call reads nothing.
    /// - The read fails.
    /// - The stream ends.
    /// - The read takes longer than the pending limit of the stream.
    pub(super) async fn pending_message(&mut self, e: &Error) -> Option<Message> {
        if !matches!(e, Error::Io(_)) {
            return None;
        }
        let read = async { self.reader.read_message().await.ok().flatten() };
        match self.pending_limit {
            None => read.await,
            Some(limit) => {
                let timeout = async {
                    ostrya_rt::Timer::after(limit).await;
                    None
                };
                futures_lite::future::or(read, timeout).await
            }
        }
    }

    /// Reads the next message. An end of file is an [`Error::Io`] of the kind
    /// `UnexpectedEof`.
    pub(super) async fn next(&mut self) -> Result<Message> {
        self.reader
            .read_message()
            .await?
            .ok_or_else(|| Error::Io(io::ErrorKind::UnexpectedEof.into()))
    }

    /// Reads the next message. An end of file is `None`.
    pub(super) async fn read_raw(&mut self) -> Result<Option<Message>> {
        self.reader.read_message().await
    }

    /// Closes the writer.
    pub(super) async fn close(self) -> Result<()> {
        self.writer.close().await
    }

    /// Sends the objects of `up` in one object stream and reads the
    /// `ObjectsReply`.
    ///
    /// If there is nothing to send, the call writes nothing. If the writer
    /// stops, the call abandons the stream and returns the error of the stop.
    /// A reply other than `ObjectsReply` or an `Error` message is
    /// [`Error::Protocol`].
    pub(super) async fn upload(&mut self, up: &Upload<'_>) -> Result<()> {
        let mut started = false;
        let mut pass = Pass::default();
        match self.writer.write_items(up, &mut pass, &mut started).await {
            Ok(()) => {}
            Err(Stop::Wire(e)) => return Err(self.after_write_error(e).await),
            Err(Stop::Abandon {
                error, in_object, ..
            }) => {
                // The call returns the error of the stop, so it ignores a
                // failure of these writes.
                let _ = self.writer.abandon(in_object).await;
                let _ = self.writer.frames().flush().await;
                return Err(error);
            }
        }
        if !started {
            return Ok(());
        }
        self.request(&Message::ObjectsEnd).await?;
        match self.next().await? {
            Message::ObjectsReply(_) => Ok(()),
            Message::Error(e) => Err(e.into()),
            other => Err(protocol(format!(
                "{:?} in reply to ObjectsEnd",
                other.kind()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::writer::CHUNK_PAYLOAD;
    use super::WRITE_BUFFER;

    /// A full chunk and its 4-byte length fill the output buffer, and the
    /// buffer is 64 KiB.
    #[test]
    fn a_full_chunk_and_its_length_fill_the_output_buffer() {
        assert_eq!(WRITE_BUFFER, 65_536);
        assert_eq!(CHUNK_PAYLOAD, 65_532);
        assert_eq!(CHUNK_PAYLOAD + 4, WRITE_BUFFER);
    }
}
