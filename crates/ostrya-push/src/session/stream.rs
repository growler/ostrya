//! One stream transport of a session: the frame codec over a pair of byte
//! streams, and the object stream the session writes to it.

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

/// The buffer size of the output of the stream: 64 KiB, the default capacity
/// of a Linux pipe, so a full buffer goes into an empty pipe in one write. A
/// full chunk of `CHUNK_PAYLOAD` bytes and its 4-byte length fill the buffer
/// exactly. Each chunk is shorter than the buffer, so it goes through the
/// buffer, and a chunk length is never the only content of a write to the
/// transport.
const WRITE_BUFFER: usize = 64 * 1024;

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

    /// Wait at most `limit` for a pending message after a failed write.
    pub(super) fn set_pending_limit(&mut self, limit: Duration) {
        self.pending_limit = Some(limit);
    }

    /// Set the frame and chunk limit of the writer to the `max-frame` of the
    /// server.
    pub(super) fn set_write_limit(&mut self, limit: u32) {
        self.writer.frames().set_limit(limit);
    }

    /// Write `msg` and flush, with no mapping of a failure.
    pub(super) async fn write_raw(&mut self, msg: &Message) -> Result<()> {
        let frames = self.writer.frames();
        frames.write_message(msg).await?;
        frames.flush().await
    }

    /// Write `msg` and flush. A failed write gives the `Error` the server
    /// sent before it closed, where it sent one.
    pub(super) async fn request(&mut self, msg: &Message) -> Result<()> {
        match self.write_raw(msg).await {
            Ok(()) => Ok(()),
            Err(e) => Err(self.after_write_error(e).await),
        }
    }

    /// The `Error` the server sent, when a write failed with an I/O error
    /// because the server closed the stream after it. Otherwise `e`.
    pub(super) async fn after_write_error(&mut self, e: Error) -> Error {
        match self.pending_message(&e).await {
            Some(Message::Error(sent)) => sent.into(),
            _ => e,
        }
    }

    /// Read one message after the write failure `e`, when `e` is an I/O
    /// error. A read that fails gives `None`, and so does a read that takes
    /// longer than the pending limit of the stream.
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

    /// Read the next message. An end of file is an [`Error::Io`] of kind
    /// `UnexpectedEof`.
    pub(super) async fn next(&mut self) -> Result<Message> {
        self.reader
            .read_message()
            .await?
            .ok_or_else(|| Error::Io(io::ErrorKind::UnexpectedEof.into()))
    }

    /// Read the next message with no mapping.
    pub(super) async fn read_raw(&mut self) -> Result<Option<Message>> {
        self.reader.read_message().await
    }

    /// Close the writer.
    pub(super) async fn close(self) -> Result<()> {
        self.writer.close().await
    }

    /// Send the objects of `up` in one object stream, and read the
    /// `ObjectsReply`. A call with nothing to send writes nothing.
    pub(super) async fn upload(&mut self, up: &Upload<'_>) -> Result<()> {
        let mut started = false;
        let mut pass = Pass::default();
        match self.writer.write_items(up, &mut pass, &mut started).await {
            Ok(()) => {}
            Err(Stop::Wire(e)) => return Err(self.after_write_error(e).await),
            Err(Stop::Abandon { error, in_object }) => {
                self.writer.abandon(in_object).await;
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
