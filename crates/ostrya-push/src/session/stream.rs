//! One stream transport of a session: the frame codec over a pair of byte
//! streams, and the object stream the session writes to it.

use std::collections::HashSet;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use ostrya_core::filehdr::frame;
use ostrya_core::{Checksum, DeflateReader, MAX_METADATA_SIZE, ObjectName, ObjectType};
use ostrya_gvariant::Type;

use super::progress::Counters;
use super::{ObjectData, ObjectReader, ObjectSource, invalid};
use crate::error::{Error, Result};
use crate::proto::{Encoding, FrameReader, FrameWriter, Message, ObjectHeader, protocol};

/// The buffer size of the input of the stream, and of the object bytes the
/// session copies from a source. The compressor gives chunks of at most this
/// size too.
const STREAM_BUFFER: usize = 64 * 1024;

/// The buffer size of the output of the stream: the longest chunk and the
/// length of the next one. The buffer then holds a full chunk and the length
/// that follows it, so no write to the transport carries a chunk length
/// alone.
const WRITE_BUFFER: usize = STREAM_BUFFER + 4;

pub(crate) type Input = Box<dyn AsyncRead + Unpin + Send>;
pub(crate) type Output = Box<dyn AsyncWrite + Unpin + Send>;

/// The writer under the buffer of the stream. It counts each byte the stream
/// takes as a byte sent.
struct Counting {
    inner: Output,
    counters: Arc<Counters>,
}

impl AsyncWrite for Counting {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let n = std::task::ready!(Pin::new(&mut me.inner).poll_write(cx, buf))?;
        me.counters.wire(n as u64);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

/// The objects of one `send` call, and what the session knows to send them.
pub(super) struct Upload<'a> {
    pub source: &'a dyn ObjectSource,
    pub names: &'a [ObjectName],
    pub commits: &'a [Checksum],
    /// The level a content object is deflated at, or `None` to send it raw.
    pub level: Option<u8>,
    /// Whether the server lists the encoding `deflate`.
    pub deflate_ok: bool,
    /// The commits whose detached metadata the session has sent.
    pub sent_meta: &'a Mutex<HashSet<Checksum>>,
}

/// Why an object stream stopped.
enum Stop {
    /// A write to the stream failed.
    Wire(Error),
    /// The source failed, or gave data the session cannot send. The session
    /// ends the stream with `Abort`, after the abandon marker when an object
    /// is open.
    Abandon { error: Error, in_object: bool },
}

impl From<Error> for Stop {
    fn from(e: Error) -> Stop {
        Stop::Wire(e)
    }
}

fn refuse(error: Error) -> Stop {
    Stop::Abandon {
        error,
        in_object: false,
    }
}

/// The error of a source call. An error that is already a source error is
/// kept as it is.
fn source_error(e: Error) -> Error {
    match e {
        Error::Source(_) => e,
        other => Error::Source(Box::new(other)),
    }
}

fn read_failed(e: io::Error) -> Stop {
    Stop::Abandon {
        error: Error::Source(Box::new(e)),
        in_object: true,
    }
}

/// The object bytes after the prefix the session builds.
enum Body {
    /// No bytes: a symlink.
    None,
    /// Bytes copied as the reader gives them.
    Copy(Box<dyn ObjectReader>),
    /// Bytes the session deflates at `level`.
    Deflate(Box<dyn ObjectReader>, u8),
}

/// What the session sends for one object.
struct Plan {
    encoding: Encoding,
    prefix: Vec<u8>,
    body: Body,
}

/// Check the data a source gave for `name`, and build what the session sends
/// for it. `level` is the level of the session compressor, when it deflates.
fn plan(name: &ObjectName, data: ObjectData, level: Option<u8>, deflate_ok: bool) -> Result<Plan> {
    let is_file = name.ty == ObjectType::File;
    match data {
        ObjectData::Encoded { encoding, reader } => {
            if encoding == Encoding::Deflate && !(is_file && deflate_ok) {
                return Err(invalid(format!(
                    "object {} of type {:?} cannot be sent deflated to this server",
                    name.checksum, name.ty
                )));
            }
            Ok(Plan {
                encoding,
                prefix: Vec::new(),
                body: Body::Copy(reader),
            })
        }
        ObjectData::Content {
            header,
            size,
            payload,
        } => {
            if !is_file {
                return Err(invalid(format!(
                    "object {} of type {:?} is not a content object",
                    name.checksum, name.ty
                )));
            }
            let body = match (header.is_symlink(), payload) {
                (true, None) if size == 0 => None,
                (false, Some(reader)) => Some(reader),
                (true, _) => {
                    return Err(invalid(format!(
                        "content object {}: a symlink has no payload",
                        name.checksum
                    )));
                }
                (false, None) => {
                    return Err(invalid(format!(
                        "content object {}: a regular file needs a payload",
                        name.checksum
                    )));
                }
            };
            let bad_header =
                |e: ostrya_core::Error| invalid(format!("content object {}: {e}", name.checksum));
            match level {
                Some(level) => Ok(Plan {
                    encoding: Encoding::Deflate,
                    prefix: frame(&header.serialize_archive(size).map_err(bad_header)?)
                        .map_err(bad_header)?,
                    body: body.map_or(Body::None, |r| Body::Deflate(r, level)),
                }),
                None => Ok(Plan {
                    encoding: Encoding::Raw,
                    prefix: frame(&header.serialize().map_err(bad_header)?).map_err(bad_header)?,
                    body: body.map_or(Body::None, Body::Copy),
                }),
            }
        }
    }
}

/// The frame codec of a session over one pair of byte streams.
pub(super) struct Stream {
    reader: FrameReader<BufReader<Input>>,
    writer: FrameWriter<BufWriter<Counting>>,
    /// The compressor of the objects this stream deflates. It is made at the
    /// first such object and reset for each one after it.
    deflate: Option<DeflateReader<Box<dyn ObjectReader>>>,
    /// The buffer object bytes are copied through.
    buf: Vec<u8>,
    counters: Arc<Counters>,
    /// The longest wait for a pending message after a failed write. `None`
    /// waits with no limit.
    pending_limit: Option<Duration>,
}

impl Stream {
    pub(super) fn new(input: Input, output: Output, counters: Arc<Counters>) -> Stream {
        let counting = Counting {
            inner: output,
            counters: Arc::clone(&counters),
        };
        Stream {
            reader: FrameReader::new(BufReader::with_capacity(STREAM_BUFFER, input)),
            writer: FrameWriter::new(BufWriter::with_capacity(WRITE_BUFFER, counting)),
            deflate: None,
            buf: Vec::new(),
            counters,
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
        self.writer.set_limit(limit);
    }

    /// Write `msg` and flush, with no mapping of a failure.
    pub(super) async fn write_raw(&mut self, msg: &Message) -> Result<()> {
        self.writer.write_message(msg).await?;
        self.writer.flush().await
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
        self.writer.into_inner().close().await?;
        Ok(())
    }

    /// Send the objects of `up` in one object stream, and read the
    /// `ObjectsReply`. A call with nothing to send writes nothing.
    pub(super) async fn upload(&mut self, up: &Upload<'_>) -> Result<()> {
        let mut started = false;
        match self.upload_objects(up, &mut started).await {
            Ok(()) => {}
            Err(Stop::Wire(e)) => return Err(self.after_write_error(e).await),
            Err(Stop::Abandon { error, in_object }) => {
                let _ = if in_object {
                    self.writer.abandon_object().await
                } else {
                    self.writer.write_message(&Message::Abort).await
                };
                let _ = self.writer.flush().await;
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

    async fn upload_objects(
        &mut self,
        up: &Upload<'_>,
        started: &mut bool,
    ) -> std::result::Result<(), Stop> {
        for name in up.names {
            let encoding = match (name.ty, up.level) {
                (ObjectType::File, Some(_)) => Encoding::Deflate,
                _ => Encoding::Raw,
            };
            let data = up
                .source
                .open(name, encoding)
                .await
                .map_err(|e| refuse(source_error(e)))?;
            let level = up.level.filter(|_| name.ty == ObjectType::File);
            let plan = plan(name, data, level, up.deflate_ok).map_err(refuse)?;
            *started = true;
            self.write_object(*name, plan).await?;
            self.counters.object_sent();
        }
        for commit in up.commits {
            if sent(up.sent_meta, commit) {
                continue;
            }
            let dict = up
                .source
                .detached_metadata(commit)
                .await
                .map_err(|e| refuse(source_error(e)))?;
            let Some(dict) = dict else {
                continue;
            };
            let a_sv = Type::parse("a{sv}").expect("valid signature");
            let bytes = ostrya_gvariant::to_bytes(&a_sv, &dict).map_err(|e| {
                refuse(invalid(format!(
                    "the detached metadata of commit {commit}: {e}"
                )))
            })?;
            if bytes.len() as u64 > MAX_METADATA_SIZE {
                return Err(refuse(invalid(format!(
                    "the detached metadata of commit {commit} is {} bytes, over the limit \
                     {MAX_METADATA_SIZE}",
                    bytes.len()
                ))));
            }
            up.sent_meta
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(*commit);
            *started = true;
            let name = ObjectName::new(*commit, ObjectType::CommitMeta);
            let plan = Plan {
                encoding: Encoding::Raw,
                prefix: bytes,
                body: Body::None,
            };
            self.write_object(name, plan).await?;
        }
        Ok(())
    }

    /// Write one object: its header, its bytes as chunks, and the end chunk.
    async fn write_object(
        &mut self,
        name: ObjectName,
        plan: Plan,
    ) -> std::result::Result<(), Stop> {
        let header = ObjectHeader {
            name,
            encoding: plan.encoding,
        };
        self.writer
            .write_message(&Message::ObjectHeader(header))
            .await?;
        self.write_data(&plan.prefix).await?;
        match plan.body {
            Body::None => {}
            Body::Copy(mut reader) => {
                if self.buf.is_empty() {
                    self.buf = vec![0u8; STREAM_BUFFER];
                }
                loop {
                    let n = reader.read(&mut self.buf).await.map_err(read_failed)?;
                    if n == 0 {
                        break;
                    }
                    let Stream {
                        writer,
                        buf,
                        counters,
                        ..
                    } = self;
                    writer.write_object_data(&buf[..n]).await?;
                    counters.payload(n as u64);
                }
            }
            Body::Deflate(reader, level) => {
                let deflate = match &mut self.deflate {
                    Some(deflate) => {
                        deflate.reset(reader, level);
                        deflate
                    }
                    none => none.insert(DeflateReader::new(reader, level)),
                };
                loop {
                    let chunk = deflate.fill_buf().await.map_err(read_failed)?;
                    if chunk.is_empty() {
                        break;
                    }
                    let n = chunk.len();
                    self.writer.write_object_data(chunk).await?;
                    self.counters.payload(n as u64);
                    deflate.consume(n);
                }
                // Release the source of the object.
                *deflate.get_mut() = Box::new(futures_lite::io::empty());
            }
        }
        self.writer.end_object().await?;
        Ok(())
    }

    async fn write_data(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.writer.write_object_data(data).await?;
        self.counters.payload(data.len() as u64);
        Ok(())
    }
}

fn sent(set: &Mutex<HashSet<Checksum>>, commit: &Checksum) -> bool {
    set.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(commit)
}
