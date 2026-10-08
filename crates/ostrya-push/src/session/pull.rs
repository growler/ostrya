//! The client session of a pull: the pipeline of `Get` frames and the bodies
//! of the replies.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker, ready};
use std::time::Duration;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::{AsyncWriteExt, BufReader};
use ostrya_fetch::Priority;
use ostrya_fetch::gate::{Gate, Permit};

use super::stream::{Input, Output};
use crate::error::{Error, Result};
use crate::proto::{
    FrameReader, FrameWriter, GetReply, MIN_FRAME_LIMIT, Message, PULL_PROTOCOL_VERSION, PullHello,
    Step, encode_frame, protocol,
};
use crate::transport::Transport;

/// The buffer size of the input of the session.
const STREAM_BUFFER: usize = 64 * 1024;

/// The most calls that hold a place at a time if the options give no number.
const DEFAULT_OUTSTANDING: usize = 8;

type Reader = FrameReader<BufReader<Input>>;
type ReadFuture = Pin<Box<dyn Future<Output = Result<Option<Message>>> + Send>>;

/// The options of a pull session.
#[derive(Debug, Clone, Default)]
pub struct PullSessionOptions {
    /// The `agent` value that the session sends in [`PullHello`].
    ///
    /// The default is `ostrya/<version>`, with the version of this crate.
    pub agent: Option<String>,
    /// The most [`get`](PullSession::get) calls that hold a place in the
    /// [pipeline](PullSession#pipeline) at a time.
    ///
    /// The default is 8. The session raises a value of 0 to 1.
    pub max_outstanding: Option<usize>,
}

/// A client session of a pull, which reads the files of a server repository.
///
/// [`connect`](PullSession::connect) opens a session over ssh, and
/// [`over_stream`](PullSession::over_stream) opens one over a pair of byte
/// streams. The session is `Send + Sync`. Concurrent
/// [`get`](PullSession::get) calls share the [pipeline](PullSession#pipeline),
/// and the replies come in the order of the `Get` frames.
///
/// If the session is dropped without [`finish`](PullSession::finish), it
/// sends nothing more and closes its output, so the server reads the end of
/// its input. This is also true while the caller holds a [`PullBody`]. If
/// [`connect`](PullSession::connect) opened the session, the drop then drops
/// the ssh client without a wait.
///
/// # Pipeline
///
/// The session opens with [`PullHello`] and asks for files by their path
/// with [`get`](PullSession::get). All requests share one stream as a
/// pipeline. A `get` takes its place in the pipeline and writes its `Get`
/// frame under one lock. Because of this lock, the frames go on the wire in
/// the order of the places.
///
/// A reply carries no request id. The reply of a call is the next reply
/// after the reply of the call before it.
///
/// At most [`max_outstanding`](PullSessionOptions::max_outstanding) calls
/// hold a place at a time. A call holds its place from the write of its
/// `Get` frame to the end of its reply.
///
/// The end of a reply is a [`GetReply`] whose `found` is `false`. For a reply
/// whose `found` is `true`, the end is the chunk that ends the body. When the
/// session reads that chunk, it moves to the next reply, also while the
/// caller still holds the [`PullBody`].
///
/// # Failures
///
/// Each of these events is a failure, and a failure ends the session:
///
/// - an `Error` message from the server
/// - a reply of a kind that the session does not expect
/// - a stated length that is more than the cap of the call, or that is
///   different from the sum of the chunks
/// - a body that is longer than the cap of the call
/// - a failed read or write
/// - a drop of a `get` future after the call took its place
/// - a drop of a [`PullBody`] before its end
/// - a [`finish`](PullSession::finish) while the body of a reply is not read
///   to its end
///
/// After a failure, each later call and each later read of a body fails. Its
/// error has the variant and the message of the first failure.
pub struct PullSession {
    inner: PullInner,
}

struct PullInner {
    shared: Arc<Shared>,
    /// The ssh client, for a session that [`PullSession::connect`] opened.
    transport: Option<Transport>,
}

/// The state that the session, its calls, and its bodies share.
struct Shared {
    /// The places of the pipeline.
    places: Arc<Gate>,
    /// The order of the writes: one call writes at a time, in the order in
    /// which the calls arrived.
    writing: Arc<Gate>,
    write: Mutex<WriteSide>,
    read: Mutex<ReadSide>,
    /// The longest wait for a pending message after a failed write. `None`
    /// waits with no limit.
    pending_limit: Option<Duration>,
}

struct WriteSide {
    /// The output, which a call takes while it writes its `Get` frame. It is
    /// `None` after a write failed, after the session failed, or after the
    /// session ended.
    writer: Option<Output>,
    /// The place of the next call.
    next: u64,
}

struct ReadSide {
    /// The reader. The call whose reply is next takes it while it reads the
    /// head of its reply. The body of a found file reads it here, under the
    /// lock. The end of the session can then drop it also while the caller
    /// holds the body.
    reader: Option<Box<Reader>>,
    /// The read of the frame that follows the abandon marker of a body. It
    /// holds the reader.
    abandoned: Option<ReadFuture>,
    /// The place whose reply is next.
    turn: u64,
    /// The waker of each call that waits for its reply, by place.
    waiting: BTreeMap<u64, Waker>,
    /// The first failure of the session.
    failure: Option<Error>,
}

/// Returns a copy of `e` for a later call of a session that failed with `e`.
///
/// The copy has the variant and the message of `e`, and an I/O error keeps
/// its kind. Each other variant with no wire code becomes `InvalidInput`.
fn repeat(e: &Error) -> Error {
    match e {
        Error::Io(io) => Error::Io(io::Error::new(io.kind(), io.to_string())),
        Error::Transport(msg) => Error::Transport(msg.clone()),
        Error::InvalidInput(msg) => Error::InvalidInput(msg.clone()),
        other if other.code().is_some() => other.to_message().into(),
        other => Error::InvalidInput(other.to_string()),
    }
}

/// Returns the `io::Error` that a body read gives for `e`.
///
/// It carries `e`. Its kind is the kind of an I/O error, and `Other` for
/// each other error.
fn body_error(e: Error) -> io::Error {
    let kind = match &e {
        Error::Io(io) => io.kind(),
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, e)
}

fn eof(what: &str) -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!("the session ended before {what}"),
    ))
}

/// Reads one message within `limit`. A failed read, an end of file, and a
/// read that takes longer than `limit` give `None`.
async fn read_pending(reader: &mut Reader, limit: Option<Duration>) -> Option<Message> {
    let read = async { reader.read_message().await.ok().flatten() };
    match limit {
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

impl Shared {
    fn lock_read(&self) -> MutexGuard<'_, ReadSide> {
        self.read.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_write(&self) -> MutexGuard<'_, WriteSide> {
        self.write.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the repeat of the first failure if the session failed.
    fn check(&self) -> Result<()> {
        match &self.lock_read().failure {
            Some(first) => Err(repeat(first)),
            None => Ok(()),
        }
    }

    /// Ends the session with `e`, and returns `e` or the repeat of an earlier
    /// failure.
    ///
    /// The first failure stays the failure of the session. The call drops the
    /// reader and the writer, and wakes every waiting call.
    ///
    /// The call records the failure before it takes the writer. A call that
    /// checks for a failure under the lock of the write side then cannot give
    /// the writer back to a failed session.
    fn fail(&self, e: Error) -> Error {
        let (out, reader, abandoned, waiting) = {
            let mut read = self.lock_read();
            let out = match &read.failure {
                Some(first) => repeat(first),
                None => {
                    read.failure = Some(repeat(&e));
                    e
                }
            };
            (
                out,
                read.reader.take(),
                read.abandoned.take(),
                std::mem::take(&mut read.waiting),
            )
        };
        let writer = self.lock_write().writer.take();
        drop((reader, abandoned, writer));
        for waker in waiting.into_values() {
            waker.wake();
        }
        out
    }

    /// Takes the reader for the call at `place` when its reply is next.
    async fn wait_turn(&self, place: u64) -> Result<Box<Reader>> {
        poll_fn(|cx| {
            let mut read = self.lock_read();
            if let Some(first) = &read.failure {
                return Poll::Ready(Err(repeat(first)));
            }
            if read.turn == place
                && let Some(reader) = read.reader.take()
            {
                return Poll::Ready(Ok(reader));
            }
            match read.waiting.entry(place) {
                Entry::Occupied(mut stored) => {
                    if !stored.get().will_wake(cx.waker()) {
                        stored.insert(cx.waker().clone());
                    }
                }
                Entry::Vacant(slot) => {
                    slot.insert(cx.waker().clone());
                }
            }
            Poll::Pending
        })
        .await
    }

    /// Gives back the reader after the reply of `place` ended, and wakes the
    /// call whose reply is next.
    fn advance(&self, reader: Box<Reader>, place: u64) {
        let waker = {
            let mut read = self.lock_read();
            if read.failure.is_none() {
                read.reader = Some(reader);
            }
            read.advance(place)
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Gives back the reader for the body of the reply at the turn, which
    /// reads it in place. If the session failed, the call drops the reader
    /// and returns the repeat of the first failure.
    fn lend(&self, reader: Box<Reader>) -> Result<()> {
        let mut read = self.lock_read();
        match &read.failure {
            Some(first) => Err(repeat(first)),
            None => {
                read.reader = Some(reader);
                Ok(())
            }
        }
    }
}

impl ReadSide {
    /// Moves the turn past the reply of `place`, and returns the waker of the
    /// call whose reply is next.
    fn advance(&mut self, place: u64) -> Option<Waker> {
        self.turn = place + 1;
        self.waiting.remove(&(place + 1))
    }
}

/// A call that took its place in the pipeline.
///
/// If it is dropped before the call read the head of its reply, it ends the
/// session. The reply of the call still arrives, and the codec is not
/// cancel-safe.
struct Placed<'a> {
    shared: &'a Shared,
    armed: bool,
}

impl Placed<'_> {
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for Placed<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.shared.fail(Error::InvalidInput(
                "a get call was dropped before its reply".into(),
            ));
        }
    }
}

/// The open of a session over a pair of byte streams, and its calls.
impl PullSession {
    /// Opens a session over a pair of byte streams.
    ///
    /// `input` carries the bytes from the server, and `output` the bytes to
    /// it. The session sends [`PullHello`] with [`PULL_PROTOCOL_VERSION`] and
    /// reads [`PullHelloReply`](crate::proto::PullHelloReply).
    ///
    /// The caller owns the liveness of the two streams. The session puts no
    /// time limit on a read. A peer that stays silent keeps a call waiting
    /// until the caller drops its future or closes the streams.
    ///
    /// # Errors
    ///
    /// - An `Error` message from the server, as the [`Error`] variant of its
    ///   code.
    /// - [`Error::VersionUnsupported`] if the reply states a version out of
    ///   `1..=PULL_PROTOCOL_VERSION`. The session then closes `output` and
    ///   sends no `Get`.
    /// - [`Error::Protocol`] if the reply is a message of another kind, or if
    ///   the codec refuses a frame of the reply.
    /// - [`Error::Protocol`] if `agent` holds a NUL byte.
    /// - [`Error::LimitExceeded`] if the `PullHello` frame or a frame of the
    ///   reply is longer than [`MIN_FRAME_LIMIT`].
    /// - [`Error::Io`] if a read or a write of a stream fails. If `input`
    ///   ends before the reply, the kind is `UnexpectedEof`.
    ///
    /// If the write of `PullHello` fails with [`Error::Io`], the call then
    /// reads the message that the server can have sent before it closed. If
    /// that message is an `Error` message, the call returns its variant.
    pub async fn over_stream<R, W>(input: R, output: W, opts: PullSessionOptions) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        PullSession::open(Box::new(input), Box::new(output), opts, None).await
    }

    /// Opens a session over `input` and `output`. `pending_limit` is the
    /// longest wait for a pending message after a failed write.
    pub(crate) async fn open(
        input: Input,
        output: Output,
        opts: PullSessionOptions,
        pending_limit: Option<Duration>,
    ) -> Result<PullSession> {
        let mut reader = FrameReader::new(BufReader::with_capacity(STREAM_BUFFER, input));
        let mut writer = FrameWriter::new(output);
        let agent = opts
            .agent
            .unwrap_or_else(|| format!("ostrya/{}", env!("CARGO_PKG_VERSION")));
        let hello = Message::PullHello(PullHello {
            version: PULL_PROTOCOL_VERSION,
            agent: Some(agent),
        });
        let written = match writer.write_message(&hello).await {
            Ok(()) => writer.flush().await,
            Err(e) => Err(e),
        };
        if let Err(e) = written {
            drop(writer);
            return Err(match read_pending(&mut reader, pending_limit).await {
                Some(Message::Error(sent)) if matches!(e, Error::Io(_)) => sent.into(),
                _ => e,
            });
        }
        let reply = match reader.read_message().await? {
            Some(Message::PullHelloReply(reply)) => reply,
            Some(Message::Error(e)) => return Err(e.into()),
            Some(other) => {
                return Err(protocol(format!(
                    "{:?} in reply to PullHello",
                    other.kind()
                )));
            }
            None => return Err(eof("the reply to PullHello")),
        };
        if !(1..=PULL_PROTOCOL_VERSION).contains(&reply.version) {
            let _ = writer.into_inner().close().await;
            return Err(Error::VersionUnsupported(format!(
                "the server replied with pull version {}, and the client speaks 1 to \
                 {PULL_PROTOCOL_VERSION}",
                reply.version
            )));
        }
        let outstanding = opts.max_outstanding.unwrap_or(DEFAULT_OUTSTANDING).max(1);
        Ok(PullSession {
            inner: PullInner {
                shared: Arc::new(Shared {
                    places: Arc::new(Gate::new(outstanding)),
                    writing: Arc::new(Gate::new(1)),
                    write: Mutex::new(WriteSide {
                        writer: Some(writer.into_inner()),
                        next: 0,
                    }),
                    read: Mutex::new(ReadSide {
                        reader: Some(Box::new(reader)),
                        abandoned: None,
                        turn: 0,
                        waiting: BTreeMap::new(),
                        failure: None,
                    }),
                    pending_limit,
                }),
                transport: None,
            },
        })
    }

    /// Attaches the child process whose standard streams the session uses.
    pub(crate) fn with_transport(mut self, child: Transport) -> PullSession {
        self.inner.transport = Some(child);
        self
    }

    /// Asks for the file at `path` and waits for the head of its reply.
    ///
    /// `path` is relative to the repository root. The call returns `None` if
    /// the server does not serve the path. The [`PullBody`] holds the body to
    /// `max_len` bytes and to its stated length.
    ///
    /// If [`max_outstanding`](PullSessionOptions::max_outstanding) calls hold
    /// a place, the call waits. It then takes its place, and writes and
    /// flushes its `Get` frame under one lock.
    ///
    /// The caller must read each body to its end, or drop it, before it
    /// awaits a later `get`. A later call waits for the end of each earlier
    /// body before it reads its own reply. If the future of the call is
    /// dropped after the call took its place, the session ends.
    ///
    /// If the write of the `Get` frame fails, the call waits for the turn of
    /// its reply. It then reads the message that the server can have sent
    /// before it closed. If [`connect`](PullSession::connect) opened the
    /// session, this read takes the ssh time limits of
    /// [`PushSession::connect`](super::PushSession::connect). If
    /// [`over_stream`](PullSession::over_stream) opened the session, this
    /// read has no time limit.
    ///
    /// # Errors
    ///
    /// The first two errors leave the session usable, and the call writes
    /// nothing. Each other error is a failure of the session, as
    /// [Failures](PullSession#failures) states.
    ///
    /// - [`Error::LimitExceeded`] if the `Get` frame of `path` is longer than
    ///   [`MIN_FRAME_LIMIT`].
    /// - [`Error::Protocol`] if `path` holds a NUL byte.
    /// - The repeat of the first failure, if the session failed before the
    ///   call or while it waits.
    /// - [`Error::LimitExceeded`] if the stated length of the body is more
    ///   than `max_len`. The session ends before it reads the body.
    /// - [`Error::LimitExceeded`] if a frame of the reply is longer than
    ///   [`MIN_FRAME_LIMIT`].
    /// - An `Error` message from the server, as the [`Error`] variant of its
    ///   code.
    /// - [`Error::Protocol`] if the reply is a message of another kind, or if
    ///   the codec refuses a frame of the reply.
    /// - [`Error::Io`] if a read or a write of the stream fails. If the stream
    ///   ends before the reply, the kind is `UnexpectedEof`.
    ///
    /// If the write of the `Get` frame fails and the server sent an `Error`
    /// message before it closed, the call returns the variant of that
    /// message. Otherwise it returns the [`Error::Io`] of the write.
    pub async fn get(&self, path: &str, max_len: u64) -> Result<Option<PullBody>> {
        let shared = &self.inner.shared;
        shared.check()?;
        let get = Message::Get(path.to_owned());
        let frame = encode_frame(&get, MIN_FRAME_LIMIT)?;
        let Message::Get(path) = get else {
            unreachable!("the message is a Get");
        };
        let place = shared.places.acquire(Priority::Normal).await;
        let turn = shared.writing.acquire(Priority::Normal).await;
        shared.check()?;
        let (seq, writer) = {
            let mut write = shared.lock_write();
            let seq = write.next;
            write.next += 1;
            (seq, write.writer.take())
        };
        let placed = Placed {
            shared,
            armed: true,
        };
        let written = match writer {
            Some(mut writer) => {
                let written = match writer.write_all(&frame).await {
                    Ok(()) => writer.flush().await.map_err(Error::from),
                    Err(e) => Err(e.into()),
                };
                // A failed write drops the writer, so the server reads the end
                // of its input. The check of a failure runs under the lock of
                // the write side: a session that failed during the write keeps
                // no writer.
                if written.is_ok() {
                    let mut write = shared.lock_write();
                    if shared.check().is_ok() {
                        write.writer = Some(writer);
                    }
                }
                written
            }
            // A write failed before this call: the call that failed gives the
            // failure at its turn, and this call repeats it.
            None => Ok(()),
        };
        drop(turn);
        let mut reader = shared.wait_turn(seq).await?;
        if let Err(e) = written {
            let pending = read_pending(&mut reader, shared.pending_limit).await;
            drop(reader);
            placed.disarm();
            return Err(shared.fail(match pending {
                Some(Message::Error(sent)) if matches!(e, Error::Io(_)) => sent.into(),
                _ => e,
            }));
        }
        let reply = reader.read_message().await;
        placed.disarm();
        match reply {
            Ok(Some(Message::GetReply(GetReply { found: false, .. }))) => {
                shared.advance(reader, seq);
                drop(place);
                Ok(None)
            }
            Ok(Some(Message::GetReply(GetReply { found: true, len }))) => {
                if let Some(len) = len
                    && len > max_len
                {
                    drop(reader);
                    return Err(shared.fail(Error::LimitExceeded(format!(
                        "{path}: a body of {len} bytes is over the limit {max_len}"
                    ))));
                }
                shared.lend(reader)?;
                Ok(Some(PullBody {
                    len,
                    inner: Mutex::new(BodyInner {
                        shared: Arc::clone(shared),
                        state: BodyState::Reading,
                        place: Some(place),
                        seq,
                        path,
                        len,
                        max_len,
                        read: 0,
                    }),
                }))
            }
            Ok(Some(Message::Error(e))) => Err(shared.fail(e.into())),
            Ok(Some(other)) => {
                Err(shared.fail(protocol(format!("{:?} in reply to Get", other.kind()))))
            }
            Ok(None) => Err(shared.fail(eof("the reply to Get"))),
            Err(e) => Err(shared.fail(e)),
        }
    }

    /// Ends the session.
    ///
    /// An end is clean if the session read the end of every reply. After a
    /// clean end, the session closes its output at a frame boundary. The call
    /// then returns `Ok`, whatever the exit status of the ssh client.
    ///
    /// At any other end, the session closes its output and drops its input
    /// before it waits for the ssh client. Because the session drops the
    /// input first, a server that is blocked in a write of a body does not
    /// keep the client open. The session then fails with the error that the
    /// call returns, and a later read of a held body repeats that error.
    ///
    /// If [`connect`](PullSession::connect) opened the session, the call then
    /// waits for the ssh client to exit. The wait takes the ssh time limits
    /// of [`PushSession::connect`](super::PushSession::connect).
    ///
    /// # Errors
    ///
    /// - The repeat of the first failure, if the session failed.
    /// - [`Error::InvalidInput`] if the body of a reply is not read to its
    ///   end, for example a body that the caller still holds.
    /// - [`Error::Transport`] with the exit status, if the ssh client exited
    ///   with a failure status and the error of the session is
    ///   [`Error::Io`]. Only a session that [`connect`](PullSession::connect)
    ///   opened returns it.
    pub async fn finish(mut self) -> Result<()> {
        let transport = self.inner.transport.take();
        let shared = &self.inner.shared;
        let next = shared.lock_write().next;
        let unclean = {
            let read = shared.lock_read();
            match &read.failure {
                Some(first) => Some(repeat(first)),
                None if read.reader.is_none() || read.turn != next => Some(Error::InvalidInput(
                    "the session ended while a body was unread".into(),
                )),
                None => None,
            }
        };
        let result = match unclean {
            // The failure drops the reader and the writer, also while the
            // caller holds a body, whose later read repeats the failure.
            Some(e) => Err(shared.fail(e)),
            None => {
                let writer = shared.lock_write().writer.take();
                if let Some(mut output) = writer {
                    let _ = output.close().await;
                }
                let reader = shared.lock_read().reader.take();
                drop(reader);
                Ok(())
            }
        };
        match transport {
            Some(transport) => transport.finish(result).await,
            None => result,
        }
    }
}

impl Drop for PullSession {
    fn drop(&mut self) {
        // A body that the caller holds keeps the shared state, so this drop
        // closes the output.
        let writer = self.inner.shared.lock_write().writer.take();
        drop(writer);
    }
}

/// The body of a file that [`PullSession::get`] returns, as an `AsyncRead`.
///
/// A read gives the bytes of the body until the chunk that ends it, and then
/// end of file. When a read meets that chunk, the session moves to the next
/// reply. The body is `Send + Sync`.
///
/// # Failures
///
/// Each of these events in a read ends the session:
///
/// - a body that is longer than the `max_len` of its call
/// - a body whose stated length is different from the sum of its chunks
/// - an `Error` message after the abandon marker
/// - a failed read
///
/// The read then fails with an `io::Error` that carries the [`Error`] of the
/// session, and each later read fails the same way. If that error is an
/// [`Error::Io`], the `io::Error` has its kind. Otherwise the kind is
/// `Other`.
///
/// The session can also fail for another reason, for example a dropped
/// `get` future or [`PullSession::finish`]. A later read of the body then
/// fails with the first failure and reads no more of the body. A drop of the
/// body before its end also ends the session.
pub struct PullBody {
    len: Option<u64>,
    inner: Mutex<BodyInner>,
}

struct BodyInner {
    shared: Arc<Shared>,
    state: BodyState,
    /// The place of the call, which the end of the body releases.
    place: Option<Permit>,
    seq: u64,
    path: String,
    len: Option<u64>,
    max_len: u64,
    /// The number of bytes of the body that the reads gave so far.
    read: u64,
}

enum BodyState {
    /// The read of the body is in progress. The read side of the session
    /// holds the reader, or the read of the frame that follows the abandon
    /// marker.
    Reading,
    /// The body ended.
    Ended,
    /// The session failed. Each read repeats the error.
    Failed(Error),
}

impl PullBody {
    /// Returns the length that the server stated for the body, if any.
    // A body with no stated length has no answer to `is_empty`.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> Option<u64> {
        self.len
    }
}

impl std::fmt::Debug for PullBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PullBody")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl BodyInner {
    /// Ends the session with `e`, and returns the error of the read.
    fn fail(&mut self, e: Error) -> io::Error {
        let e = self.shared.fail(e);
        self.state = BodyState::Failed(repeat(&e));
        self.place = None;
        body_error(e)
    }

    /// Adds `n` bytes to the count of the body, and checks the count against
    /// the cap and the stated length.
    fn count(&mut self, n: usize) -> Result<()> {
        self.read += n as u64;
        if self.read > self.max_len {
            return Err(Error::LimitExceeded(format!(
                "{}: the body passed the limit of {} bytes",
                self.path, self.max_len
            )));
        }
        if let Some(len) = self.len
            && self.read > len
        {
            return Err(protocol(format!(
                "{}: the body holds more than its stated length of {len} bytes",
                self.path
            )));
        }
        Ok(())
    }

    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match &self.state {
            BodyState::Ended => return Poll::Ready(Ok(0)),
            BodyState::Failed(e) => return Poll::Ready(Err(body_error(repeat(e)))),
            BodyState::Reading => {}
        }
        let mut next = None;
        // The bytes read, or 0 at the end of the body.
        let got = {
            let mut guard = self.shared.lock_read();
            let read = &mut *guard;
            loop {
                if let Some(first) = &read.failure {
                    break Err(repeat(first));
                }
                if let Some(abandoned) = read.abandoned.as_mut() {
                    let frame = ready!(abandoned.as_mut().poll(cx));
                    read.abandoned = None;
                    break Err(match frame {
                        Ok(Some(Message::Error(sent))) => sent.into(),
                        Ok(Some(other)) => {
                            protocol(format!("{:?} after the abandon marker", other.kind()))
                        }
                        Ok(None) => eof("the Error after the abandon marker"),
                        Err(e) => e,
                    });
                }
                let Some(reader) = read.reader.as_mut() else {
                    unreachable!("the body holds the turn of the reader");
                };
                if buf.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                match ready!(reader.poll_step(cx, buf)) {
                    Ok(Step::Data(n)) => break Ok(n),
                    Ok(Step::End) => {
                        if let Some(len) = self.len
                            && len != self.read
                        {
                            break Err(protocol(format!(
                                "{}: the body holds {} bytes, not its stated length of {len}",
                                self.path, self.read
                            )));
                        }
                        next = read.advance(self.seq);
                        break Ok(0);
                    }
                    Ok(Step::Marker(_)) => {
                        if let Some(mut reader) = read.reader.take() {
                            read.abandoned =
                                Some(Box::pin(async move { reader.read_message().await }));
                        }
                    }
                    Err(e) => break Err(e),
                }
            }
        };
        match got {
            Ok(0) => {
                self.state = BodyState::Ended;
                self.place = None;
                if let Some(waker) = next {
                    waker.wake();
                }
                Poll::Ready(Ok(0))
            }
            Ok(n) => Poll::Ready(match self.count(n) {
                Ok(()) => Ok(n),
                Err(e) => Err(self.fail(e)),
            }),
            Err(e) => Poll::Ready(Err(self.fail(e))),
        }
    }
}

impl AsyncRead for PullBody {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .inner
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .poll_read(cx, buf)
    }
}

impl Drop for PullBody {
    fn drop(&mut self) {
        let inner = self.inner.get_mut().unwrap_or_else(PoisonError::into_inner);
        if matches!(inner.state, BodyState::Reading) {
            inner.shared.fail(Error::InvalidInput(
                "a pull body was dropped before its end".into(),
            ));
        }
    }
}
