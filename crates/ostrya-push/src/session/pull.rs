//! The client session of a pull over ssh.
//!
//! A [`PullSession`] opens with `PullHello` and asks for files by their path
//! with [`get`](PullSession::get). The requests share one stream as a
//! pipeline: a `get` takes its place in the pipeline and writes its `Get`
//! frame under one lock, so the frames go on the wire in the order of the
//! places, and the reply of a call is the next reply after the reply of the
//! call before it. A reply carries no request id.
//!
//! At most [`max_outstanding`](PullSessionOptions::max_outstanding) calls
//! hold a place at a time. A call holds its place from the write of its
//! `Get` frame to the end of its reply: a reply with found false, or the
//! chunk that ends the body of a found reply. The session moves to the next
//! reply when it reads that chunk, also while the caller still holds the
//! [`PullBody`].
//!
//! A failure ends the session: an `Error` from the server, a reply out of
//! order, a stated length above the cap of the call or different from the
//! sum of the chunks, a body past the cap, a failed read or write, a `get`
//! future dropped after it took its place, and a [`PullBody`] dropped before
//! its end. Each later call, and each later read of a body, fails with an
//! error of the variant and the message of the first failure.

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

/// The most calls that hold a place when the options name no number.
const DEFAULT_OUTSTANDING: usize = 8;

type Reader = FrameReader<BufReader<Input>>;
type ReadFuture = Pin<Box<dyn Future<Output = Result<Option<Message>>> + Send>>;

/// The options of a pull session.
#[derive(Debug, Clone, Default)]
pub struct PullSessionOptions {
    /// The `agent` the session sends in `PullHello`. The default is
    /// `ostrya/<version>`.
    pub agent: Option<String>,
    /// The most `get` calls that hold a place in the pipeline at a time. The
    /// default is 8, and 0 is raised to 1.
    pub max_outstanding: Option<usize>,
}

/// One client session of a pull over ssh.
///
/// The session is `Send + Sync`. Concurrent [`get`](PullSession::get) calls
/// share the pipeline, and the replies come in the order of the `Get`
/// frames. See the module docs for the rules of the pipeline.
///
/// A session dropped without [`finish`](PullSession::finish) sends nothing
/// more and closes its output, so the server reads the end of its input. This
/// is also true while the caller holds a [`PullBody`]. A session that [`connect`](PullSession::connect) opened then drops the ssh
/// client without a wait.
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
    /// The order of the writes: one call writes at a time, in the order the
    /// calls arrived.
    writing: Arc<Gate>,
    write: Mutex<WriteSide>,
    read: Mutex<ReadSide>,
    /// The longest wait for a pending message after a failed write. `None`
    /// waits with no limit.
    pending_limit: Option<Duration>,
}

struct WriteSide {
    /// The output, which a call takes while it writes its `Get` frame. `None`
    /// once a write failed, the session failed, or the session ended.
    writer: Option<Output>,
    /// The place of the next call.
    next: u64,
}

struct ReadSide {
    /// The reader. The call whose reply is next takes it while it reads the
    /// head of its reply. The body of a found reply reads it here, under the
    /// lock, so the end of the session drops it also while the caller holds
    /// the body.
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

/// An error of the variant and the message of `e`, for a later call of a
/// session that failed with `e`. An I/O error keeps its kind.
fn repeat(e: &Error) -> Error {
    match e {
        Error::Io(io) => Error::Io(io::Error::new(io.kind(), io.to_string())),
        Error::Transport(msg) => Error::Transport(msg.clone()),
        Error::InvalidInput(msg) => Error::InvalidInput(msg.clone()),
        other if other.code().is_some() => other.to_message().into(),
        other => Error::InvalidInput(other.to_string()),
    }
}

/// The `io::Error` a body read gives for `e`. It carries `e`, and the kind of
/// an I/O error.
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

/// Read one message within `limit`. A failed read, an end of file, and a read
/// that takes longer than `limit` give `None`.
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

    /// The repeat of the first failure, when the session failed.
    fn check(&self) -> Result<()> {
        match &self.lock_read().failure {
            Some(first) => Err(repeat(first)),
            None => Ok(()),
        }
    }

    /// End the session with `e`. The first failure stays the failure of the
    /// session. Gives `e`, or the repeat of an earlier failure. The reader
    /// and the writer are dropped, and every waiting call wakes.
    ///
    /// The failure is recorded before the writer is taken, so a call that
    /// checks for a failure under the lock of the write side does not give
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

    /// Take the reader for the call at `place`, when its reply is next.
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

    /// Give back the reader after the reply of `place` ended, and wake the
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

    /// Give back the reader for the body of the reply at the turn, which
    /// reads it in place. When the session failed, the reader is dropped,
    /// and the call gives the repeat of the first failure.
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
    /// Move the turn past the reply of `place`. Gives the waker of the call
    /// whose reply is next.
    fn advance(&mut self, place: u64) -> Option<Waker> {
        self.turn = place + 1;
        self.waiting.remove(&(place + 1))
    }
}

/// A call that took its place. Dropped before its reply was handed over, it
/// ends the session: its reply still arrives, and the codec is not
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

impl PullSession {
    /// Open a session over a pair of byte streams: `input` from the server and
    /// `output` to it. The session sends `PullHello` with
    /// [`PULL_PROTOCOL_VERSION`] and reads `PullHelloReply`.
    ///
    /// An `Error` from the server is returned as its error. A reply with a
    /// version the client does not speak is [`Error::VersionUnsupported`],
    /// and the session closes `output` and sends no `Get`.
    ///
    /// The caller owns the liveness of the two streams. The session puts no
    /// time limit on a read: a peer that stays silent keeps a call waiting
    /// until the caller drops its future or closes the streams.
    pub async fn over_stream<R, W>(input: R, output: W, opts: PullSessionOptions) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        PullSession::open(Box::new(input), Box::new(output), opts, None).await
    }

    /// Open a session over `input` and `output`. `pending_limit` bounds the
    /// wait for a pending message after a failed write.
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

    /// Attach the child process the streams of the session belong to.
    pub(crate) fn with_transport(mut self, child: Transport) -> PullSession {
        self.inner.transport = Some(child);
        self
    }

    /// Ask for the file at `path`, relative to the repository root, and wait
    /// for the head of its reply. `None` is a path that the server does not
    /// serve.
    ///
    /// The call waits while `max_outstanding` calls hold a place. It then
    /// takes its place, and writes and flushes its `Get` frame under one
    /// lock. A path whose `Get` frame is over the frame limit is
    /// [`Error::LimitExceeded`], nothing is written, and the session stays
    /// usable.
    ///
    /// A stated length above `max_len` ends the session with
    /// [`Error::LimitExceeded`] before the body is read. The [`PullBody`]
    /// holds the body to `max_len` and to its stated length.
    ///
    /// The caller reads each body to its end, or drops it, before it awaits a
    /// later `get`: a later call waits for the end of each body before its
    /// own reply. A future of the call dropped after the call took its place
    /// ends the session.
    ///
    /// When the write of the `Get` frame fails, the call reads the message
    /// the server can have sent before it closed, at the turn of its reply,
    /// within the time limit of a session that
    /// [`connect`](PullSession::connect) opened. An `Error` is returned as its
    /// error, and otherwise the error of the write.
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

    /// End the session.
    ///
    /// After a clean end, when the session read the end of every reply and
    /// the caller holds no body, the session closes its output at a frame
    /// boundary, and the call returns `Ok` whatever the exit status of the
    /// ssh client. At any other end the session closes its output and drops
    /// its input before it waits for the ssh client, and the call returns the
    /// error of the session: the first failure, or [`Error::InvalidInput`]
    /// for a body that the caller still holds. The session then fails with
    /// that error, and a later read of the held body repeats it.
    ///
    /// A session that [`connect`](PullSession::connect) opened then waits a
    /// bounded time for the ssh client to exit. When the error of the session
    /// is [`Error::Io`] and the client exited with a failure status, the call
    /// returns [`Error::Transport`] with the status.
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
        // A body that the caller holds keeps the shared state, so the output
        // is closed here.
        let writer = self.inner.shared.lock_write().writer.take();
        drop(writer);
    }
}

/// The body of one found reply, as an `AsyncRead`.
///
/// A read gives the bytes of the body until the chunk that ends it, and then
/// end of file. The session moves to the next reply when a read meets that
/// chunk. A body past the cap of its call, a body whose stated length
/// differs from the sum of its chunks, an `Error` after the abandon marker,
/// and a failed read each end the session. The read fails with an
/// `io::Error` that carries the [`Error`] of the session, and each later read
/// fails the same way. A read after the session failed for another reason,
/// for example a dropped `get` future or [`PullSession::finish`], fails with
/// the first failure and reads no more of the body. A body dropped before its
/// end ends the session.
///
/// The body is `Send + Sync`.
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
    /// The bytes of the body read so far.
    read: u64,
}

enum BodyState {
    /// The body is being read. The read side of the session holds the
    /// reader, or the read of the frame that follows the abandon marker.
    Reading,
    /// The body ended.
    Ended,
    /// The session failed. Each read repeats the error.
    Failed(Error),
}

impl PullBody {
    /// The length the server stated for the body, when it knows it.
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
    /// End the session with `e`, and give the error of the read.
    fn fail(&mut self, e: Error) -> io::Error {
        let e = self.shared.fail(e);
        self.state = BodyState::Failed(repeat(&e));
        self.place = None;
        body_error(e)
    }

    /// Count `n` bytes of the body, and check them against the cap and the
    /// stated length.
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
