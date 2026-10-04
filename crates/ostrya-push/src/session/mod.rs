//! The client session of a push.
//!
//! A [`PushSession`] opens with `Hello` and gives the facts of the server as
//! [`ServerInfo`]. [`missing`](PushSession::missing) asks the server which
//! objects it needs, [`send`](PushSession::send) sends them from an
//! [`ObjectSource`] with the detached metadata of their commits, and
//! [`commit`](PushSession::commit) asks the server to update its refs in one
//! transaction.
//!
//! The session does not verify the objects it sends. It computes no checksum
//! and checks no size, and the server verifies each object as it arrives. A
//! source that fails while the session sends an object makes the session
//! abandon the object with the abandon marker and end the session with
//! `Abort`.
//!
//! On a stream transport the session runs one call at a time. A call to
//! [`missing`](PushSession::missing) or [`send`](PushSession::send) while
//! another one runs fails at once with [`Error::InvalidInput`]. A call that
//! fails, or whose future is dropped before it completes, leaves the session
//! broken, and each later call fails with [`Error::InvalidInput`].
//!
//! Over HTTP, several [`send`](PushSession::send) calls can run at the same
//! time, and a [`missing`](PushSession::missing) call can run beside them.
//! A second `missing` call while one runs fails at once with
//! [`Error::InvalidInput`]. A call that fails, or whose future is dropped
//! before it completes, leaves the session broken, as on a stream.

pub(crate) mod http;
mod progress;
mod pull;
pub(crate) mod stream;
mod writer;

use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_io::{AsyncRead, AsyncWrite};
use ostrya_core::{Checksum, FileHeader, ObjectName};
use ostrya_gvariant::Value;

pub use progress::{PushPhase, PushProgress, PushProgressSnapshot, PushStats};
pub use pull::{PullBody, PullSession, PullSessionOptions};

use self::http::{Endpoint, HttpLink};
use self::progress::Counters;
use self::stream::Stream;
use self::writer::{MetaClaims, Upload};
use crate::error::{Error, Result};
use crate::proto::{
    CommitRequest, Encoding, Hello, HelloReply, Message, PROTOCOL_VERSION, RefOutcome, RefState,
    RefUpdate, have_entries_within, have_type, protocol,
};
use crate::transport::Transport;

/// A boxed future that is `Send`, the return type of the [`ObjectSource`]
/// methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The encoding a session sends content objects in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Compression {
    /// The `raw` encoding: the framed file header and the payload.
    #[default]
    None,
    /// The `deflate` encoding at `level`, 1 through 9, when the server lists
    /// it. A server that lists `raw` alone gets `raw`.
    Deflate {
        /// The compression level.
        level: u8,
    },
}

/// A stream of object bytes that a source gives the session.
pub trait ObjectReader: AsyncRead + Send + Sync + Unpin {}

impl<T: AsyncRead + Send + Sync + Unpin + ?Sized> ObjectReader for T {}

/// The data of one object, as an [`ObjectSource`] gives it.
pub enum ObjectData {
    /// A content object that the session encodes. `header` is its file
    /// header and `size` the length of its payload. A regular file has a
    /// `payload`, and a symlink has none and a `size` of 0.
    ///
    /// The session sends the framed header and the payload for `raw`, and the
    /// framed archive header and the payload through its own raw-DEFLATE
    /// compressor for `deflate`.
    Content {
        /// The file header.
        header: FileHeader,
        /// The length of the payload, in bytes.
        size: u64,
        /// The payload of a regular file.
        payload: Option<Box<dyn ObjectReader>>,
    },
    /// The object bytes in `encoding`, which the session copies as they are.
    /// A metadata object is `raw` alone. A content object in `raw` is sent as
    /// `raw` also when the session deflates.
    Encoded {
        /// The encoding of the bytes.
        encoding: Encoding,
        /// The bytes.
        reader: Box<dyn ObjectReader>,
    },
}

impl fmt::Debug for ObjectData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectData::Content {
                header,
                size,
                payload,
            } => f
                .debug_struct("Content")
                .field("header", header)
                .field("size", size)
                .field("payload", &payload.is_some())
                .finish(),
            ObjectData::Encoded { encoding, .. } => f
                .debug_struct("Encoded")
                .field("encoding", encoding)
                .finish_non_exhaustive(),
        }
    }
}

/// The objects a session can send.
pub trait ObjectSource: Send + Sync {
    /// Every object reachable from `commit`, the commit object included.
    fn objects<'a>(&'a self, commit: &'a Checksum) -> BoxFuture<'a, Result<Vec<ObjectName>>>;

    /// The data of the object `name`. `encoding` is the encoding the session
    /// sends the object in: `deflate` for a content object when the session
    /// deflates, `raw` otherwise. A source that holds the object in that
    /// encoding can give its bytes as [`ObjectData::Encoded`].
    fn open<'a>(
        &'a self,
        name: &'a ObjectName,
        encoding: Encoding,
    ) -> BoxFuture<'a, Result<ObjectData>>;

    /// The detached metadata the session sends for `commit`, an `a{sv}`
    /// dict, after the source applied its own filter.
    fn detached_metadata<'a>(
        &'a self,
        commit: &'a Checksum,
    ) -> BoxFuture<'a, Result<Option<Value>>>;
}

/// The facts of the server, from its `HelloReply`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// The protocol version of the session.
    pub version: u32,
    /// The repository mode.
    pub mode: String,
    /// The collection id of the repository.
    pub collection_id: Option<String>,
    /// The frame and chunk limit the session writes with.
    pub max_frame: u32,
    /// The most object names in one `Have`.
    pub max_have: u32,
    /// The content encodings the server accepts.
    pub encodings: Vec<Encoding>,
    /// The most object streams the server serves at the same time.
    pub parallel_uploads: u32,
    /// The state of each ref the session named, in the order of the names.
    pub refs: Vec<RefState>,
}

impl ServerInfo {
    /// The current commit of the ref `name` on the server. `None` when the
    /// ref is absent, or when the session did not name it.
    pub fn tip(&self, name: &str) -> Option<Checksum> {
        self.refs
            .iter()
            .find(|r| r.name == name)
            .and_then(|r| r.commit)
    }
}

/// The options of a session.
#[derive(Debug, Clone, Default)]
pub struct SessionOptions {
    /// The `agent` the session sends in `Hello`. The default is
    /// `ostrya/<version>`.
    pub agent: Option<String>,
    /// A handle the session also counts its progress into.
    pub progress: Option<PushProgress>,
}

/// The result of a push that committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    /// The commit the client built, when it built one. A session that sends
    /// objects of a source builds none.
    pub commit: Option<Checksum>,
    /// One outcome for each ref update, in the order of the updates.
    pub refs: Vec<RefOutcome>,
    /// The statistics of the session.
    pub stats: PushStats,
}

/// One client session of a push, over a stream transport or over HTTP.
///
/// The session is `Send + Sync`. See the module docs for the rules of
/// concurrent calls.
///
/// A session dropped without [`commit`](PushSession::commit) or
/// [`abort`](PushSession::abort) sends nothing more. A stream transport then
/// closes its output, so the server reads the end of the stream. Over HTTP
/// the server ends the session when its idle timeout ends.
pub struct PushSession {
    inner: SessionInner,
}

struct SessionInner {
    server: ServerInfo,
    counters: Arc<Counters>,
    /// The claims of the detached metadata the session sends.
    claims: MetaClaims,
    link: Link,
}

/// The transport of a session.
enum Link {
    /// A pair of byte streams.
    Stream {
        slot: Mutex<Slot>,
        /// The child process the streams belong to, for a session that
        /// [`PushSession::connect`] opened.
        transport: Option<Transport>,
    },
    /// The receive endpoint of an HTTP server.
    Http(HttpLink),
}

enum Slot {
    /// No call runs.
    Idle(Box<Stream>),
    /// A call runs and holds the stream.
    Busy,
    /// A call failed or was dropped. The stream is gone.
    Poisoned,
}

/// The stream a call holds. The call gives it back with
/// [`release`](Taken::release) when it completes. Dropped without a release,
/// it leaves the session broken.
struct Taken<'a> {
    slot: &'a Mutex<Slot>,
    stream: Option<Box<Stream>>,
}

impl Taken<'_> {
    fn stream(&mut self) -> &mut Stream {
        self.stream.as_mut().expect("the stream is held")
    }

    fn release(mut self) {
        let stream = self.stream.take().expect("the stream is held");
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Slot::Idle(stream);
    }
}

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        if self.stream.is_some() {
            *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Slot::Poisoned;
        }
    }
}

pub(crate) fn invalid(msg: impl Into<String>) -> Error {
    Error::InvalidInput(msg.into())
}

pub(super) fn broken() -> Error {
    invalid("the session is broken")
}

pub(super) fn unexpected(msg: &Message, request: &str) -> Error {
    protocol(format!("{:?} in reply to {request}", msg.kind()))
}

/// The DEFLATE level of `compression`, or `None` for `raw`. A level outside 1
/// through 9 is [`Error::InvalidInput`].
pub(crate) fn deflate_level(compression: Compression) -> Result<Option<u8>> {
    match compression {
        Compression::None => Ok(None),
        Compression::Deflate { level } if (1..=9).contains(&level) => Ok(Some(level)),
        Compression::Deflate { level } => Err(invalid(format!(
            "compression level {level} is not in 1 through 9"
        ))),
    }
}

/// Refuse a name of a type that `Have` and the objects of a source cannot
/// carry. The session sends detached metadata for a commit on its own.
fn refuse_off_wire(names: &[ObjectName]) -> Result<()> {
    match names.iter().find(|n| !have_type(n.ty)) {
        Some(n) => Err(invalid(format!(
            "object {} of type {:?} is not an object to offer or send",
            n.checksum, n.ty
        ))),
        None => Ok(()),
    }
}

/// Take the stream of `slot` for one call.
fn take(slot: &Mutex<Slot>) -> Result<Taken<'_>> {
    let mut held = slot.lock().unwrap_or_else(PoisonError::into_inner);
    match std::mem::replace(&mut *held, Slot::Busy) {
        Slot::Idle(stream) => Ok(Taken {
            slot,
            stream: Some(stream),
        }),
        Slot::Busy => Err(invalid("a call is in progress")),
        Slot::Poisoned => {
            *held = Slot::Poisoned;
            Err(broken())
        }
    }
}

/// The stream of an idle session.
fn into_stream(slot: Mutex<Slot>) -> Result<Box<Stream>> {
    match slot.into_inner().unwrap_or_else(PoisonError::into_inner) {
        Slot::Idle(stream) => Ok(stream),
        Slot::Busy | Slot::Poisoned => Err(broken()),
    }
}

/// The facts of the server from `reply`, the reply to a `Hello` with `refs`.
/// A reply whose version is not the version of the session, or whose refs
/// are not `refs` in order, is [`Error::Protocol`].
fn server_info(reply: HelloReply, refs: &[String]) -> Result<ServerInfo> {
    if reply.version != PROTOCOL_VERSION {
        return Err(protocol(format!(
            "the server replied with protocol version {}, not {PROTOCOL_VERSION}",
            reply.version
        )));
    }
    if reply.refs.len() != refs.len() || reply.refs.iter().zip(refs).any(|(s, n)| s.name != *n) {
        return Err(protocol("the refs of HelloReply are not the refs of Hello"));
    }
    Ok(ServerInfo {
        version: reply.version,
        mode: reply.mode,
        collection_id: reply.collection_id,
        max_frame: reply.max_frame,
        max_have: reply.max_have,
        encodings: reply.encodings,
        parallel_uploads: reply.parallel_uploads,
        refs: reply.refs,
    })
}

impl PushSession {
    /// Open a session over a pair of byte streams: `input` from the server
    /// and `output` to it. The session sends `Hello` with `refs`, the refs it
    /// intends to update, and reads `HelloReply`.
    ///
    /// An `Error` from the server is returned as its error. A reply whose
    /// version is not the version of the session, or whose refs are not the
    /// refs of `Hello` in order, is [`Error::Protocol`].
    ///
    /// The caller owns the liveness of the two streams. The session puts no
    /// time limit on a read: a peer that stays silent keeps a call waiting
    /// until the caller drops its future or closes the streams.
    pub async fn over_stream<R, W>(
        input: R,
        output: W,
        refs: &[String],
        opts: SessionOptions,
    ) -> Result<PushSession>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        PushSession::open(Box::new(input), Box::new(output), refs, opts, None).await
    }

    /// Open a session over `input` and `output`. `pending_limit` bounds the
    /// wait for a pending message after a failed write.
    pub(crate) async fn open(
        input: stream::Input,
        output: stream::Output,
        refs: &[String],
        opts: SessionOptions,
        pending_limit: Option<Duration>,
    ) -> Result<PushSession> {
        let counters = Arc::new(Counters::new(opts.progress.as_ref()));
        counters.phase(PushPhase::Negotiating);
        let mut stream = Stream::new(input, output, Arc::clone(&counters));
        if let Some(limit) = pending_limit {
            stream.set_pending_limit(limit);
        }
        let agent = opts
            .agent
            .unwrap_or_else(|| format!("ostrya/{}", env!("CARGO_PKG_VERSION")));
        stream
            .request(&Message::Hello(Hello {
                version: PROTOCOL_VERSION,
                agent: Some(agent),
                refs: refs.to_vec(),
            }))
            .await?;
        let reply = match stream.next().await? {
            Message::HelloReply(reply) => reply,
            Message::Error(e) => return Err(e.into()),
            other => return Err(unexpected(&other, "Hello")),
        };
        let server = server_info(reply, refs)?;
        stream.set_write_limit(server.max_frame);
        Ok(PushSession {
            inner: SessionInner {
                server,
                counters,
                claims: MetaClaims::default(),
                link: Link::Stream {
                    slot: Mutex::new(Slot::Idle(Box::new(stream))),
                    transport: None,
                },
            },
        })
    }

    /// Open a session over HTTP at `endpoint`: send `Hello` with `refs` and
    /// read `HelloReply`.
    pub(crate) async fn open_http(
        endpoint: Endpoint,
        refs: &[String],
        opts: SessionOptions,
    ) -> Result<PushSession> {
        let counters = Arc::new(Counters::new(opts.progress.as_ref()));
        counters.phase(PushPhase::Negotiating);
        let agent = opts
            .agent
            .unwrap_or_else(|| format!("ostrya/{}", env!("CARGO_PKG_VERSION")));
        let (server, link) = http::open(endpoint, refs, agent, &counters).await?;
        Ok(PushSession {
            inner: SessionInner {
                server,
                counters,
                claims: MetaClaims::default(),
                link: Link::Http(link),
            },
        })
    }

    /// Attach the child process the streams of the session belong to.
    pub(crate) fn with_transport(mut self, child: Transport) -> PushSession {
        if let Link::Stream { transport, .. } = &mut self.inner.link {
            *transport = Some(child);
        }
        self
    }

    /// The facts of the server.
    pub fn server(&self) -> &ServerInfo {
        &self.inner.server
    }

    /// The objects of `names` that the server does not hold, in the order of
    /// `names`. The session sends `Have` messages of at most `max-have`
    /// names each, and of at most the names whose frame fits in
    /// `max-frame`. A name whose type is not a file, a dirtree, a dirmeta,
    /// or a commit is [`Error::InvalidInput`], nothing is sent, and the
    /// session stays usable.
    ///
    /// Over HTTP each `Have` is one request, and the session sends the next
    /// one after the response to the one before it.
    pub async fn missing(&self, names: &[ObjectName]) -> Result<Vec<ObjectName>> {
        refuse_off_wire(names)?;
        let slot = match &self.inner.link {
            Link::Stream { slot, .. } => slot,
            Link::Http(link) => {
                return link
                    .missing(&self.inner.server, &self.inner.counters, names)
                    .await;
            }
        };
        let mut taken = take(slot)?;
        let counters = &self.inner.counters;
        counters.phase(PushPhase::Negotiating);
        counters.offered(names.len() as u64);
        let stream = taken.stream();
        let mut missing = Vec::new();
        let server = &self.inner.server;
        let batch_len = server
            .max_have
            .min(have_entries_within(server.max_frame))
            .max(1);
        for batch in names.chunks(batch_len as usize) {
            stream.request(&Message::Have(batch.to_vec())).await?;
            match stream.next().await? {
                Message::HaveReply(reply) => {
                    reply.check_len(batch.len())?;
                    missing.extend(
                        batch
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| reply.is_missing(*i))
                            .map(|(_, n)| *n),
                    );
                }
                Message::Error(e) => return Err(e.into()),
                other => return Err(unexpected(&other, "Have")),
            }
        }
        counters.needed(missing.len() as u64);
        taken.release();
        Ok(missing)
    }

    /// Send `names` from `source` in one object stream, then the detached
    /// metadata of each commit in `commits` that has some and whose detached
    /// metadata the session has not sent yet.
    ///
    /// `commits` holds the commits of `names` and the new value of each ref
    /// update, whether `names` holds that commit or not. A call with nothing
    /// to send writes nothing. A level outside 1 through 9, and a name whose
    /// type is not a file, a dirtree, a dirmeta, or a commit, are
    /// [`Error::InvalidInput`]. Nothing is sent, and the session stays
    /// usable.
    ///
    /// A source that fails ends the session with `Abort`, and the call
    /// returns [`Error::Source`]. Data of the source that the session cannot
    /// send ends the session the same way, and the call returns
    /// [`Error::InvalidInput`].
    ///
    /// Over HTTP the call sends the objects in up to `parallel-uploads`
    /// object streams at the same time, each in one request, and the objects
    /// of `names` can arrive in another order. The detached metadata goes in
    /// one of the streams, after its objects. The object streams of all the
    /// calls of the session stay within `parallel-uploads`, at most 31: a
    /// stream waits for a permit. After the first failure no stream starts a
    /// new object, and each stream reads its response. The call then returns
    /// a failure of the client first, then an error that the server gave
    /// for its own cause, then any other error.
    pub async fn send(
        &self,
        source: &dyn ObjectSource,
        names: &[ObjectName],
        commits: &[Checksum],
        compression: Compression,
    ) -> Result<()> {
        let level = deflate_level(compression)?;
        refuse_off_wire(names)?;
        let deflate_ok = self.inner.server.encodings.contains(&Encoding::Deflate);
        let upload = Upload::new(
            source,
            names,
            commits,
            level.filter(|_| deflate_ok),
            deflate_ok,
            &self.inner.claims,
        );
        let slot = match &self.inner.link {
            Link::Stream { slot, .. } => slot,
            Link::Http(link) => {
                self.inner.counters.phase(PushPhase::Uploading);
                return link.send(&self.inner.counters, &upload).await;
            }
        };
        let mut taken = take(slot)?;
        self.inner.counters.phase(PushPhase::Uploading);
        taken.stream().upload(&upload).await?;
        taken.release();
        Ok(())
    }

    /// Send `Commit` with `updates` and read the reply.
    ///
    /// Empty `updates`, a ref that `Hello` did not name, and a ref named
    /// twice are [`Error::InvalidInput`]. The call consumes the session and
    /// sends nothing, so the server reads the end of the stream. A call that
    /// failed, or whose future was dropped, left the stream broken: the call
    /// then sends nothing too, and returns [`Error::InvalidInput`]. Over
    /// HTTP, in each of these cases the call sends `DELETE` and no `Commit`.
    ///
    /// An `Error` from the server is returned as its error, and the server
    /// changed no ref. A `CommitReply` whose refs are not the refs of
    /// `updates` in order is [`Error::CommitOutcomeUnknown`]. When the write
    /// of `Commit` fails with an I/O error, the session reads one message:
    /// an `Error` is returned as that error, and a `CommitReply` is the
    /// reply. A `Commit` that the codec refuses, for example a frame over the
    /// limit, is returned as its error, and nothing is written. Each other
    /// end of the session after the session wrote `Commit` is
    /// [`Error::CommitOutcomeUnknown`]: the server may have written the refs.
    ///
    /// Over HTTP, a `Commit` request that the client did not hand over to a
    /// connection is [`Error::Fetch`], and the server changed no ref. After
    /// the hand-over, a failure of the request, a response head that the
    /// client refuses, as for a declared coding or a declared length over
    /// the cap, a failed read of the response, a status the endpoint does
    /// not give, and a body that is not one frame are
    /// [`Error::CommitOutcomeUnknown`]. The client does not send the request
    /// again.
    ///
    /// A session that [`connect`](PushSession::connect) opened then waits a
    /// bounded time for the ssh client to exit, also when the call refuses
    /// `updates` and when the stream is broken. A session that committed
    /// returns its outcome whatever the exit status.
    pub async fn commit(self, updates: &[RefUpdate], force: bool) -> Result<PushOutcome> {
        let checked = check_updates(&self.inner.server.refs, updates);
        let (slot, transport, counters, checked) =
            match self.inner.into_commit(checked, updates, force) {
                Committing::Stream {
                    slot,
                    transport,
                    counters,
                    checked,
                } => (slot, transport, counters, checked),
                Committing::Http(commit) => return commit.await,
            };
        let stream = into_stream(slot);
        let result = match (checked, stream) {
            (Ok(()), Ok(stream)) => commit_on(stream, updates, force, &counters).await,
            (Ok(()), Err(e)) => Err(e),
            (Err(e), stream) => {
                // The server reads the end of the stream.
                drop(stream);
                Err(e)
            }
        };
        finish(transport, result).await
    }

    /// End the session. The server aborts its transaction.
    ///
    /// When the stream is still usable, the session writes `Abort` and
    /// closes its output. A call that failed, or whose future was dropped,
    /// left the stream broken and dropped it. The session then writes
    /// nothing, and the call returns [`Error::InvalidInput`].
    ///
    /// A session that [`connect`](PushSession::connect) opened then waits a
    /// bounded time for the ssh client to exit, also when the stream is
    /// broken. When the write of `Abort` fails with an I/O error and the
    /// client exited with a failure status, the call returns
    /// [`Error::Transport`] with the status.
    ///
    /// Over HTTP the call sends `DELETE`, also on a broken session, which
    /// then gives [`Error::InvalidInput`]. A 404, which the server gives for
    /// a session that it ended already, is success.
    pub async fn abort(self) -> Result<()> {
        let (slot, transport) = match self.inner.link {
            Link::Stream { slot, transport } => (slot, transport),
            Link::Http(link) => return link.abort().await,
        };
        let result = match into_stream(slot) {
            Ok(mut stream) => {
                let result = stream.write_raw(&Message::Abort).await;
                let _ = stream.close().await;
                result
            }
            Err(e) => Err(e),
        };
        finish(transport, result).await
    }
}

/// A session that commits: the parts of a stream session, or the commit of
/// an HTTP session. The value lives for one match, so the size of the
/// stream variant costs nothing.
#[allow(clippy::large_enum_variant)]
enum Committing<'a> {
    Stream {
        slot: Mutex<Slot>,
        transport: Option<Transport>,
        counters: Arc<Counters>,
        checked: Result<()>,
    },
    /// The HTTP commit holds the response of its request, so its future is
    /// boxed, and the future of a stream commit does not hold it.
    Http(BoxFuture<'a, Result<PushOutcome>>),
}

impl SessionInner {
    /// Take the session apart to commit `updates`, which `checked` checked.
    fn into_commit<'a>(
        self,
        checked: Result<()>,
        updates: &'a [RefUpdate],
        force: bool,
    ) -> Committing<'a> {
        let SessionInner {
            server,
            counters,
            link,
            ..
        } = self;
        match link {
            Link::Stream { slot, transport } => Committing::Stream {
                slot,
                transport,
                counters,
                checked,
            },
            Link::Http(link) => Committing::Http(Box::pin(async move {
                link.commit(&server, &counters, checked, updates, force)
                    .await
            })),
        }
    }
}

/// Refuse empty `updates`, a ref that is not in `refs`, and a ref named
/// twice.
fn check_updates(refs: &[RefState], updates: &[RefUpdate]) -> Result<()> {
    if updates.is_empty() {
        return Err(invalid("a commit needs at least one ref update"));
    }
    let mut seen = HashSet::new();
    for u in updates {
        if !refs.iter().any(|r| r.name == u.name) {
            return Err(invalid(format!(
                "ref '{}' was not named when the session opened",
                u.name
            )));
        }
        if !seen.insert(u.name.as_str()) {
            return Err(invalid(format!("ref '{}' is updated twice", u.name)));
        }
    }
    Ok(())
}

/// End a session with `result`. A session with a transport waits for it to
/// finish. The stream of the session must be closed or dropped first.
async fn finish<T>(transport: Option<Transport>, result: Result<T>) -> Result<T> {
    match transport {
        Some(transport) => transport.finish(result).await,
        None => result,
    }
}

/// Send `Commit` over `stream` and read the reply. The stream is closed or
/// dropped when the call returns.
async fn commit_on(
    mut stream: Box<Stream>,
    updates: &[RefUpdate],
    force: bool,
    counters: &Counters,
) -> Result<PushOutcome> {
    counters.phase(PushPhase::Committing);
    let names = || updates.iter().map(|u| u.name.clone()).collect::<Vec<_>>();
    let unknown = |message: String| Error::CommitOutcomeUnknown {
        refs: names(),
        message,
    };
    let request = Message::Commit(CommitRequest {
        updates: updates.to_vec(),
        force,
    });
    let reply = match stream.write_raw(&request).await {
        Ok(()) => stream.read_raw().await,
        Err(e @ Error::Io(_)) => match stream.pending_message(&e).await {
            Some(msg @ (Message::Error(_) | Message::CommitReply(_))) => Ok(Some(msg)),
            _ => return Err(unknown(format!("the write of Commit failed: {e}"))),
        },
        Err(e) => return Err(e),
    };
    let refs = match reply {
        Ok(Some(Message::CommitReply(refs))) => refs,
        Ok(Some(Message::Error(e))) => return Err(e.into()),
        Ok(Some(other)) => {
            return Err(unknown(format!("{:?} in reply to Commit", other.kind())));
        }
        Ok(None) => return Err(unknown("the session ended before CommitReply".into())),
        Err(e) => return Err(unknown(format!("the reply to Commit failed: {e}"))),
    };
    if refs.len() != updates.len() || refs.iter().zip(updates).any(|(o, u)| o.name != u.name) {
        return Err(unknown(
            "the server replied to Commit for other refs than the refs of Commit".into(),
        ));
    }
    // The refs are written. A failure to close the stream changes nothing.
    let _ = stream.close().await;
    Ok(PushOutcome {
        commit: None,
        refs,
        stats: counters.stats(),
    })
}
