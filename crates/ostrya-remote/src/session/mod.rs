//! The client sessions of the push and of the pull, and the one-way stream.
//!
//! A [`PushSession`] opens with `Hello` and gives the facts of the server as
//! [`ServerInfo`]. Its calls are:
//!
//! - [`missing`](PushSession::missing) asks the server which objects it needs.
//! - [`send`](PushSession::send) sends them from an [`ObjectSource`], with the
//!   detached metadata of their commits.
//! - [`commit`](PushSession::commit) asks the server to update its refs in
//!   one transaction.
//!
//! [`PushProgress`] counts the progress of a session, and [`PushOutcome`]
//! gives the result of a session that committed.
//!
//! A [`PullSession`] reads files of a server repository by their path, and
//! gives the body of each file as a [`PullBody`].
//!
//! [`export_stream`] writes a one-way stream: the messages of a push session in
//! one direction, for a receiver that sends no reply.

pub(crate) mod http;
mod one_way;
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
use ostrya_core::{Checksum, FileHeader, ObjectName, ObjectType};
use ostrya_gvariant::Value;

pub use one_way::export_stream;
pub use progress::{PushPhase, PushProgress, PushProgressFn, PushProgressSnapshot, PushStats};
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

/// A boxed `Send` future, the return type of the [`ObjectSource`] methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The encoding of the content objects that a session sends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Compression {
    /// The `raw` encoding: the framed file header and the payload.
    #[default]
    None,
    /// The `deflate` encoding at `level`, 1 through 9.
    ///
    /// The session uses it if the server lists `deflate`. If the server lists
    /// `raw` alone, the session sends `raw`.
    Deflate {
        /// The compression level, 1 through 9.
        level: u8,
    },
}

/// A stream of object bytes that a source gives to the session.
pub trait ObjectReader: AsyncRead + Send + Sync + Unpin {}

impl<T: AsyncRead + Send + Sync + Unpin + ?Sized> ObjectReader for T {}

/// The data of one object, as an [`ObjectSource`] gives it.
pub enum ObjectData {
    /// A content object that the session encodes.
    ///
    /// `header` is the file header of the object, and `size` is the length of
    /// its payload. A regular file has a `payload`. A symlink has no `payload`
    /// and a `size` of 0.
    ///
    /// For `raw`, the session sends the framed header and the payload. For
    /// `deflate`, it sends the framed archive header, and then the payload
    /// through its own raw-DEFLATE compressor.
    Content {
        /// The file header.
        header: FileHeader,
        /// The length of the payload, in bytes.
        size: u64,
        /// The payload of a regular file.
        payload: Option<Box<dyn ObjectReader>>,
    },
    /// The object bytes in `encoding`, which the session copies as they are.
    ///
    /// A metadata object is `raw` alone. The session sends a content object in
    /// `raw` as `raw`, also if it deflates. Bytes in `deflate` for a metadata
    /// object, or for a server that does not list `deflate`, are
    /// [`Error::InvalidInput`].
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

/// A source of the objects that a session sends.
pub trait ObjectSource: Send + Sync {
    /// Returns the name of each object that `commit` reaches, and of the commit.
    ///
    /// No session method calls `objects`. A caller gives the list to
    /// [`missing`](PushSession::missing) to find the objects to
    /// [`send`](PushSession::send).
    ///
    /// # Errors
    ///
    /// The error depends on the implementation:
    ///
    /// - [`TreeModel`](crate::tree::TreeModel) returns [`Error::InvalidInput`]
    ///   if the model holds no commit, or if `commit` is not the commit of the
    ///   model.
    /// - The repository source of the `ostrya` crate returns
    ///   [`Error::Source`] if the walk of `commit` in the repository fails.
    fn objects<'a>(&'a self, commit: &'a Checksum) -> BoxFuture<'a, Result<Vec<ObjectName>>>;

    /// Returns the data of the object `name`.
    ///
    /// `encoding` is the encoding in which the session sends the object:
    /// `deflate` for a content object if the session deflates, and `raw` for
    /// all other objects. A source that holds the object in that encoding can
    /// give its bytes as [`ObjectData::Encoded`].
    ///
    /// # Errors
    ///
    /// An error of the source stops the object stream.
    /// [`send`](PushSession::send) and [`export_stream`] return it as
    /// [`Error::Source`].
    fn open<'a>(
        &'a self,
        name: &'a ObjectName,
        encoding: Encoding,
    ) -> BoxFuture<'a, Result<ObjectData>>;

    /// Returns the detached metadata for `commit`, an `a{sv}` dict.
    ///
    /// The source applies its own filter first. For `None`, the session sends
    /// no detached metadata for `commit`. If the dict is not a valid `a{sv}`
    /// value, or if its bytes are more than 128 MiB, the object stream stops
    /// with [`Error::InvalidInput`].
    ///
    /// # Errors
    ///
    /// An error of the source stops the object stream.
    /// [`send`](PushSession::send) and [`export_stream`] return it as
    /// [`Error::Source`].
    fn detached_metadata<'a>(
        &'a self,
        commit: &'a Checksum,
    ) -> BoxFuture<'a, Result<Option<Value>>>;

    /// Returns the content bytes of the file objects of `names` in `encoding`.
    ///
    /// `None` means that the source does not know the number. The names that
    /// are not file objects count no byte. The default implementation returns
    /// `None`.
    ///
    /// The content bytes of one file object are the bytes that the session
    /// reads from the reader that [`open`](ObjectSource::open) gives for it
    /// with the same `encoding`:
    ///
    /// - the payload of [`ObjectData::Content`]
    /// - 0 for a symlink
    /// - the bytes of [`ObjectData::Encoded`]
    ///
    /// If the session has a [`PushProgress`] and `names` holds at least one
    /// file object, each [`send`](PushSession::send) call and each
    /// [`export_stream`] call asks once, before the first object. The call
    /// adds the answer to [`bytes_total`](PushProgressSnapshot::bytes_total).
    ///
    /// The method must not read the content of an object. It reads what the
    /// source already holds, or the metadata of each object.
    ///
    /// # Errors
    ///
    /// The session treats an error as `None`. The call adds nothing to the
    /// total and sends the objects.
    fn content_size<'a>(
        &'a self,
        names: &'a [ObjectName],
        encoding: Encoding,
    ) -> BoxFuture<'a, Result<Option<u64>>> {
        let _ = (names, encoding);
        Box::pin(async { Ok(None) })
    }
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
    /// The frame and chunk limit that the session writes with.
    ///
    /// The [frame rules](crate::proto#frames) give the range of the value.
    pub max_frame: u32,
    /// The highest number of object names in one `Have`.
    pub max_have: u32,
    /// The content encodings that the server accepts.
    pub encodings: Vec<Encoding>,
    /// The most object streams that the server serves at the same time.
    pub parallel_uploads: u32,
    /// The state of each ref that the session named, in the order of the names.
    pub refs: Vec<RefState>,
}

impl ServerInfo {
    /// Returns the current commit of the ref `name` on the server.
    ///
    /// Returns `None` if the ref is absent, or if the session did not name it.
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
    /// The `agent` that the session sends in `Hello`.
    ///
    /// The default is `ostrya/<version>`.
    pub agent: Option<String>,
    /// A handle that the session also counts its progress into.
    pub progress: Option<PushProgress>,
}

/// The result of a push that committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    /// The commit that the client built, if it built one.
    ///
    /// A session that sends the objects of a source builds no commit.
    pub commit: Option<Checksum>,
    /// One outcome for each ref update, in the order of the updates.
    pub refs: Vec<RefOutcome>,
    /// The statistics of the session.
    pub stats: PushStats,
}

/// A client session of a push, over a stream transport or over HTTP.
///
/// [`connect`](PushSession::connect) opens a session over ssh or HTTP, and
/// [`prepare`](PushSession::prepare) checks the transport before the open.
/// [`over_stream`](PushSession::over_stream) opens a session over a pair of
/// byte streams.
///
/// If the caller drops a session without [`commit`](PushSession::commit) or
/// [`abort`](PushSession::abort), the session sends nothing more. A stream
/// transport then closes its output, so the server reads the end of the
/// stream. Over HTTP, the server ends the session when its idle timeout ends.
///
/// # Verification
///
/// The session does not verify the objects that it sends. It computes no
/// checksum and checks no size. The server verifies each object when it
/// arrives. If a source fails while the session sends an object, the session
/// abandons the object with the abandon marker and ends the session with
/// `Abort`.
///
/// # Concurrent calls
///
/// The session is `Send + Sync`. On a stream transport, the session runs one
/// call at a time. A call to [`missing`](PushSession::missing) or
/// [`send`](PushSession::send) while another call runs fails at once with
/// [`Error::InvalidInput`].
///
/// Over HTTP, several [`send`](PushSession::send) calls can run at the same
/// time, and a [`missing`](PushSession::missing) call can run beside them. A
/// second `missing` call while one runs fails at once with
/// [`Error::InvalidInput`].
///
/// On both transports, a call that fails, or whose future the caller drops
/// before it completes, leaves the session broken. Each later call then fails
/// with [`Error::InvalidInput`]. If `missing` or `send` refuses an argument,
/// the call sends nothing and the session stays usable.
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

/// Asks `source` for the content bytes of the file objects of `names`, sent
/// at `level`, and adds them to the byte total of `counters`. A session with
/// no caller's handle, and names with no file object, ask nothing. An
/// unknown size and a failure add nothing.
async fn count_content_total(
    counters: &Counters,
    source: &dyn ObjectSource,
    names: &[ObjectName],
    level: Option<u8>,
) {
    if !counters.has_caller() || !names.iter().any(|n| n.ty == ObjectType::File) {
        return;
    }
    let encoding = match level {
        Some(_) => Encoding::Deflate,
        None => Encoding::Raw,
    };
    if let Ok(Some(total)) = source.content_size(names, encoding).await {
        counters.content_total(total);
    }
}

/// Refuses a name of a type that `Have` and the objects of a source cannot
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

/// Takes the stream of `slot` for one call.
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

/// The open of a session over a pair of byte streams, and its calls.
impl PushSession {
    /// Opens a session over a pair of byte streams.
    ///
    /// `input` comes from the server, and `output` goes to the server. The
    /// session sends `Hello` with `refs`, the refs that it intends to update,
    /// and reads `HelloReply`.
    ///
    /// The caller owns the liveness of the two streams. The session puts no
    /// time limit on a read. A peer that stays silent keeps a call waiting
    /// until the caller drops its future or closes the streams.
    ///
    /// A session over a stream uses the `futures-io` traits alone, so it needs
    /// no async runtime.
    ///
    /// # Errors
    ///
    /// - An `Error` message from the server, as the [`Error`] variant of its
    ///   code, for example [`Error::VersionUnsupported`].
    /// - [`Error::Protocol`] if the version of `HelloReply` is not the version
    ///   of the session, or if its refs are not the refs of `Hello` in order.
    /// - [`Error::Protocol`] for a malformed frame, or for a reply that is not
    ///   `HelloReply`.
    /// - [`Error::LimitExceeded`] for a frame over the frame limit.
    /// - [`Error::Io`] for a failure of a stream. An end of `input` before
    ///   the reply has the kind `UnexpectedEof`.
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

    /// Opens a session over `input` and `output`. `pending_limit` bounds the
    /// wait for a pending message after a failed write.
    pub(crate) async fn open(
        input: stream::Input,
        output: stream::Output,
        refs: &[String],
        opts: SessionOptions,
        pending_limit: Option<Duration>,
    ) -> Result<PushSession> {
        let counters = Arc::new(Counters::new(opts.progress.as_ref()));
        counters.phase(PushPhase::Connecting);
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
                one_way: false,
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

    /// Opens a session over HTTP at `endpoint`: sends `Hello` with `refs` and
    /// reads `HelloReply`.
    pub(crate) async fn open_http(
        endpoint: Endpoint,
        refs: &[String],
        opts: SessionOptions,
    ) -> Result<PushSession> {
        let counters = Arc::new(Counters::new(opts.progress.as_ref()));
        counters.phase(PushPhase::Connecting);
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

    /// Attaches the child process the streams of the session belong to.
    pub(crate) fn with_transport(mut self, child: Transport) -> PushSession {
        if let Link::Stream { transport, .. } = &mut self.inner.link {
            *transport = Some(child);
        }
        self
    }

    /// Returns the facts of the server.
    pub fn server(&self) -> &ServerInfo {
        &self.inner.server
    }

    /// Returns the objects of `names` that the server does not hold.
    ///
    /// The order of the result is the order of `names`. The session sends
    /// `Have` messages of at most `max-have` names each. A `Have` also holds
    /// no more names than its frame can hold within `max-frame`.
    ///
    /// Over HTTP, each `Have` is one request. The session sends the next
    /// `Have` after the response to the one before it.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if the type of a name is not a file, a
    ///   dirtree, a dirmeta, or a commit. The call sends nothing, and the
    ///   session stays usable.
    /// - [`Error::InvalidInput`] if another call runs, as the rules of
    ///   [concurrent calls](PushSession#concurrent-calls) state, or if the
    ///   session is broken.
    /// - An `Error` message from the server, as the [`Error`] variant of its
    ///   code.
    /// - [`Error::Protocol`] for a malformed reply, for a reply that is not
    ///   `HaveReply`, or for a `HaveReply` whose length does not match its
    ///   `Have`.
    /// - [`Error::LimitExceeded`] on a stream transport, for a frame over the
    ///   frame limit.
    /// - [`Error::Io`] for a failure of the stream, or for a failed read of a
    ///   response body over HTTP.
    /// - [`Error::Fetch`] over HTTP, for a failure of the HTTP client.
    /// - [`Error::Transport`] over HTTP, for a status that the endpoint does
    ///   not give, or for a body that is not one frame.
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

    /// Sends the objects `names` from `source`, then the detached metadata of
    /// `commits`.
    ///
    /// On a stream transport, the objects go in one object stream. The call
    /// sends the detached metadata of each commit in `commits` that has
    /// detached metadata, if the session did not send it before. `commits`
    /// holds the commits of `names` and the new value of each ref update, also
    /// if `names` does not hold that commit. A call with nothing to send
    /// writes nothing.
    ///
    /// If the session has a [`PushProgress`] and `names` holds at least one
    /// file object, the call first asks [`ObjectSource::content_size`]. The
    /// answer is the number of content bytes that the call sends.
    ///
    /// # HTTP
    ///
    /// Over HTTP, the call sends the objects in at most `parallel-uploads`
    /// object streams at the same time, and in no more streams than the
    /// objects that it sends. Each object stream is one request, and the
    /// objects of `names` can arrive in another order. The detached metadata
    /// goes in one of the streams, after its objects.
    ///
    /// The object streams of all the calls of the session stay within
    /// `parallel-uploads`, at most 31. A stream waits for a permit. After the
    /// first failure, no stream starts a new object, and each stream reads its
    /// response.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if the level of `compression` is not 1
    ///   through 9, or if the type of a name is not a file, a dirtree, a
    ///   dirmeta, or a commit. The call sends nothing, and the session stays
    ///   usable.
    /// - [`Error::InvalidInput`] if another call runs, as the rules of
    ///   [concurrent calls](PushSession#concurrent-calls) state, or if the
    ///   session is broken.
    /// - [`Error::Source`] if the source fails. The session ends with
    ///   `Abort`.
    /// - [`Error::InvalidInput`] if the source gives data that the session
    ///   cannot send, for example a symlink with a payload. The session ends
    ///   with `Abort`.
    /// - An `Error` message from the server, as the [`Error`] variant of its
    ///   code.
    /// - [`Error::Protocol`] for a malformed reply, or for a reply that is
    ///   not `ObjectsReply`.
    /// - [`Error::LimitExceeded`] on a stream transport, for a frame over the
    ///   frame limit.
    /// - [`Error::Io`] for a failure of the stream, or for a failed read of a
    ///   response body over HTTP.
    /// - [`Error::Fetch`] over HTTP, for a failure of the HTTP client.
    /// - [`Error::Transport`] over HTTP, for a status that the endpoint does
    ///   not give, or for a body that is not one frame.
    ///
    /// If more than one object stream fails over HTTP, the call returns one
    /// error, in this order:
    ///
    /// 1. [`Error::Source`] or [`Error::InvalidInput`], a failure of the client
    /// 2. an error with a wire code, for example an error that the server gave
    ///    for its own cause
    /// 3. any other error, also the [`Error::Protocol`] of a stream that ends
    ///    because the server aborted the session for the failure of another
    ///    stream
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
        let level = level.filter(|_| deflate_ok);
        let upload = Upload::new(
            source,
            names,
            commits,
            level,
            deflate_ok,
            &self.inner.claims,
        );
        let counters = &self.inner.counters;
        let slot = match &self.inner.link {
            Link::Stream { slot, .. } => slot,
            Link::Http(link) => {
                count_content_total(counters, source, names, level).await;
                counters.phase(PushPhase::Uploading);
                return link.send(counters, &upload).await;
            }
        };
        let mut taken = take(slot)?;
        count_content_total(counters, source, names, level).await;
        counters.phase(PushPhase::Uploading);
        taken.stream().upload(&upload).await?;
        taken.release();
        Ok(())
    }

    /// Sends `Commit` with `updates`, and returns the outcome from the reply.
    ///
    /// The call consumes the session. The call sends no `Commit` if it refuses
    /// `updates`, if the session is broken, or if the `Commit` frame is over
    /// the frame limit. On a stream transport it then sends nothing, so the
    /// server reads the end of the stream. Over HTTP, it sends `DELETE`.
    ///
    /// Over ssh, the call then waits for the ssh client to exit, also after a
    /// refusal. The ssh time limits of [`connect`](PushSession::connect) give
    /// the rules of the wait.
    ///
    /// # HTTP
    ///
    /// The client sends the `Commit` request once, and never sends it again.
    /// If the client did not hand the request over to a connection, the
    /// server changed no ref. After the hand-over, these failures are
    /// [`Error::CommitOutcomeUnknown`]:
    ///
    /// - a failure of the request
    /// - a response head that the client refuses, for example for a declared
    ///   coding or for a declared length over the cap
    /// - a failed read of the response
    /// - a status that the endpoint does not give
    /// - a body that is not one frame
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `updates` is empty, names a ref that
    ///   `Hello` did not name, or names a ref twice.
    /// - [`Error::InvalidInput`] if the session is broken.
    /// - [`Error::LimitExceeded`] if the `Commit` frame is over the frame
    ///   limit.
    /// - An `Error` message from the server, as the [`Error`] variant of its
    ///   code. An ostrya server sends it before it changes a ref, with two
    ///   exceptions. A failed write of the refs can leave some refs written,
    ///   and a failure of a hook after the update keeps all the refs.
    /// - [`Error::Fetch`] over HTTP, if the client did not hand the request
    ///   over to a connection.
    /// - [`Error::CommitOutcomeUnknown`] for each other end of the session
    ///   after the session wrote `Commit`. The server can have written the
    ///   refs. A `CommitReply` whose refs are not the refs of `updates` in
    ///   order is one of these cases.
    ///
    /// If the write of `Commit` fails with an I/O error, the session reads one
    /// message. An `Error` message gives the [`Error`] variant of its code,
    /// and a `CommitReply` gives the outcome. Any other result is
    /// [`Error::CommitOutcomeUnknown`].
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

    /// Ends the session, so that the server aborts its transaction.
    ///
    /// On a stream transport, if the stream is usable, the session writes
    /// `Abort` and closes its output. A broken session has no stream, so the
    /// call writes nothing. Over ssh, the call then waits for the ssh client to
    /// exit, as the ssh time limits of [`connect`](PushSession::connect) state.
    ///
    /// Over HTTP, the call sends `DELETE`, also on a broken session. A 204 is
    /// success, and so is a 404, which the server gives for a session that it
    /// ended already.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if the session is broken. Over HTTP, the
    ///   call sends `DELETE` first.
    /// - [`Error::Io`] if the write of `Abort` fails.
    /// - [`Error::Transport`] over ssh, if the write of `Abort` fails with an
    ///   I/O error and the ssh client exits with a failure status. The error
    ///   names the status.
    /// - An `Error` message from the server over HTTP, as the [`Error`]
    ///   variant of its code.
    /// - [`Error::Fetch`] over HTTP, for a failure of the HTTP client.
    /// - [`Error::Transport`] over HTTP, for a status that the endpoint does
    ///   not give, or for a body that is not one frame.
    /// - [`Error::Io`] over HTTP, for a failed read of the response body.
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
    /// Takes the session apart to commit `updates`, which `checked` checked.
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

/// Refuses empty `updates`, a ref that is not in `refs`, and a ref named
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

/// Ends a session with `result`. A session with a transport waits for it to
/// finish. The stream of the session must be closed or dropped first.
async fn finish<T>(transport: Option<Transport>, result: Result<T>) -> Result<T> {
    match transport {
        Some(transport) => transport.finish(result).await,
        None => result,
    }
}

/// Sends `Commit` over `stream` and reads the reply. The stream is closed or
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
