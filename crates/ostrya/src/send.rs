//! One pull session over a pair of streams: the serving side of the pull over
//! ssh.

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::sync::Arc;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::{AsyncReadExt, BufReader, BufWriter};
use ostrya_core::RefSelector;

use crate::access::ReadAccess;
use crate::archive::{ArchiveAnswer, ArchiveView};
use crate::error::{Error, Result};
use crate::remote;
use crate::remote::proto::{
    FrameReader, FrameWriter, GetReply, ListRefsRequest, MAX_REF_ENTRY_LEN, MAX_REF_ENTRY_PARTS,
    MAX_REF_LISTING, MAX_REF_PATTERNS, Message, PULL_PROTOCOL_VERSION, PullHello, PullHelloReply,
};
use crate::repo::Repo;

/// The buffer size of each direction of the session stream.
const STREAM_BUFFER: usize = 64 * 1024;

/// The payload size of each chunk of a body, except the last chunk.
///
/// Each write to the output is at most [`STREAM_BUFFER`] bytes, because a
/// full chunk and its 4-byte length fill the output buffer. No write holds a
/// chunk length alone.
const CHUNK: usize = STREAM_BUFFER - 4;

/// The callback that receives each [`SendEvent`] of a session.
///
/// The session calls it in its own task, so the callback must return soon.
pub type SendEventFn = Arc<dyn Fn(&SendEvent) + Send + Sync>;

/// The options of [`Repo::send_with`].
///
/// The struct is `#[non_exhaustive]`, so a caller starts from
/// [`SendOptions::default`] and sets the fields.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct SendOptions {
    /// The callback for each [`SendEvent`] of the session, or `None`.
    ///
    /// A host writes the event to its log, for example the
    /// [`Display`](fmt::Display) text of the event on standard error. The
    /// default is `None`, which drops each event.
    pub on_event: Option<SendEventFn>,
}

/// The debug text shows a callback that is set as `<callback>`.
impl fmt::Debug for SendOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendOptions")
            .field("on_event", &self.on_event.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

/// An event of a session of [`Repo::send_with`], which
/// [`SendOptions::on_event`] receives.
///
/// [`Display`](fmt::Display) writes one line for the log of the host. It
/// writes each ASCII control character of a name as an escape sequence, for
/// example `\n`, so the line holds no line break.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendEvent {
    /// A ref listing of the session left out a directory under
    /// `refs/mirrors/` whose name fails the collection-id rule
    /// ([`is_collection_id`](crate::is_collection_id)).
    ///
    /// The session reports each name one time, at the first listing that
    /// finds it. Only a `ListRefs` with the `collections` key reads the
    /// directories under `refs/mirrors/`.
    #[non_exhaustive]
    InvalidCollectionDir {
        /// The name of the directory.
        name: String,
    },
    /// The session answered `summary` or `summary.sig` as an absent path,
    /// because the `.access` file of the item of the client does not hold
    /// the access digest of the item ([`ArchiveAnswer::StaleSummary`]).
    ///
    /// The summary of the item does not match the client groups. The session
    /// reports the event one time, at the first request that finds it.
    #[non_exhaustive]
    StaleSummary {
        /// The text of the auth item of the client.
        item: String,
    },
}

impl SendEvent {
    /// Returns `true` if the event is a warning: the session served the
    /// request. Each other event is an error of a request that the session
    /// did not serve.
    ///
    /// [`InvalidCollectionDir`](SendEvent::InvalidCollectionDir) is a
    /// warning, and [`StaleSummary`](SendEvent::StaleSummary) is an error.
    pub fn is_warning(&self) -> bool {
        match self {
            SendEvent::InvalidCollectionDir { .. } => true,
            SendEvent::StaleSummary { .. } => false,
        }
    }
}

impl fmt::Display for SendEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendEvent::InvalidCollectionDir { name } => {
                f.write_str("refs/mirrors/")?;
                write_escaped(f, name)?;
                f.write_str(
                    ": the directory name is not a collection id, and the ref listing leaves \
                     out the directory",
                )
            }
            SendEvent::StaleSummary { item } => {
                f.write_str("the summary of the auth item ")?;
                write_escaped(f, item)?;
                f.write_str(
                    " does not match the client groups, and the session does not serve it; \
                     run `ostrya summary -u`",
                )
            }
        }
    }
}

/// Writes `text` with each ASCII control character as its escape sequence.
fn write_escaped(f: &mut fmt::Formatter<'_>, text: &str) -> fmt::Result {
    for c in text.chars() {
        if c.is_ascii_control() {
            write!(f, "{}", c.escape_default())?;
        } else {
            write!(f, "{c}")?;
        }
    }
    Ok(())
}

/// The kind of failure that ends a session.
enum Failure {
    /// A failure with a wire code. The session sends it to the peer. The
    /// caller gets it as [`Error::Remote`].
    Wire(remote::Error),
    /// A failure on the server side. The session sends it to the peer as
    /// `internal`. The caller gets the error unchanged.
    Internal(Error),
    /// A body that failed after its reply. The session wrote the abandon
    /// marker and the `Error` frame before it made this value. The caller
    /// gets the error unchanged.
    Abandoned(Error),
    /// A failure of the output. The session sends nothing.
    Silent(Error),
}

/// Maps a codec error of the reader to a failure.
///
/// An end of file inside a frame is `protocol`. Another error of the input
/// stream is a failure of the server. Every other error keeps its wire code.
fn input(error: remote::Error) -> Failure {
    match error {
        remote::Error::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => Failure::Wire(
            remote::Error::Protocol("the input ended inside a frame".to_owned()),
        ),
        remote::Error::Io(e) => Failure::Internal(Error::Io(e)),
        other => Failure::Wire(other),
    }
}

/// Maps an error of the writer to a failure.
///
/// An error of the output stream is silent. If the codec refuses a message,
/// the failure is `internal`, whatever code the codec gives. The refusal is a
/// fault of the server.
fn output(error: remote::Error) -> Failure {
    match error {
        remote::Error::Io(e) => Failure::Silent(Error::Io(e)),
        other => Failure::Wire(remote::Error::Internal(other.to_string())),
    }
}

fn out_of_order(msg: &Message) -> Failure {
    Failure::Wire(remote::Error::Protocol(format!(
        "{:?} is out of order",
        msg.kind()
    )))
}

/// Returns the `GetReply` of a path that the session does not serve.
fn not_found() -> Message {
    Message::GetReply(GetReply {
        found: false,
        len: None,
    })
}

/// Returns `true` if `buf` starts with a whole frame.
///
/// A whole frame is its 4-byte length and that number of bytes.
fn complete_frame(buf: &[u8]) -> bool {
    match buf.first_chunk::<4>() {
        Some(prefix) => buf.len() - 4 >= u32::from_be_bytes(*prefix) as usize,
        None => false,
    }
}

/// Methods that serve a pull session.
impl Repo {
    /// Serves one pull session over the streams `input` and `output`, with
    /// the read rights `access`.
    ///
    /// The session reads a `PullHello` message and then `Get` and `ListRefs`
    /// messages of a client from `input`. It writes the replies and the bodies
    /// to `output`. This method is the serving side of a pull over ssh. It
    /// does not close `output`.
    ///
    /// # Requests
    ///
    /// The session answers each `Get` through one [`ArchiveView`] of this
    /// repository, with `access`. All requests of the session share the
    /// parsed `config` and the idle compressors of the view. The session reads
    /// one `Get`, answers it to the end of its body, and then reads the next
    /// request.
    ///
    /// - If the view does not find the path, or refuses it, the reply is a
    ///   `GetReply` with `found` set to `false`. The session continues.
    /// - If the view serves the path, the reply is a `GetReply` with `found`
    ///   set to `true`. The reply holds the length if the view knows it. The
    ///   body follows as chunks.
    ///
    /// The session answers each `ListRefs` with the listing that
    /// [`build_ref_listing`](Repo::build_ref_listing) builds for its two
    /// lists of entries and `access`. The entries of field 0 select the local
    /// refs. The entries under the key `collections` select the collection
    /// refs, and with no such key the listing holds no collection ref.
    /// The entries are ref patterns with an optional leading `!`, which
    /// [`RefSelector::parse`] reads. A `ListRefs` holds at most
    /// [`MAX_REF_PATTERNS`] entries in its two lists together, and each entry
    /// holds at most [`MAX_REF_ENTRY_PARTS`] parts and [`MAX_REF_ENTRY_LEN`]
    /// bytes. The reply is a `GetReply` with `found` set to `true` and the
    /// length of the listing. The listing follows as chunks.
    ///
    /// # Access
    ///
    /// `access` gives the refs that the session serves. A ref that `access`
    /// does not read, and a path under `refs/` that names no ref, get a
    /// `GetReply` with `found` set to `false`, as an absent path does. The
    /// listing of `ListRefs` holds the refs that `access` reads. `summary`
    /// and `summary.sig` give the files of the summary of the item of
    /// `access`, by the rules of [`ArchiveView`](crate::ArchiveView#read-access).
    /// An item with no summary, and a summary whose `.access` file does not
    /// match, get `found` set to `false`.
    ///
    /// The session opens no transaction and takes no lock. For an `archive`,
    /// `bare-user`, `bare-user-only`, or `bare-user-shared` repository, read
    /// access to the repository is sufficient. For a `bare` or
    /// `bare-split-xattrs` repository, the account must be able to read every
    /// object and its extended attributes.
    ///
    /// # Framing and memory
    ///
    /// The frame limit is [`MIN_FRAME_LIMIT`](crate::remote::proto::MIN_FRAME_LIMIT)
    /// in the two directions. Each direction goes through a buffer of 64 KiB.
    /// Each chunk of a body, except the last chunk, holds 64 KiB less 4 bytes.
    ///
    /// A body streams through one chunk buffer, so no content object is whole
    /// in memory. For a stored file, the session reads at most one byte past
    /// the stated length. A ref listing is whole in memory, up to
    /// [`MAX_REF_LISTING`] bytes.
    ///
    /// The memory of a session is the two stream buffers, the chunk buffer,
    /// one `Get` frame, and the reader of the current body. That reader is a
    /// `FileReader` with a read-ahead of 4 KiB to 256 KiB, or a compressor and
    /// two buffers of 64 KiB for a built `.filez`. A `Get` frame at the frame
    /// limit adds about 2 MiB, because the frame body and the decoded path are
    /// in memory at the same time.
    ///
    /// If the input buffer holds no whole frame, the next read can wait. The
    /// session flushes `output` before that read. It also flushes `output`
    /// after each `Error` message.
    ///
    /// # End of a session
    ///
    /// At an end of file of `input` at a frame boundary, the method returns
    /// `Ok`. An empty `input` also gives `Ok`. Every other end of the session
    /// is an error. The session tells the peer about the failure:
    ///
    /// - If the failure has a wire code, the session sends an `Error` message
    ///   with that code.
    /// - If the view fails before the reply, the session sends an `Error`
    ///   message with the code `internal` in place of the reply. A file that
    ///   the process cannot read is an example.
    /// - If a read of `input` fails with an error other than an end of file,
    ///   the session sends an `Error` message with the code `internal`.
    /// - If a body fails after its reply, the session ends the body with the
    ///   abandon marker and an `Error` message with the code `internal`.
    /// - If a write of a reply or of a body to `output` fails, the session
    ///   sends nothing more.
    ///
    /// If the session cannot deliver the `Error` message, the returned error
    /// does not change.
    ///
    /// # Errors
    ///
    /// - [`Error::Remote`] with the code `version-unsupported` if the
    ///   `PullHello` states version 0.
    /// - [`Error::Remote`] with the code `protocol` if a message is out of
    ///   order or is a kind of the push.
    /// - [`Error::Remote`] with the code `protocol` if a frame is malformed, or
    ///   if `input` ends inside a frame.
    /// - [`Error::Remote`] with the code `protocol` if a `ListRefs` holds more
    ///   than [`MAX_REF_PATTERNS`] entries in its two lists, an entry over the
    ///   limits of one entry, or an entry that [`RefSelector::parse`]
    ///   refuses. An entry given two times counts two times. The check of the
    ///   limits of an entry comes before the parse. The message of a refused
    ///   entry under `collections` names that key.
    /// - [`Error::Remote`] with the code `limit-exceeded` if a ref listing is
    ///   larger than [`MAX_REF_LISTING`].
    /// - [`Error::Remote`] with the code `limit-exceeded` if a frame is larger
    ///   than the limit.
    /// - [`Error::Remote`] with the code `internal` if the codec refuses a
    ///   message that the session writes.
    /// - Each error of [`ArchiveView::get`] if the view fails before the
    ///   reply.
    /// - Each other error of [`build_ref_listing`](Repo::build_ref_listing).
    ///   The session sends it as `internal`.
    /// - [`Error::Io`] if a read of `input` fails with an error other than an
    ///   end of file.
    /// - [`Error::Io`] with the error of the read if a body fails after its
    ///   reply. For a stored file that ends before its stated length, the
    ///   kind is `UnexpectedEof`. For a stored file that holds more, the kind
    ///   is `InvalidData`.
    /// - [`Error::Io`] if a write of a reply or of a body to `output` fails.
    pub async fn send<R, W>(&self, input: R, output: W, access: &ReadAccess) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        self.send_with(input, output, access, &SendOptions::default())
            .await
    }

    /// Serves one pull session as [`send`](Repo::send) does, with the
    /// options `opts`.
    ///
    /// The session gives each [`SendEvent`] to
    /// [`SendOptions::on_event`]. A ref listing of a `ListRefs` with the
    /// `collections` key reads the top level of `refs/mirrors/`. For each
    /// directory there whose name fails the collection-id rule, the session
    /// gives one [`SendEvent::InvalidCollectionDir`], at the first listing
    /// that finds it. The listing leaves out the directory. The event does
    /// not change the session, and the peer gets no message of it.
    ///
    /// When the view answers `summary` or `summary.sig` with
    /// [`ArchiveAnswer::StaleSummary`], the session gives one
    /// [`SendEvent::StaleSummary`], at the first such answer. The peer gets a
    /// `GetReply` with `found` set to `false`, as for an absent path.
    ///
    /// # Errors
    ///
    /// The errors of [`send`](Repo::send).
    pub async fn send_with<R, W>(
        &self,
        input: R,
        output: W,
        access: &ReadAccess,
        opts: &SendOptions,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        self.send_capped(input, output, access, opts, MAX_REF_LISTING)
            .await
    }

    /// Serves the session of [`send_with`](Repo::send_with) with a cap of
    /// `listing_cap` bytes on each ref listing.
    pub(crate) async fn send_capped<R, W>(
        &self,
        input: R,
        output: W,
        access: &ReadAccess,
        opts: &SendOptions,
        listing_cap: u64,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let mut session = Session {
            repo: self.clone(),
            access: access.clone(),
            listing_cap,
            on_event: opts.on_event.clone(),
            warned: HashSet::new(),
            stale_reported: false,
            view: ArchiveView::new(self.clone()),
            reader: FrameReader::new(BufReader::with_capacity(STREAM_BUFFER, input)),
            writer: FrameWriter::new(BufWriter::with_capacity(STREAM_BUFFER, output)),
            chunk: Vec::new(),
        };
        let failure = match session.run().await {
            Ok(()) => return Ok(()),
            Err(failure) => failure,
        };
        Err(match failure {
            Failure::Wire(e) => {
                session.send_error(&e).await;
                Error::Remote(e)
            }
            Failure::Internal(e) => {
                session
                    .send_error(&remote::Error::Internal(e.to_string()))
                    .await;
                e
            }
            Failure::Abandoned(e) => {
                let _ = session.writer.flush().await;
                e
            }
            Failure::Silent(e) => e,
        })
    }
}

struct Session<R, W> {
    repo: Repo,
    /// The read rights of the client.
    access: ReadAccess,
    /// The size cap of each ref listing.
    listing_cap: u64,
    /// The callback of the events of the session.
    on_event: Option<SendEventFn>,
    /// The names of the invalid collection directories that the session
    /// reported.
    warned: HashSet<String>,
    /// `true` once the session reported a stale summary.
    stale_reported: bool,
    view: ArchiveView,
    reader: FrameReader<BufReader<R>>,
    writer: FrameWriter<BufWriter<W>>,
    /// The chunk buffer of the bodies. Every body of the session uses it.
    chunk: Vec<u8>,
}

impl<R, W> Session<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    /// Runs the session until the input ends or the session fails.
    async fn run(&mut self) -> std::result::Result<(), Failure> {
        match self.next().await? {
            Some(Message::PullHello(hello)) => self.hello(hello).await?,
            Some(other) => return Err(out_of_order(&other)),
            None => return Ok(()),
        }
        loop {
            // The futures of the reader are not cancel-safe. To learn if the
            // next read can wait, the loop reads the buffer and polls no read.
            if !complete_frame(self.reader.get_ref().buffer()) {
                self.writer.flush().await.map_err(output)?;
            }
            match self.next().await? {
                Some(Message::Get(path)) => self.get(&path).await?,
                Some(Message::ListRefs(request)) => self.list_refs(&request).await?,
                Some(other) => return Err(out_of_order(&other)),
                None => return Ok(()),
            }
        }
    }

    async fn next(&mut self) -> std::result::Result<Option<Message>, Failure> {
        self.reader.read_message().await.map_err(input)
    }

    /// Writes one message. The flush rule of the loop in `run` flushes it.
    async fn reply(&mut self, msg: &Message) -> std::result::Result<(), Failure> {
        self.writer.write_message(msg).await.map_err(output)
    }

    /// Sends an `Error` message and flushes the output.
    ///
    /// The method ignores a failure to send the message, because the peer can
    /// be gone.
    async fn send_error(&mut self, error: &remote::Error) {
        let msg = Message::Error(error.to_message());
        if self.writer.write_message(&msg).await.is_ok() {
            let _ = self.writer.flush().await;
        }
    }

    /// Replies with the lower of the client version and the highest server
    /// version.
    ///
    /// The server speaks each version from 1 up.
    async fn hello(&mut self, hello: PullHello) -> std::result::Result<(), Failure> {
        if hello.version == 0 {
            return Err(Failure::Wire(remote::Error::VersionUnsupported(format!(
                "pull protocol version 0: the server speaks versions 1 to {PULL_PROTOCOL_VERSION}"
            ))));
        }
        let version = hello.version.min(PULL_PROTOCOL_VERSION);
        self.reply(&Message::PullHelloReply(PullHelloReply { version }))
            .await
    }

    /// Answers one `Get`.
    ///
    /// The method drops the body before the next `Get`, so a built `.filez`
    /// gives its compressor back to the view first.
    async fn get(&mut self, path: &str) -> std::result::Result<(), Failure> {
        let answer = self
            .view
            .get(path, &self.access)
            .await
            .map_err(Failure::Internal)?;
        let found = |len| Message::GetReply(GetReply { found: true, len });
        match answer {
            ArchiveAnswer::Bytes(bytes) => {
                self.reply(&found(Some(bytes.len() as u64))).await?;
                write_bytes(&mut self.writer, &bytes).await
            }
            ArchiveAnswer::Stream { len, body } => {
                self.reply(&found(len)).await?;
                write_body(&mut self.writer, &mut self.chunk, len, body).await
            }
            ArchiveAnswer::StaleSummary { item } => {
                if let Some(on_event) = &self.on_event
                    && !self.stale_reported
                {
                    self.stale_reported = true;
                    on_event(&SendEvent::StaleSummary {
                        item: item.to_string(),
                    });
                }
                self.reply(&not_found()).await
            }
            ArchiveAnswer::NotFound | ArchiveAnswer::Refused => self.reply(&not_found()).await,
        }
    }

    /// Answers one `ListRefs` with the listing of `request`.
    ///
    /// Each failure comes before the reply, so the session sends an `Error`
    /// message in place of the reply. The session reports each invalid
    /// collection directory of the listing that it did not report before.
    async fn list_refs(&mut self, request: &ListRefsRequest) -> std::result::Result<(), Failure> {
        let protocol = |why: String| Failure::Wire(remote::Error::Protocol(why));
        let collections = request.collections.as_deref();
        let count = request.refs.len() + collections.map_or(0, <[String]>::len);
        if count > MAX_REF_PATTERNS {
            return Err(protocol(format!(
                "ListRefs: {count} entries, over the limit of {MAX_REF_PATTERNS}"
            )));
        }
        let lists = [
            ("", request.refs.as_slice()),
            ("collections: ", collections.unwrap_or_default()),
        ];
        for (label, entries) in lists {
            for entry in entries {
                if entry.len() > MAX_REF_ENTRY_LEN || entry.split('/').count() > MAX_REF_ENTRY_PARTS
                {
                    return Err(protocol(format!(
                        "ListRefs: {label}an entry of {} bytes is over the limit of \
                         {MAX_REF_ENTRY_PARTS} parts or {MAX_REF_ENTRY_LEN} bytes",
                        entry.len()
                    )));
                }
            }
        }
        let refs = RefSelector::parse(request.refs.iter().map(String::as_str))
            .map_err(|e| protocol(format!("ListRefs: {e}")))?;
        let collections = collections
            .map(|entries| RefSelector::parse(entries.iter().map(String::as_str)))
            .transpose()
            .map_err(|e| protocol(format!("ListRefs: collections: {e}")))?;
        let listing = self
            .repo
            .build_ref_listing_capped(&refs, collections.as_ref(), &self.access, self.listing_cap)
            .await
            .map_err(|e| match e {
                Error::Remote(e @ remote::Error::LimitExceeded(_)) => Failure::Wire(e),
                other => Failure::Internal(other),
            })?;
        for name in listing.invalid_collection_dirs {
            if let Some(on_event) = &self.on_event
                && !self.warned.contains(&name)
            {
                self.warned.insert(name.clone());
                on_event(&SendEvent::InvalidCollectionDir { name });
            }
        }
        let reply = GetReply {
            found: true,
            len: Some(listing.bytes.len() as u64),
        };
        self.reply(&Message::GetReply(reply)).await?;
        write_bytes(&mut self.writer, &listing.bytes).await
    }
}

/// Writes `bytes` as the chunks of a pull body, and ends the body.
///
/// The chunks have the shape that [`write_body`] gives.
async fn write_bytes<W: AsyncWrite + Unpin>(
    writer: &mut FrameWriter<W>,
    bytes: &[u8],
) -> std::result::Result<(), Failure> {
    for chunk in bytes.chunks(CHUNK) {
        writer.write_object_data(chunk).await.map_err(output)?;
    }
    writer.end_object().await.map_err(output)
}

/// Writes `body` as the chunks of a pull body, and ends the body.
///
/// Each chunk except the last chunk is full. If `len` is set, the function
/// reads at most `len + 1` bytes. It abandons a body that ends sooner or
/// holds more.
async fn write_body<W, B>(
    writer: &mut FrameWriter<W>,
    chunk: &mut Vec<u8>,
    len: Option<u64>,
    body: B,
) -> std::result::Result<(), Failure>
where
    W: AsyncWrite + Unpin,
    B: AsyncRead + Unpin,
{
    if chunk.is_empty() {
        chunk.resize(CHUNK, 0);
    }
    let mut body = body.take(len.map_or(u64::MAX, |len| len.saturating_add(1)));
    let mut total = 0u64;
    loop {
        let n = match fill(&mut body, chunk).await {
            Ok(n) => n,
            Err(e) => return abandon(writer, Error::Io(e)).await,
        };
        total += n as u64;
        if let Some(len) = len {
            if total > len {
                let e = io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the file holds more than its stated length",
                );
                return abandon(writer, Error::Io(e)).await;
            }
            if n < CHUNK && total < len {
                let e = io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the file ended before its stated length",
                );
                return abandon(writer, Error::Io(e)).await;
            }
        }
        if n > 0 {
            writer
                .write_object_data(&chunk[..n])
                .await
                .map_err(output)?;
        }
        if n < CHUNK {
            return writer.end_object().await.map_err(output);
        }
    }
}

/// Reads from `body` until `chunk` is full or the body ends.
///
/// A built `.filez` gives its header alone in the first read. Its deflate
/// stream gives the output in bursts. Because of this, one read seldom fills
/// the chunk.
async fn fill<B: AsyncRead + Unpin>(body: &mut B, chunk: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < chunk.len() {
        match body.read(&mut chunk[filled..]).await? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Abandons the body with the abandon marker and an `Error` with `internal`.
async fn abandon<W: AsyncWrite + Unpin>(
    writer: &mut FrameWriter<W>,
    error: Error,
) -> std::result::Result<(), Failure> {
    let msg = remote::Error::Internal(error.to_string()).to_message();
    writer.abandon_body(&msg).await.map_err(output)?;
    Err(Failure::Abandoned(error))
}

/// A compile-time check that the future of a session is `Send`.
///
/// The future can run on a thread pool.
const _: fn() = || {
    fn assert_send<T: Send>(_: T) {}
    let _ = |repo: &Repo, access: &ReadAccess| {
        assert_send(repo.send(futures_lite::io::empty(), futures_lite::io::sink(), access))
    };
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SendOptions>();
    assert_send_sync::<SendEvent>();
};

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures_lite::future::block_on;

    use super::*;
    use crate::remote::ErrorCode;
    use crate::remote::proto::ObjectRead;

    /// A reader that gives `ok` bytes of `0x5a` and then fails.
    ///
    /// If `ok` is `None`, the reader never ends. `read` counts the bytes that
    /// the reader gave.
    struct Source {
        ok: Option<usize>,
        read: usize,
    }

    impl AsyncRead for Source {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let left = self.ok.map_or(usize::MAX, |ok| ok - self.read);
            if left == 0 {
                return Poll::Ready(Err(io::Error::other("the disk failed")));
            }
            // Short reads, as a pipe or a deflate stream gives them.
            let n = buf.len().min(left).min(10_000);
            buf[..n].fill(0x5a);
            self.read += n;
            Poll::Ready(Ok(n))
        }
    }

    /// Writes one found reply of `len` and its body from `body` into a
    /// buffer.
    ///
    /// Returns the result and the bytes written.
    fn serve<B: AsyncRead + Unpin>(
        len: Option<u64>,
        body: B,
    ) -> (std::result::Result<(), Failure>, Vec<u8>) {
        let mut writer = FrameWriter::new(Vec::new());
        let mut chunk = Vec::new();
        let result = block_on(async {
            let reply = GetReply { found: true, len };
            writer
                .write_message(&Message::GetReply(reply))
                .await
                .unwrap();
            write_body(&mut writer, &mut chunk, len, body).await
        });
        (result, writer.into_inner())
    }

    /// Returns the chunk lengths after the reply frame at the start of
    /// `bytes`.
    ///
    /// The list ends with the chunk of length 0 or the abandon marker.
    fn chunk_lengths(bytes: &[u8]) -> Vec<u32> {
        let frame = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let mut at = 4 + frame;
        let mut lengths = Vec::new();
        loop {
            let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
            lengths.push(len);
            if len == 0 || len == crate::remote::proto::ABANDON {
                return lengths;
            }
            at += 4 + len as usize;
        }
    }

    /// A reader that fails partway ends the body with the abandon marker
    /// and an `Error` with `internal`. The session writes the full chunk
    /// before the failure and no byte after it.
    #[test]
    fn a_reader_that_fails_partway_abandons_the_body() {
        let (result, bytes) = serve(
            None,
            Source {
                ok: Some(100_000),
                read: 0,
            },
        );
        let Err(Failure::Abandoned(Error::Io(e))) = result else {
            panic!("the body was not abandoned");
        };
        assert_eq!(e.to_string(), "the disk failed");
        assert_eq!(
            chunk_lengths(&bytes),
            [CHUNK as u32, crate::remote::proto::ABANDON]
        );

        let mut reader = FrameReader::new(&bytes[..]);
        block_on(async {
            let reply = reader.read_message().await.unwrap();
            assert_eq!(
                reply,
                Some(Message::GetReply(GetReply {
                    found: true,
                    len: None
                }))
            );
            let mut buf = vec![0u8; 200_000];
            let mut got = 0;
            let err = loop {
                match reader.read_object_data(&mut buf).await {
                    Ok(ObjectRead::Data(n)) => got += n,
                    Ok(other) => panic!("the body ended with {other:?}"),
                    Err(e) => break e,
                }
            };
            assert_eq!(got, CHUNK);
            assert_eq!(err.code(), Some(ErrorCode::Internal));
            assert_eq!(err.to_message().message, "i/o error: the disk failed");
            assert_eq!(reader.read_message().await.unwrap(), None);
        });
    }

    /// Each chunk except the last chunk is full. A body of a whole number of
    /// chunks ends with the chunk of length 0 alone.
    #[test]
    fn each_chunk_but_the_last_is_full() {
        for (size, expected) in [
            (0, vec![0]),
            (1, vec![1, 0]),
            (CHUNK, vec![CHUNK as u32, 0]),
            (2 * CHUNK + 1, vec![CHUNK as u32, CHUNK as u32, 1, 0]),
        ] {
            for len in [None, Some(size as u64)] {
                let (result, bytes) = serve(len, &vec![7u8; size][..]);
                assert!(result.is_ok(), "{size} {len:?}");
                assert_eq!(chunk_lengths(&bytes), expected, "{size} {len:?}");
            }
        }
    }

    /// Bytes in memory go out as the chunks that a body of the same bytes
    /// gives.
    #[test]
    fn bytes_take_the_chunks_of_a_body() {
        for size in [0, 1, CHUNK, CHUNK + 1, 2 * CHUNK + 1] {
            let data = vec![7u8; size];
            let len = Some(size as u64);
            let (result, expected) = serve(len, &data[..]);
            assert!(result.is_ok(), "{size}");
            let mut writer = FrameWriter::new(Vec::new());
            let result = block_on(async {
                let reply = GetReply { found: true, len };
                writer
                    .write_message(&Message::GetReply(reply))
                    .await
                    .unwrap();
                write_bytes(&mut writer, &data).await
            });
            assert!(result.is_ok(), "{size}");
            assert_eq!(writer.into_inner(), expected, "{size}");
        }
    }

    /// A stated length limits the read to one byte past it. The session
    /// abandons a body that ends sooner or holds more, with the error of its
    /// kind.
    #[test]
    fn a_stated_length_bounds_the_read() {
        let mut source = Source { ok: None, read: 0 };
        let (result, bytes) = serve(Some(10), &mut source);
        let Err(Failure::Abandoned(Error::Io(e))) = result else {
            panic!("a long body was not abandoned");
        };
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert_eq!(source.read, 11);
        assert_eq!(chunk_lengths(&bytes), [crate::remote::proto::ABANDON]);

        let (result, bytes) = serve(Some(20), &[1u8; 10][..]);
        let Err(Failure::Abandoned(Error::Io(e))) = result else {
            panic!("a short body was not abandoned");
        };
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(chunk_lengths(&bytes), [crate::remote::proto::ABANDON]);

        // The next read finds a body that falls short at a chunk boundary.
        let (result, bytes) = serve(Some(CHUNK as u64 + 1), &vec![1u8; CHUNK][..]);
        assert!(matches!(result, Err(Failure::Abandoned(_))));
        assert_eq!(
            chunk_lengths(&bytes),
            [CHUNK as u32, crate::remote::proto::ABANDON]
        );
    }

    #[test]
    fn a_complete_frame_is_its_length_and_its_bytes() {
        assert!(!complete_frame(&[]));
        assert!(!complete_frame(&[0, 0, 0]));
        assert!(!complete_frame(&[0, 0, 0, 2, 14]));
        assert!(complete_frame(&[0, 0, 0, 2, 14, 0]));
        assert!(complete_frame(&[0, 0, 0, 2, 14, 0, 0]));
        assert!(!complete_frame(&[0xff, 0xff, 0xff, 0xff, 0]));
        // A frame of length 0 is whole. The reader refuses it.
        assert!(complete_frame(&[0, 0, 0, 0]));
    }

    /// A ref listing over the cap of the session is `limit-exceeded` in place
    /// of the reply. A listing of exactly the cap goes out whole.
    #[test]
    fn a_ref_listing_over_the_cap_is_limit_exceeded() {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-send-listing-cap-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ostrya_rt::block_on(async {
            let repo = Repo::create(&dir, crate::CreateOptions::new(crate::RepoMode::BareUser))
                .await
                .unwrap();
            let config =
                crate::RepoConfig::parse("[core]\nrepo_version=1\nmode=bare-user\n").unwrap();
            let access = crate::access::ClientAccess::from_config(&config, &dir).unwrap();
            let access = ReadAccess::new(
                std::sync::Arc::new(access),
                crate::access::AuthItem::Anonymous,
                None,
            );
            let listing = repo
                .build_ref_listing(&crate::RefSelector::parse([]).unwrap(), None, &access)
                .await
                .unwrap()
                .bytes;
            let mut input = FrameWriter::new(Vec::new());
            for msg in [
                Message::PullHello(PullHello {
                    version: 1,
                    agent: None,
                }),
                Message::ListRefs(ListRefsRequest::default()),
            ] {
                input.write_message(&msg).await.unwrap();
            }
            let input = input.into_inner();

            let mut out = Vec::new();
            let result = repo
                .send_capped(
                    &input[..],
                    &mut out,
                    &access,
                    &SendOptions::default(),
                    listing.len() as u64 - 1,
                )
                .await;
            assert!(
                matches!(result, Err(Error::Remote(remote::Error::LimitExceeded(_)))),
                "{result:?}"
            );
            let mut reader = FrameReader::new(&out[..]);
            assert!(matches!(
                reader.read_message().await.unwrap(),
                Some(Message::PullHelloReply(_))
            ));
            let Some(Message::Error(e)) = reader.read_message().await.unwrap() else {
                panic!("the session sent no Error");
            };
            assert_eq!(e.code, ErrorCode::LimitExceeded);
            assert_eq!(reader.read_message().await.unwrap(), None);

            let mut out = Vec::new();
            repo.send_capped(
                &input[..],
                &mut out,
                &access,
                &SendOptions::default(),
                listing.len() as u64,
            )
            .await
            .unwrap();
            let mut reader = FrameReader::new(&out[..]);
            reader.read_message().await.unwrap();
            assert_eq!(
                reader.read_message().await.unwrap(),
                Some(Message::GetReply(GetReply {
                    found: true,
                    len: Some(listing.len() as u64)
                }))
            );
            let mut body = Vec::new();
            let mut buf = vec![0u8; 4096];
            loop {
                match reader.read_object_data(&mut buf).await.unwrap() {
                    ObjectRead::Data(n) => body.extend_from_slice(&buf[..n]),
                    ObjectRead::End => break,
                    ObjectRead::Abandoned => panic!("the body was abandoned"),
                }
            }
            assert_eq!(body, listing);
            assert_eq!(reader.read_message().await.unwrap(), None);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The line of an invalid collection directory names its path and
    /// escapes each control character.
    #[test]
    fn the_line_of_an_invalid_collection_dir_escapes_control_characters() {
        let event = SendEvent::InvalidCollectionDir {
            name: "bad\nforged line\t\u{7f}".to_owned(),
        };
        assert_eq!(
            event.to_string(),
            "refs/mirrors/bad\\nforged line\\t\\u{7f}: the directory name is not a \
             collection id, and the ref listing leaves out the directory"
        );
    }

    /// The chunk payload is equal to the chunk payload of the push, so the
    /// two directions write the same shape.
    #[test]
    fn the_chunk_and_the_buffer_fill_one_write() {
        assert_eq!(CHUNK, 65_532);
        assert_eq!(CHUNK + 4, STREAM_BUFFER);
    }
}
