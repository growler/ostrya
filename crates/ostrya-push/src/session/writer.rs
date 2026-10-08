//! The object stream that a session writes: the plan of each object, the
//! frames and chunks of the objects of one `send` call, and the detached
//! metadata of their commits.
//!
//! `ObjectWriter` is generic over its output. A stream transport gives it a
//! buffered pipe, and the HTTP transport gives it the body of one upload
//! request. One `send` call can run several writers over one `Upload`, and
//! these writers take the names from one shared cursor.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use futures_io::AsyncWrite;
use futures_lite::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use ostrya_core::{Checksum, DeflateReader, MAX_METADATA_SIZE, ObjectName, ObjectType};
use ostrya_gvariant::Type;

use super::progress::Counters;
use super::{ObjectData, ObjectReader, ObjectSource, invalid};
use crate::error::{Error, Result};
use crate::proto::{Encoding, FrameWriter, Message, ObjectHeader};

/// The largest chunk payload that the session writes: 64 KiB less 4 bytes.
///
/// The 4 bytes hold the length of the chunk. A full chunk and its length
/// fill the output buffer of a stream exactly. They also fill one frame of
/// an upload body exactly.
pub(super) const CHUNK_PAYLOAD: usize = 64 * 1024 - 4;

/// An output that tells if the bytes written to it reach the transport.
pub(super) trait HandOver {
    /// Returns `true` if the transport holds the bytes that the output takes.
    ///
    /// A stream always returns `true`. The body of an upload returns `true`
    /// from the hand-over of its request.
    fn is_handed_over(&self) -> bool;
}

impl HandOver for Box<dyn AsyncWrite + Unpin + Send> {
    fn is_handed_over(&self) -> bool {
        true
    }
}

impl HandOver for ostrya_fetch::UploadWriter {
    fn is_handed_over(&self) -> bool {
        ostrya_fetch::UploadWriter::is_handed_over(self)
    }
}

/// A writer that counts the bytes that it takes as bytes sent, after the
/// hand-over of its output.
///
/// Before the hand-over, the writer holds the bytes that it takes. It counts
/// them at the first write, flush, or close after the hand-over. If the
/// output is never handed over, the writer counts none of its bytes.
pub(super) struct Counting<W> {
    inner: W,
    counters: Arc<Counters>,
    /// The number of bytes taken before the hand-over and not counted yet.
    held: u64,
}

impl<W: AsyncWrite + HandOver + Unpin> Counting<W> {
    pub(super) fn new(inner: W, counters: Arc<Counters>) -> Counting<W> {
        Counting {
            inner,
            counters,
            held: 0,
        }
    }

    /// Adds `n` to the held bytes, and counts all held bytes as sent if the
    /// output is handed over.
    fn count(&mut self, n: u64) {
        self.held += n;
        if self.held > 0 && self.inner.is_handed_over() {
            self.counters.wire(std::mem::take(&mut self.held));
        }
    }
}

impl<W: AsyncWrite + HandOver + Unpin> AsyncWrite for Counting<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let n = std::task::ready!(Pin::new(&mut me.inner).poll_write(cx, buf))?;
        me.count(n as u64);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        std::task::ready!(Pin::new(&mut me.inner).poll_flush(cx))?;
        me.count(0);
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        std::task::ready!(Pin::new(&mut me.inner).poll_close(cx))?;
        me.count(0);
        Poll::Ready(Ok(()))
    }
}

/// A reader that counts each byte that it gives as a content byte.
///
/// The session compressor reads the content bytes through it.
struct ContentCount {
    inner: Box<dyn ObjectReader>,
    counters: Arc<Counters>,
}

impl futures_io::AsyncRead for ContentCount {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let n = std::task::ready!(Pin::new(&mut me.inner).poll_read(cx, buf))?;
        me.counters.content(n as u64);
        Poll::Ready(Ok(n))
    }
}

/// The claims of the detached metadata of the commits of one session.
///
/// A commit has one of three states:
///
/// - free: a call that finds the commit free claims it and asks its source.
/// - pending: a call asks its source. The claim is pending until the source
///   answers.
/// - sent: a call has a dict of the commit that passed the checks, and it
///   writes the dict. No call sends a dict for the commit again.
///
/// If the call gets a dict that it can send, the commit becomes sent. If the
/// source gives no dict, or a failure occurs, or the call is dropped, the
/// commit becomes free again.
///
/// A call that finds the claim of a commit pending waits until the claim
/// ends. If the commit is then free, the call claims it, so no call passes
/// over a commit whose claim another call gives back. A call holds one
/// pending claim at a time, and a waiting call holds no lock.
#[derive(Default)]
pub(super) struct MetaClaims {
    claims: Mutex<HashMap<Checksum, Claim>>,
}

/// The state of a commit that a call claimed. A commit with no entry is free.
enum Claim {
    /// A call asks its source. The wakers are of the calls that wait for the
    /// answer.
    Pending(Vec<Waker>),
    /// A call sent the dict of the commit.
    Sent,
}

impl MetaClaims {
    fn lock(&self) -> MutexGuard<'_, HashMap<Checksum, Claim>> {
        self.claims.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Claims `commit`, and returns the pending claim.
    ///
    /// Returns `None` if a call sent the dict of the commit. If another call
    /// holds the claim, this call waits until that claim ends.
    pub(super) async fn claim(&self, commit: &Checksum) -> Option<PendingClaim<'_>> {
        std::future::poll_fn(|cx| match self.lock().entry(*commit) {
            Entry::Vacant(free) => {
                free.insert(Claim::Pending(Vec::new()));
                Poll::Ready(Some(PendingClaim {
                    claims: self,
                    commit: *commit,
                    sent: false,
                }))
            }
            Entry::Occupied(mut held) => match held.get_mut() {
                Claim::Sent => Poll::Ready(None),
                Claim::Pending(waiting) => {
                    if !waiting.iter().any(|w| w.will_wake(cx.waker())) {
                        waiting.push(cx.waker().clone());
                    }
                    Poll::Pending
                }
            },
        })
        .await
    }
}

/// The pending claim of one commit.
///
/// `PendingClaim::sent` makes the commit sent. If the claim is dropped with
/// no call to `sent`, the commit becomes free again. In both cases, the calls
/// that wait for the claim wake.
pub(super) struct PendingClaim<'a> {
    claims: &'a MetaClaims,
    commit: Checksum,
    sent: bool,
}

impl PendingClaim<'_> {
    /// Marks the commit as sent, so no call sends its dict again.
    pub(super) fn sent(mut self) {
        self.sent = true;
    }
}

impl Drop for PendingClaim<'_> {
    fn drop(&mut self) {
        let mut claims = self.claims.lock();
        let before = if self.sent {
            claims.insert(self.commit, Claim::Sent)
        } else {
            claims.remove(&self.commit)
        };
        drop(claims);
        if let Some(Claim::Pending(waiting)) = before {
            waiting.into_iter().for_each(Waker::wake);
        }
    }
}

/// The objects of one `send` call, and the data that the session needs to
/// send them.
///
/// The writers of the call take the names from one cursor. The first writer
/// that finds no name left claims the detached metadata of `commits`. Only
/// that writer writes the detached metadata. After `Upload::stop`, the
/// cursor gives no name, and no writer can claim the detached metadata.
pub(super) struct Upload<'a> {
    pub source: &'a dyn ObjectSource,
    pub names: &'a [ObjectName],
    pub commits: &'a [Checksum],
    /// The deflate level of a content object, or `None` to send content
    /// objects raw.
    pub level: Option<u8>,
    /// `true` if the server lists the encoding `deflate`.
    pub deflate_ok: bool,
    /// The claims of the detached metadata of the session.
    pub claims: &'a MetaClaims,
    /// The index of the next name to send.
    cursor: AtomicUsize,
    /// `true` if a writer claimed the detached metadata.
    metas_claimed: AtomicBool,
    /// `true` if a writer failed. After that, no writer takes more work.
    stopped: AtomicBool,
}

impl<'a> Upload<'a> {
    pub(super) fn new(
        source: &'a dyn ObjectSource,
        names: &'a [ObjectName],
        commits: &'a [Checksum],
        level: Option<u8>,
        deflate_ok: bool,
        claims: &'a MetaClaims,
    ) -> Upload<'a> {
        Upload {
            source,
            names,
            commits,
            level,
            deflate_ok,
            claims,
            cursor: AtomicUsize::new(0),
            metas_claimed: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
        }
    }

    /// Returns the next name to send, or `None` if no name is left or a
    /// writer failed.
    fn next_name(&self) -> Option<&'a ObjectName> {
        if self.stopped.load(Ordering::Relaxed) {
            return None;
        }
        self.names.get(self.cursor.fetch_add(1, Ordering::Relaxed))
    }

    /// Returns `true` if this call claims the detached metadata of the
    /// commits.
    ///
    /// Only the first call returns `true`. After `Upload::stop`, no call
    /// returns `true`.
    fn claim_metas(&self) -> bool {
        !self.stopped.load(Ordering::Relaxed) && !self.metas_claimed.swap(true, Ordering::Relaxed)
    }

    /// Stops the upload, so the writers of the call get no more work.
    pub(super) fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }
}

/// The position of one writer in an `Upload`.
#[derive(Default)]
pub(super) struct Pass {
    /// The index of the next commit, after the writer claimed the detached
    /// metadata. `None` while the writer takes names.
    metas: Option<usize>,
}

/// The cause of the stop of an object stream.
pub(super) enum Stop {
    /// A write to the stream failed.
    Wire(Error),
    /// The source failed, or gave data that the session cannot send.
    ///
    /// The session ends the stream with `Abort`. If an object is open, the
    /// session writes the abandon marker before `Abort`. If the failure came
    /// before the writer wrote the header of the next object, `next` is that
    /// header.
    Abandon {
        error: Error,
        in_object: bool,
        next: Option<ObjectHeader>,
    },
}

impl From<Error> for Stop {
    fn from(e: Error) -> Stop {
        Stop::Wire(e)
    }
}

/// Returns the stop before the object of `next`, whose header the writer
/// did not write.
fn refuse(error: Error, next: ObjectHeader) -> Stop {
    Stop::Abandon {
        error,
        in_object: false,
        next: Some(next),
    }
}

/// Returns `e` as the error of a source call.
///
/// If `e` is already [`Error::Source`], the function returns it unchanged.
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
        next: None,
    }
}

/// The object bytes after the prefix that the session builds.
enum Body {
    /// No bytes, for a symlink.
    None,
    /// Bytes copied as the reader gives them.
    Copy(Box<dyn ObjectReader>),
    /// Bytes that the session deflates at the given level.
    Deflate(Box<dyn ObjectReader>, u8),
}

/// The object bytes before the body.
enum Prefix {
    /// No bytes.
    None,
    /// The framed file header in the header buffer of the writer.
    Header,
    /// The given bytes.
    Bytes(Vec<u8>),
}

/// The data that the session sends for one object.
pub(super) struct Plan {
    encoding: Encoding,
    prefix: Prefix,
    body: Body,
}

/// The next object of an object stream.
pub(super) enum Item {
    /// An object of the names, and the plan of what the session sends for it.
    Object(ObjectName, Plan),
    /// The serialized detached metadata of a commit.
    Meta(Checksum, Vec<u8>),
}

/// Checks the data that a source gave for `name`, and returns the plan of
/// what the session sends for it.
///
/// `level` is the level of the session compressor, or `None` if the session
/// does not deflate. The function writes the framed file header of a content
/// object into `header_buf`.
fn plan(
    name: &ObjectName,
    data: ObjectData,
    level: Option<u8>,
    deflate_ok: bool,
    header_buf: &mut Vec<u8>,
) -> Result<Plan> {
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
                prefix: Prefix::None,
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
                Some(level) => {
                    header
                        .write_framed_archive(size, header_buf)
                        .map_err(bad_header)?;
                    Ok(Plan {
                        encoding: Encoding::Deflate,
                        prefix: Prefix::Header,
                        body: body.map_or(Body::None, |r| Body::Deflate(r, level)),
                    })
                }
                None => {
                    header.write_framed(header_buf).map_err(bad_header)?;
                    Ok(Plan {
                        encoding: Encoding::Raw,
                        prefix: Prefix::Header,
                        body: body.map_or(Body::None, Body::Copy),
                    })
                }
            }
        }
    }
}

/// A writer of object streams over one output `W`.
pub(super) struct ObjectWriter<W> {
    writer: FrameWriter<W>,
    /// The compressor of the objects that this writer deflates.
    ///
    /// The writer creates it at the first such object, and resets it for each
    /// object after that.
    deflate: Option<DeflateReader<Box<dyn ObjectReader>>>,
    /// The buffer that the writer copies object bytes through.
    buf: Vec<u8>,
    /// The buffer of the framed file header of each content object.
    header_buf: Vec<u8>,
    counters: Arc<Counters>,
}

impl<W: AsyncWrite + Unpin> ObjectWriter<W> {
    pub(super) fn new(output: W, counters: Arc<Counters>) -> ObjectWriter<W> {
        ObjectWriter {
            writer: FrameWriter::new(output),
            deflate: None,
            buf: Vec::new(),
            header_buf: Vec::new(),
            counters,
        }
    }

    /// Returns the frame writer under the object writer.
    pub(super) fn frames(&mut self) -> &mut FrameWriter<W> {
        &mut self.writer
    }

    /// Writes the items of `up` that `pass` takes, until none is left.
    ///
    /// Sets `started` to `true` before the first write.
    pub(super) async fn write_items(
        &mut self,
        up: &Upload<'_>,
        pass: &mut Pass,
        started: &mut bool,
    ) -> std::result::Result<(), Stop> {
        while let Some(item) = self.next_item(up, pass).await? {
            *started = true;
            self.write_item(item).await?;
        }
        Ok(())
    }

    /// Returns the next item of `up` for `pass`, or `None` if the writer has
    /// nothing more to write.
    ///
    /// The objects of the names of the cursor come first. Then the writer that
    /// claims the detached metadata gets the detached metadata of the commits.
    /// It skips a commit with no dict, and a commit that a call of the session
    /// made sent. It waits while another call holds a pending claim.
    pub(super) async fn next_item(
        &mut self,
        up: &Upload<'_>,
        pass: &mut Pass,
    ) -> std::result::Result<Option<Item>, Stop> {
        if pass.metas.is_none() {
            if let Some(name) = up.next_name() {
                let encoding = match (name.ty, up.level) {
                    (ObjectType::File, Some(_)) => Encoding::Deflate,
                    _ => Encoding::Raw,
                };
                let next = ObjectHeader {
                    name: *name,
                    encoding,
                };
                let data = up
                    .source
                    .open(name, encoding)
                    .await
                    .map_err(|e| refuse(source_error(e), next.clone()))?;
                let level = up.level.filter(|_| name.ty == ObjectType::File);
                let plan = plan(name, data, level, up.deflate_ok, &mut self.header_buf)
                    .map_err(|e| refuse(e, next))?;
                return Ok(Some(Item::Object(*name, plan)));
            }
            if !up.claim_metas() {
                return Ok(None);
            }
            pass.metas = Some(0);
        }
        while let Some(i) = pass.metas {
            let Some(commit) = up.commits.get(i) else {
                return Ok(None);
            };
            pass.metas = Some(i + 1);
            if up.is_stopped() {
                return Ok(None);
            }
            // If the source fails or has no dict for the commit, the claim
            // drops. The commit is then free again for the calls that wait
            // for it.
            let Some(claim) = up.claims.claim(commit).await else {
                continue;
            };
            let next = ObjectHeader {
                name: ObjectName::new(*commit, ObjectType::CommitMeta),
                encoding: Encoding::Raw,
            };
            let dict = up
                .source
                .detached_metadata(commit)
                .await
                .map_err(|e| refuse(source_error(e), next.clone()))?;
            let Some(dict) = dict else {
                continue;
            };
            let a_sv = Type::parse("a{sv}").expect("valid signature");
            let bytes = ostrya_gvariant::to_bytes(&a_sv, &dict).map_err(|e| {
                refuse(
                    invalid(format!("the detached metadata of commit {commit}: {e}")),
                    next.clone(),
                )
            })?;
            if bytes.len() as u64 > MAX_METADATA_SIZE {
                return Err(refuse(
                    invalid(format!(
                        "the detached metadata of commit {commit} is {} bytes, over the limit \
                         {MAX_METADATA_SIZE}",
                        bytes.len()
                    )),
                    next,
                ));
            }
            claim.sent();
            return Ok(Some(Item::Meta(*commit, bytes)));
        }
        Ok(None)
    }

    /// Writes one item.
    pub(super) async fn write_item(&mut self, item: Item) -> std::result::Result<(), Stop> {
        match item {
            Item::Object(name, plan) => {
                self.write_object(name, plan).await?;
                self.counters.object_sent();
            }
            Item::Meta(commit, bytes) => {
                let name = ObjectName::new(commit, ObjectType::CommitMeta);
                let plan = Plan {
                    encoding: Encoding::Raw,
                    prefix: Prefix::Bytes(bytes),
                    body: Body::None,
                };
                self.write_object(name, plan).await?;
            }
        }
        Ok(())
    }

    /// Ends the stream after a `Stop::Abandon`.
    ///
    /// If an object is open, the call writes the abandon marker and `Abort`.
    /// If no object is open, it writes `Abort` alone. If a write fails, the
    /// call stops and returns its error.
    pub(super) async fn abandon(&mut self, in_object: bool) -> Result<()> {
        if in_object {
            self.writer.abandon_object().await
        } else {
            self.writer.write_message(&Message::Abort).await
        }
    }

    /// Writes one object: its header, its bytes as chunks, and the end chunk.
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
        let is_file = name.ty == ObjectType::File;
        match &plan.prefix {
            Prefix::None => {}
            Prefix::Header => {
                // The buffer goes back to the writer for the next header. If
                // the write fails, the buffer is dropped, and the stream ends.
                let header = std::mem::take(&mut self.header_buf);
                self.write_data(&header).await?;
                self.header_buf = header;
            }
            Prefix::Bytes(bytes) => self.write_data(bytes).await?,
        }
        match plan.body {
            Body::None => {}
            Body::Copy(mut reader) => {
                if self.buf.is_empty() {
                    self.buf = vec![0u8; CHUNK_PAYLOAD];
                }
                loop {
                    // Each chunk except the last is full, for all sizes of
                    // the reads.
                    let mut n = 0;
                    let mut end = false;
                    while n < self.buf.len() {
                        let read = reader.read(&mut self.buf[n..]).await.map_err(read_failed)?;
                        if read == 0 {
                            end = true;
                            break;
                        }
                        n += read;
                    }
                    if n > 0 {
                        let ObjectWriter {
                            writer,
                            buf,
                            counters,
                            ..
                        } = self;
                        writer.write_object_data(&buf[..n]).await?;
                        counters.payload(n as u64);
                        if is_file {
                            counters.content(n as u64);
                        }
                    }
                    if end {
                        break;
                    }
                }
            }
            Body::Deflate(reader, level) => {
                // The compressor reads the content bytes through a
                // `ContentCount`.
                let reader: Box<dyn ObjectReader> = Box::new(ContentCount {
                    inner: reader,
                    counters: Arc::clone(&self.counters),
                });
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
                    // The compressor gives up to 64 KiB, which is 4 bytes
                    // more than a chunk.
                    let n = chunk.len().min(CHUNK_PAYLOAD);
                    self.writer.write_object_data(&chunk[..n]).await?;
                    self.counters.payload(n as u64);
                    deflate.consume(n);
                }
                // The empty reader releases the source of the object.
                *deflate.get_mut() = Box::new(futures_lite::io::empty());
            }
        }
        self.writer.end_object().await?;
        Ok(())
    }

    async fn write_data(&mut self, data: &[u8]) -> Result<()> {
        for piece in data.chunks(CHUNK_PAYLOAD) {
            self.writer.write_object_data(piece).await?;
        }
        self.counters.payload(data.len() as u64);
        Ok(())
    }

    /// Closes the output.
    pub(super) async fn close(self) -> Result<()> {
        self.writer.into_inner().close().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The writer holds the bytes written before the hand-over, and counts
    /// them at the first write or close after it. If the output is never
    /// handed over, the writer counts no byte.
    #[test]
    fn bytes_count_once_the_output_is_handed_over() {
        struct Output {
            handed: Arc<AtomicBool>,
        }
        impl AsyncWrite for Output {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl HandOver for Output {
            fn is_handed_over(&self) -> bool {
                self.handed.load(Ordering::Relaxed)
            }
        }

        let counters = Arc::new(Counters::new(None));
        let handed = Arc::new(AtomicBool::new(false));
        let output = Output {
            handed: Arc::clone(&handed),
        };
        let mut counting = Counting::new(output, Arc::clone(&counters));
        ostrya_rt::block_on(async {
            counting.write_all(&[0; 10]).await.unwrap();
            assert_eq!(counters.stats().bytes_sent, 0);
            handed.store(true, Ordering::Relaxed);
            counting.write_all(&[0; 5]).await.unwrap();
            assert_eq!(counters.stats().bytes_sent, 15);
            counting.close().await.unwrap();
            assert_eq!(counters.stats().bytes_sent, 15);
        });

        let never = Arc::new(Counters::new(None));
        let output = Output {
            handed: Arc::new(AtomicBool::new(false)),
        };
        let mut counting = Counting::new(output, Arc::clone(&never));
        ostrya_rt::block_on(async {
            counting.write_all(&[0; 10]).await.unwrap();
            counting.close().await.unwrap();
        });
        assert_eq!(never.stats().bytes_sent, 0);
    }

    /// If many threads claim one commit at the same time, one thread gets
    /// the claim. The others wait until the claim ends. A claim of a sent
    /// commit returns `None`, and another commit is free.
    #[test]
    fn one_claim_of_a_commit_wins() {
        let claims = MetaClaims::default();
        let commit = Checksum::from_bytes([3; 32]);
        let wins = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..16 {
                s.spawn(|| {
                    if let Some(claim) = ostrya_rt::block_on(claims.claim(&commit)) {
                        wins.fetch_add(1, Ordering::Relaxed);
                        claim.sent();
                    }
                });
            }
        });
        assert_eq!(wins.load(Ordering::Relaxed), 1);
        assert!(ostrya_rt::block_on(claims.claim(&commit)).is_none());
        assert!(ostrya_rt::block_on(claims.claim(&Checksum::from_bytes([4; 32]))).is_some());
    }

    /// A call that finds the claim of a commit pending waits. If the claim is
    /// given back, as for a source with no dict, the waiting call gets the
    /// claim and asks its own source. If the commit is sent, the waiting call
    /// passes over it.
    #[test]
    fn a_waiting_claim_follows_the_pending_one() {
        use futures_lite::future::poll_once;

        let claims = MetaClaims::default();
        let commit = Checksum::from_bytes([5; 32]);
        ostrya_rt::block_on(async {
            let first = claims.claim(&commit).await.expect("the commit is free");
            let mut second = std::pin::pin!(claims.claim(&commit));
            assert!(poll_once(second.as_mut()).await.is_none());
            // With no dict, the claim is given back, and the waiting call
            // gets it.
            drop(first);
            let second = second.await.expect("a given-back claim is free");

            let mut third = std::pin::pin!(claims.claim(&commit));
            assert!(poll_once(third.as_mut()).await.is_none());
            second.sent();
            assert!(third.await.is_none());
        });
    }

    /// The cursor gives each name once, the detached metadata goes to one
    /// claimer, and a stopped upload gives neither.
    #[test]
    fn the_cursor_gives_each_name_once_and_stop_ends_it() {
        struct NoSource;
        impl ObjectSource for NoSource {
            fn objects<'a>(
                &'a self,
                _: &'a Checksum,
            ) -> super::super::BoxFuture<'a, Result<Vec<ObjectName>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn open<'a>(
                &'a self,
                _: &'a ObjectName,
                _: Encoding,
            ) -> super::super::BoxFuture<'a, Result<ObjectData>> {
                Box::pin(async { Err(invalid("no object")) })
            }
            fn detached_metadata<'a>(
                &'a self,
                _: &'a Checksum,
            ) -> super::super::BoxFuture<'a, Result<Option<ostrya_gvariant::Value>>> {
                Box::pin(async { Ok(None) })
            }
        }
        let names: Vec<ObjectName> = (0..3u8)
            .map(|i| ObjectName::new(Checksum::from_bytes([i; 32]), ObjectType::DirMeta))
            .collect();
        let claims = MetaClaims::default();
        let up = Upload::new(&NoSource, &names, &[], None, false, &claims);
        let taken: Vec<_> = std::iter::from_fn(|| up.next_name().copied()).collect();
        assert_eq!(taken, names);
        assert!(up.next_name().is_none());
        assert!(up.claim_metas());
        assert!(!up.claim_metas());

        let up = Upload::new(&NoSource, &names, &[], None, false, &claims);
        assert!(up.next_name().is_some());
        up.stop();
        assert!(up.next_name().is_none());
        assert!(!up.claim_metas());
    }

    /// A body that the source gives in short reads goes out in full chunks,
    /// and the last chunk holds the rest.
    #[test]
    fn short_reads_make_full_chunks() {
        /// A reader of `left` bytes that gives at most 1000 bytes for each
        /// read.
        struct Trickle {
            left: usize,
        }
        impl futures_io::AsyncRead for Trickle {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                let me = self.get_mut();
                let n = me.left.min(buf.len()).min(1000);
                buf[..n].fill(7);
                me.left -= n;
                Poll::Ready(Ok(n))
            }
        }

        let size = 3 * CHUNK_PAYLOAD + 100;
        let mut writer = ObjectWriter::new(Vec::new(), Arc::new(Counters::new(None)));
        let plan = Plan {
            encoding: Encoding::Raw,
            prefix: Prefix::None,
            body: Body::Copy(Box::new(Trickle { left: size })),
        };
        let name = ObjectName::new(Checksum::from_bytes([1; 32]), ObjectType::File);
        if ostrya_rt::block_on(writer.write_object(name, plan)).is_err() {
            panic!("the object is not written");
        }
        let out = writer.writer.into_inner();
        let len = |at: usize| u32::from_be_bytes(out[at..at + 4].try_into().unwrap()) as usize;
        let mut at = 4 + len(0);
        let mut chunks = Vec::new();
        while len(at) != 0 {
            chunks.push(len(at));
            at += 4 + len(at);
        }
        assert_eq!(at + 4, out.len());
        assert_eq!(
            chunks,
            vec![CHUNK_PAYLOAD, CHUNK_PAYLOAD, CHUNK_PAYLOAD, 100]
        );
    }
}
