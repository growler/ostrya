//! The HTTP transport of a session: each step of the session is one request
//! to the receive endpoint of the server.
//!
//! `Hello`, `Have`, and `Commit` go as whole request bodies, and each object
//! stream as the streamed body of one `objects` request. Each response body
//! holds one frame: the reply of the step, or an `Error`. One `send` call
//! runs up to `parallel-uploads` object streams at the same time, and the
//! calls of one session share one gate of that many permits.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::AsyncReadExt;
use ostrya_core::ObjectName;
use ostrya_fetch::gate::Gate;
use ostrya_fetch::{
    BasicAuth, BearerToken, Fetcher, Priority, UploadBody, UploadMethod, UploadRequest, Uploaded,
};

use super::progress::Counters;
use super::writer::{Counting, Item, ObjectWriter, Pass, Stop, Upload};
use super::{
    BoxFuture, PushOutcome, PushPhase, ServerInfo, broken, invalid, server_info, unexpected,
};
use crate::error::{Error, Result};
use crate::proto::{
    CommitRequest, FrameReader, Hello, MAX_FRAME, MIN_FRAME_LIMIT, Message, PROTOCOL_VERSION,
    RefUpdate, encode_frame, have_entries_within,
};

/// The path of the receive endpoint under the push address, with the step
/// that opens a session.
const SESSION_PATH: &str = "_ostrya/receive/v1/session";

/// The response header that names a new session.
const SESSION_HEADER: &str = "ostrya-session";

/// The longest wait for the response to `Hello` after the request body was
/// sent.
const HELLO_RESPONSE: Duration = Duration::from_secs(360);

/// The longest wait for the response to `Commit` after the request body was
/// sent. The response follows the commit checks and the ref writes.
const COMMIT_RESPONSE: Duration = Duration::from_secs(3600);

/// The most object streams of one session, whatever the server announces.
/// The fetcher of a session admits one request more, so `Have` and `Commit`
/// never wait for the object streams at the gate of the fetcher.
pub(crate) const MAX_PARALLEL: u32 = 31;

/// The start of the message of an error that the server gives a step of a
/// session that it aborted for another cause.
const SESSION_ABORTED: &str = "the session was aborted";

/// The credential each request of a session carries.
pub(crate) enum Credential {
    /// `Authorization: Bearer`.
    Bearer(BearerToken),
    /// `Authorization: Basic`.
    Basic(BasicAuth),
}

/// The receive endpoint of a server, as a session reaches it.
pub(crate) struct Endpoint {
    /// The fetcher, with the push address as its one mirror.
    pub(crate) fetcher: Fetcher,
    /// The push address, which the messages name.
    pub(crate) url: String,
    pub(crate) credential: Option<Credential>,
    /// Send the credential to an `http://` address.
    pub(crate) allow_cleartext: bool,
}

/// The result of one upload request.
type Sent = std::result::Result<Uploaded, ostrya_fetch::Error>;

impl Endpoint {
    /// Send one request to `path` under the push address. `timeout` bounds
    /// the wait for the response after the body was sent. `None` takes the
    /// progress timeout of the fetcher.
    ///
    /// The future of an upload is large, so it is boxed, and the future of
    /// each step holds a pointer to it.
    fn request<'a>(
        &'a self,
        path: &'a str,
        method: UploadMethod,
        body: UploadBody,
        timeout: Option<Duration>,
    ) -> BoxFuture<'a, Sent> {
        let mut request = UploadRequest::path(path, body);
        request.method = method;
        request.response_timeout = timeout;
        request.allow_cleartext_credentials = self.allow_cleartext;
        match &self.credential {
            Some(Credential::Bearer(token)) => request.bearer_token = Some(token),
            Some(Credential::Basic(basic)) => request.basic_auth = Some(basic),
            None => {}
        }
        Box::pin(self.fetcher.upload(request))
    }

    /// `POST` the whole body `body` to `path`, as [`request`](Self::request)
    /// does. The bytes of the body count as sent when the fetcher handed the
    /// request to a connection: when the upload gives a response, and when
    /// it fails after the hand-over.
    async fn post(
        &self,
        path: &str,
        body: Vec<u8>,
        timeout: Option<Duration>,
        counters: &Counters,
    ) -> Sent {
        let len = body.len() as u64;
        let sent = self
            .request(path, UploadMethod::Post, UploadBody::bytes(body), timeout)
            .await;
        if sent.as_ref().map_or_else(|e| !e.is_unsent(), |_| true) {
            counters.wire(len);
        }
        sent
    }

    /// The URL of `path`, for a message.
    fn url_of(&self, path: &str) -> String {
        format!("{}/{path}", self.url.trim_end_matches('/'))
    }
}

/// One session over HTTP.
pub(crate) struct HttpLink {
    endpoint: Endpoint,
    /// The path of the session under the push address.
    session: String,
    /// The permits of the object streams of the session.
    gate: Arc<Gate>,
    /// The number of permits of `gate`.
    permits: usize,
    /// The frame and chunk limit of the server.
    max_frame: u32,
    /// Set when a call failed or its future was dropped before it completed.
    broken: AtomicBool,
    /// Set while a `missing` call runs.
    have_busy: AtomicBool,
}

/// Marks a session broken when a call fails, or when its future is dropped
/// before it completes.
struct Call<'a> {
    broken: &'a AtomicBool,
    completed: bool,
}

impl<'a> Call<'a> {
    fn new(broken: &'a AtomicBool) -> Call<'a> {
        Call {
            broken,
            completed: false,
        }
    }

    fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for Call<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.broken.store(true, Ordering::Relaxed);
        }
    }
}

/// Clears the flag of a `missing` call when the call ends.
struct Busy<'a> {
    flag: &'a AtomicBool,
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Relaxed);
    }
}

/// The message of the body of a response with `status` from `url`.
///
/// The body of a 200 holds one frame. The body of a 401, a 403, a 409, a
/// 422, a 500, and a 503 holds one `Error` frame. Each other status, a body
/// that is not one frame, and a frame that is not `Error` with one of those
/// statuses, is [`Error::Transport`], which names the URL and the status. A
/// failed read of the body is [`Error::Io`]. The reader takes frames of at
/// most [`MAX_FRAME`] bytes, whatever the server announced.
async fn decode_reply<R: AsyncRead + Unpin>(status: u16, url: &str, body: R) -> Result<Message> {
    if !matches!(status, 200 | 401 | 403 | 409 | 422 | 500 | 503) {
        return Err(Error::Transport(format!(
            "{url} answered with the status {status}"
        )));
    }
    let not_a_frame = |why: &str| {
        Error::Transport(format!(
            "{url} answered with the status {status} and a body that is not one frame: {why}"
        ))
    };
    let mut reader = FrameReader::new(body);
    reader.set_limit(MAX_FRAME);
    let msg = match reader.read_message().await {
        Ok(Some(msg)) => msg,
        Ok(None) => return Err(not_a_frame("the body is empty")),
        Err(Error::Io(e)) => return Err(Error::Io(e)),
        Err(e) => return Err(not_a_frame(&e.to_string())),
    };
    let mut byte = [0u8; 1];
    if reader.into_inner().read(&mut byte).await? != 0 {
        return Err(not_a_frame("bytes follow the frame"));
    }
    match msg {
        Message::Error(_) => Ok(msg),
        _ if status == 200 => Ok(msg),
        other => Err(not_a_frame(&format!(
            "a {:?} frame comes with an error status",
            other.kind()
        ))),
    }
}

/// The message of the response `uploaded` from `url`, as
/// [`decode_reply`] reads it. The future holds the response body and a frame
/// reader, so it is boxed, and the future of each step holds a pointer to it.
fn reply(uploaded: Uploaded, url: &str) -> BoxFuture<'_, Result<Message>> {
    let status = uploaded.status();
    Box::pin(decode_reply(status, url, uploaded.into_body()))
}

/// A session id: 64 lowercase hex digits.
fn session_id(uploaded: &Uploaded) -> Option<String> {
    let id = uploaded.headers().get(SESSION_HEADER)?.to_str().ok()?;
    let valid = id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    valid.then(|| id.to_owned())
}

/// Open a session: send `Hello` with `refs` and read `HelloReply`. A failed
/// check of the reply after the server opened the session ends the session
/// with `DELETE`.
pub(super) async fn open(
    endpoint: Endpoint,
    refs: &[String],
    agent: String,
    counters: &Counters,
) -> Result<(ServerInfo, HttpLink)> {
    let hello = Message::Hello(Hello {
        version: PROTOCOL_VERSION,
        agent: Some(agent),
        refs: refs.to_vec(),
        one_way: false,
    });
    let body = encode_frame(&hello, MIN_FRAME_LIMIT)?;
    let url = endpoint.url_of(SESSION_PATH);
    let uploaded = endpoint
        .post(SESSION_PATH, body, Some(HELLO_RESPONSE), counters)
        .await
        .map_err(Error::Fetch)?;
    let id = session_id(&uploaded);
    let reply = match reply(uploaded, &url).await? {
        Message::HelloReply(reply) => reply,
        Message::Error(e) => return Err(e.into()),
        other => return Err(unexpected(&other, "Hello")),
    };
    let Some(id) = id else {
        return Err(Error::Transport(format!(
            "{url} answered HelloReply with no session id of 64 lowercase hex digits in the \
             {SESSION_HEADER} header"
        )));
    };
    let max_frame = reply.max_frame;
    let permits = reply.parallel_uploads.clamp(1, MAX_PARALLEL) as usize;
    let link = HttpLink {
        endpoint,
        session: format!("{SESSION_PATH}/{id}"),
        gate: Arc::new(Gate::new(permits)),
        permits,
        max_frame,
        broken: AtomicBool::new(false),
        have_busy: AtomicBool::new(false),
    };
    match server_info(reply, refs) {
        Ok(server) => Ok((server, link)),
        Err(e) => {
            let _ = link.delete().await;
            Err(e)
        }
    }
}

/// The number of object streams of a `send` call of `names` names with
/// `permits` permits: one for each permit, and no more than the names, and
/// at least one, which sends the detached metadata of a call with no name.
fn worker_count(permits: usize, names: usize) -> usize {
    permits.min(names.max(1))
}

/// The rank of an error of one object stream of a `send` call. The call
/// returns the error of the lowest rank: an error of the client, then an
/// error the server gave for its own cause, then any other error, such as
/// the error a step gets when the server aborted the session for the cause
/// of another stream.
fn rank(e: &Error) -> u8 {
    match e {
        Error::Source(_) | Error::InvalidInput(_) => 0,
        Error::Protocol(m) if m.starts_with(SESSION_ABORTED) => 2,
        e if e.code().is_some() => 1,
        _ => 2,
    }
}

/// The error of a `Commit` request whose upload failed with `e`. A request
/// that the fetcher did not hand over is a definite failure, which is
/// [`Error::Fetch`]. A request that it handed over can have reached the
/// server, so each failure after it is the error of `unknown`, and the
/// request is not sent again.
fn commit_failure(e: ostrya_fetch::Error, unknown: impl FnOnce(String) -> Error) -> Error {
    if e.is_unsent() {
        Error::Fetch(e)
    } else {
        unknown(e.to_string())
    }
}

/// The future of one object stream of a `send` call.
type Worker<'f> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'f>>;

/// The wake-ups of the workers of one [`join_workers`] call. Each worker has
/// a waker of its own, which records the worker and wakes the task of the
/// call, so the call polls the workers that woke alone.
struct Woken {
    /// One bit for each worker that woke since the call last polled it.
    due: AtomicU32,
    /// The waker of the task that polls the call.
    task: Mutex<Option<Waker>>,
}

/// The waker of worker `index` of a [`join_workers`] call.
struct WorkerWaker {
    index: usize,
    woken: Arc<Woken>,
}

impl Wake for WorkerWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.due.fetch_or(1 << self.index, Ordering::AcqRel);
        // The task wakes after the lock is released.
        let task = self
            .woken
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(task) = task {
            task.wake();
        }
    }
}

/// Run `workers` to their end in the task of the caller, and give the error
/// of each worker that failed, in the order the errors came. At the first
/// error `stop` runs, and the call then waits for every worker to end.
///
/// Each worker is polled first when the call is, and then only when its own
/// waker woke. The waker of the task is kept before the due workers are
/// read, so a worker that wakes during a poll of the call wakes the task
/// again, and no wake-up is lost. One call runs at most 32 workers.
async fn join_workers(workers: Vec<Worker<'_>>, stop: impl Fn()) -> Vec<Error> {
    assert!(workers.len() <= 32, "a call runs at most 32 workers");
    // A worker that ends is dropped at once.
    let mut workers: Vec<Option<Worker<'_>>> = workers.into_iter().map(Some).collect();
    let all = u32::MAX.checked_shr(32 - workers.len() as u32).unwrap_or(0);
    let woken = Arc::new(Woken {
        due: AtomicU32::new(all),
        task: Mutex::new(None),
    });
    let wakers: Vec<Waker> = (0..workers.len())
        .map(|index| {
            Waker::from(Arc::new(WorkerWaker {
                index,
                woken: Arc::clone(&woken),
            }))
        })
        .collect();
    let mut live = all;
    let mut errors = Vec::new();
    std::future::poll_fn(|cx| {
        {
            let mut task = woken.task.lock().unwrap_or_else(PoisonError::into_inner);
            if !task.as_ref().is_some_and(|t| t.will_wake(cx.waker())) {
                *task = Some(cx.waker().clone());
            }
        }
        let mut due = woken.due.swap(0, Ordering::AcqRel) & live;
        while due != 0 {
            let index = due.trailing_zeros() as usize;
            due &= due - 1;
            let Some(worker) = &mut workers[index] else {
                continue;
            };
            let mut worker_cx = Context::from_waker(&wakers[index]);
            if let Poll::Ready(result) = worker.as_mut().poll(&mut worker_cx) {
                workers[index] = None;
                live &= !(1 << index);
                if let Err(e) = result {
                    stop();
                    errors.push(e);
                }
            }
        }
        if live == 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    errors
}

/// How the write side of one object stream ended.
enum Written {
    /// The stream ended with `ObjectsEnd`, and the body is closed.
    Done,
    /// The source failed, or gave data the session cannot send. The stream
    /// ended with `Abort`.
    Abandoned(Error),
    /// A write failed. The body was dropped open, so the request fails.
    Failed(Error),
}

/// Write the object stream of one request: `first`, the items of `up` that
/// `pass` takes after it, and `ObjectsEnd`. A failure stops `up`. The output
/// is dropped when the call returns, so a body that is not closed fails.
async fn write_stream<W: AsyncWrite + Unpin>(
    mut out: ObjectWriter<W>,
    first: std::result::Result<Item, Stop>,
    up: &Upload<'_>,
    mut pass: Pass,
) -> Written {
    let mut started = true;
    let written = match first {
        Ok(item) => match out.write_item(item).await {
            Ok(()) => out.write_items(up, &mut pass, &mut started).await,
            Err(stop) => Err(stop),
        },
        Err(stop) => Err(stop),
    };
    match written {
        Ok(()) => {
            if let Err(e) = out.frames().write_message(&Message::ObjectsEnd).await {
                up.stop();
                return Written::Failed(e);
            }
            match out.close().await {
                Ok(()) => Written::Done,
                Err(e) => {
                    up.stop();
                    Written::Failed(e)
                }
            }
        }
        Err(Stop::Wire(e)) => {
            up.stop();
            Written::Failed(e)
        }
        Err(Stop::Abandon {
            error, in_object, ..
        }) => {
            up.stop();
            // The upload ends with the error of the stop, so a failed write
            // is ignored.
            let _ = out.abandon(in_object).await;
            let _ = out.close().await;
            Written::Abandoned(error)
        }
    }
}

impl HttpLink {
    /// The path of the step `step` of the session.
    fn step_path(&self, step: &str) -> String {
        format!("{}/{step}", self.session)
    }

    /// Send `body` to the step `step` and read the message of the response.
    async fn step(&self, step: &str, body: Vec<u8>, counters: &Counters) -> Result<Message> {
        let path = self.step_path(step);
        let uploaded = self
            .endpoint
            .post(&path, body, None, counters)
            .await
            .map_err(Error::Fetch)?;
        reply(uploaded, &self.endpoint.url_of(&path)).await
    }

    /// End the session on the server with `DELETE`. A 204 and a 404, which
    /// the server gives for a session it ended already, are success.
    async fn delete(&self) -> Result<()> {
        let url = self.endpoint.url_of(&self.session);
        let uploaded = self
            .endpoint
            .request(
                &self.session,
                UploadMethod::Delete,
                UploadBody::bytes(Vec::new()),
                None,
            )
            .await
            .map_err(Error::Fetch)?;
        match uploaded.status() {
            204 | 404 => Ok(()),
            _ => match reply(uploaded, &url).await? {
                Message::Error(e) => Err(e.into()),
                other => Err(Error::Transport(format!(
                    "{url} answered DELETE with {:?}",
                    other.kind()
                ))),
            },
        }
    }

    /// The objects of `names` that the server does not hold, as
    /// [`PushSession::missing`](super::PushSession::missing) states. Each
    /// `Have` is one request, and the next waits for its response.
    pub(super) async fn missing(
        &self,
        server: &ServerInfo,
        counters: &Counters,
        names: &[ObjectName],
    ) -> Result<Vec<ObjectName>> {
        if self.broken.load(Ordering::Relaxed) {
            return Err(broken());
        }
        if self.have_busy.swap(true, Ordering::Relaxed) {
            return Err(invalid("a call is in progress"));
        }
        let _busy = Busy {
            flag: &self.have_busy,
        };
        let call = Call::new(&self.broken);
        counters.phase(PushPhase::Negotiating);
        counters.offered(names.len() as u64);
        let mut missing = Vec::new();
        let batch_len = server
            .max_have
            .min(have_entries_within(server.max_frame))
            .max(1);
        for batch in names.chunks(batch_len as usize) {
            let body = encode_frame(&Message::Have(batch.to_vec()), server.max_frame)?;
            match self.step("have", body, counters).await? {
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
        call.complete();
        Ok(missing)
    }

    /// Send the objects of `up` over object streams of their own, as
    /// [`PushSession::send`](super::PushSession::send) states.
    ///
    /// The call runs one object stream for each permit of the session, up to
    /// one for each name, and polls them in its own task. Each stream waits
    /// for a permit of the session gate, so the streams of all the calls of
    /// the session stay within the permits. After the first error, no stream
    /// takes a new name. Each stream reads its response, and the call then
    /// returns the error of the lowest [`rank`].
    pub(super) async fn send(&self, counters: &Arc<Counters>, up: &Upload<'_>) -> Result<()> {
        if self.broken.load(Ordering::Relaxed) {
            return Err(broken());
        }
        let call = Call::new(&self.broken);
        let workers: Vec<Worker<'_>> = (0..worker_count(self.permits, up.names.len()))
            .map(|_| Box::pin(self.object_stream(counters, up)) as Worker<'_>)
            .collect();
        let errors = join_workers(workers, || up.stop()).await;
        let first = errors
            .into_iter()
            .enumerate()
            .min_by_key(|(i, e)| (rank(e), *i))
            .map(|(_, e)| e);
        match first {
            Some(e) => Err(e),
            None => {
                call.complete();
                Ok(())
            }
        }
    }

    /// One object stream of a `send` call: take a permit, take the first
    /// item, and send the items of `up` in one `objects` request. A stream
    /// that finds no item sends no request.
    async fn object_stream(&self, counters: &Arc<Counters>, up: &Upload<'_>) -> Result<()> {
        let _permit = self.gate.acquire(Priority::Normal).await;
        let (body, writer) = UploadBody::channel();
        let output = Counting::new(writer, Arc::clone(counters));
        let mut out = ObjectWriter::new(output, Arc::clone(counters));
        out.frames().set_limit(self.max_frame);
        let mut pass = Pass::default();
        let first = match out.next_item(up, &mut pass).await {
            Ok(None) => return Ok(()),
            Ok(Some(item)) => Ok(item),
            Err(stop) => {
                up.stop();
                Err(stop)
            }
        };
        let path = self.step_path("objects");
        let url = self.endpoint.url_of(&path);
        // The response is read to its end, which ends a body that is still
        // open, so the write side cannot wait for a request that is over.
        let response = async {
            let uploaded = self
                .endpoint
                .request(&path, UploadMethod::Post, body, None)
                .await
                .map_err(Error::Fetch)?;
            reply(uploaded, &url).await
        };
        let write = write_stream(out, first, up, pass);
        let (reply, written) = futures_lite::future::zip(response, write).await;
        match written {
            Written::Done => match reply? {
                Message::ObjectsReply(_) => Ok(()),
                Message::Error(e) => Err(e.into()),
                other => Err(unexpected(&other, "ObjectsEnd")),
            },
            Written::Abandoned(error) => Err(error),
            // A write fails when the request failed or the server answered
            // before the end of the body. The response tells why.
            Written::Failed(e) => Err(match reply {
                Ok(Message::Error(sent)) => sent.into(),
                Ok(_) => e,
                Err(r) => r,
            }),
        }
    }

    /// Send `Commit` with `updates`, as
    /// [`PushSession::commit`](super::PushSession::commit) states. A refusal
    /// of `checked`, a broken session, and a `Commit` the codec refuses end
    /// the session with `DELETE` and send no `Commit`.
    pub(super) async fn commit(
        self,
        server: &ServerInfo,
        counters: &Counters,
        checked: Result<()>,
        updates: &[RefUpdate],
        force: bool,
    ) -> Result<PushOutcome> {
        if let Err(e) = checked {
            let _ = self.delete().await;
            return Err(e);
        }
        if self.broken.load(Ordering::Relaxed) {
            let _ = self.delete().await;
            return Err(broken());
        }
        counters.phase(PushPhase::Committing);
        let request = Message::Commit(CommitRequest {
            updates: updates.to_vec(),
            force,
        });
        let body = match encode_frame(&request, server.max_frame) {
            Ok(body) => body,
            Err(e) => {
                let _ = self.delete().await;
                return Err(e);
            }
        };
        let unknown = |message: String| Error::CommitOutcomeUnknown {
            refs: updates.iter().map(|u| u.name.clone()).collect(),
            message,
        };
        let path = self.step_path("commit");
        let sent = self
            .endpoint
            .post(&path, body, Some(COMMIT_RESPONSE), counters)
            .await;
        let uploaded = sent.map_err(|e| commit_failure(e, unknown))?;
        let refs = match reply(uploaded, &self.endpoint.url_of(&path)).await {
            Ok(Message::CommitReply(refs)) => refs,
            Ok(Message::Error(e)) => return Err(e.into()),
            Ok(other) => {
                return Err(unknown(format!("{:?} in reply to Commit", other.kind())));
            }
            Err(e) => return Err(unknown(format!("the reply to Commit failed: {e}"))),
        };
        if refs.len() != updates.len() || refs.iter().zip(updates).any(|(o, u)| o.name != u.name) {
            return Err(unknown(
                "the server replied to Commit for other refs than the refs of Commit".into(),
            ));
        }
        Ok(PushOutcome {
            commit: None,
            refs,
            stats: counters.stats(),
        })
    }

    /// End the session with `DELETE`. On a broken session the call still
    /// sends `DELETE`, and then returns [`Error::InvalidInput`].
    pub(super) async fn abort(self) -> Result<()> {
        let was_broken = self.broken.load(Ordering::Relaxed);
        let deleted = self.delete().await;
        if was_broken {
            return Err(broken());
        }
        deleted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ErrorMessage, ObjectsReply};
    use crate::{ErrorCode, RefOutcome, RefState};

    fn encode(msg: &Message) -> Vec<u8> {
        encode_frame(msg, MAX_FRAME).unwrap()
    }

    fn decode(status: u16, body: &[u8]) -> Result<Message> {
        ostrya_rt::block_on(decode_reply(status, "https://h/x", body))
    }

    fn error_frame(code: ErrorCode) -> Vec<u8> {
        // A `ref-mismatch` carries the current state of its ref.
        let current = (code == ErrorCode::RefMismatch).then(|| RefState {
            name: "main".into(),
            commit: None,
        });
        encode(&Message::Error(ErrorMessage {
            code,
            message: "m".into(),
            missing: Vec::new(),
            current,
        }))
    }

    fn transport(r: Result<Message>, part: &str) {
        match r {
            Err(Error::Transport(m)) => {
                assert!(m.contains("https://h/x"), "{m}");
                assert!(m.contains(part), "{m:?} lacks {part:?}");
            }
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    /// A 200 gives its one frame. An `Error` frame with each status that
    /// carries one gives the frame.
    #[test]
    fn a_frame_status_gives_its_frame() {
        let reply = Message::ObjectsReply(ObjectsReply {
            objects: 2,
            payload_bytes: 9,
        });
        assert!(matches!(
            decode(200, &encode(&reply)),
            Ok(Message::ObjectsReply(_))
        ));
        let committed = Message::CommitReply(vec![RefOutcome {
            name: "main".into(),
            old: None,
            new: None,
        }]);
        assert!(matches!(
            decode(200, &encode(&committed)),
            Ok(Message::CommitReply(_))
        ));
        for (status, code) in [
            (401, ErrorCode::Unauthorized),
            (403, ErrorCode::Unauthorized),
            (409, ErrorCode::RefMismatch),
            (409, ErrorCode::NonFastForward),
            (422, ErrorCode::ChecksumMismatch),
            (500, ErrorCode::Internal),
            (503, ErrorCode::LimitExceeded),
            (200, ErrorCode::Protocol),
        ] {
            match decode(status, &error_frame(code)) {
                Ok(Message::Error(e)) => {
                    assert_eq!(e.code, code, "{status}");
                    assert_eq!(Error::from(e).code(), Some(code), "{status}");
                }
                other => panic!("{status}: {other:?}"),
            }
        }
    }

    /// Each other status is a transport error that names the URL and the
    /// status, whatever the body holds.
    #[test]
    fn another_status_is_a_transport_error() {
        for status in [201, 204, 301, 302, 307, 308, 400, 404, 405, 413, 502, 504] {
            transport(decode(status, b""), &format!("status {status}"));
            transport(
                decode(status, &error_frame(ErrorCode::Internal)),
                &format!("status {status}"),
            );
        }
    }

    /// A body that is not one frame is a transport error: an empty body,
    /// text, a cut frame, bytes after the frame, a frame over the limit of
    /// the client, and a reply frame with an error status.
    #[test]
    fn a_body_that_is_not_one_frame_is_a_transport_error() {
        transport(decode(200, b""), "the body is empty");
        transport(decode(422, b""), "the body is empty");
        transport(decode(200, b"<html>bad gateway</html>"), "not one frame");
        transport(decode(500, b"Internal Server Error"), "not one frame");
        let mut two = error_frame(ErrorCode::Internal);
        two.extend_from_slice(&error_frame(ErrorCode::Internal));
        transport(decode(500, &two), "bytes follow the frame");
        let mut over = (MAX_FRAME + 1).to_be_bytes().to_vec();
        over.push(10);
        transport(decode(200, &over), "limit");
        let reply = encode(&Message::ObjectsReply(ObjectsReply {
            objects: 0,
            payload_bytes: 0,
        }));
        transport(decode(422, &reply), "error status");
        // A cut frame is a failed read of the body.
        let cut = &error_frame(ErrorCode::Internal)[..6];
        assert!(matches!(decode(500, cut), Err(Error::Io(_))));
    }

    /// The future of a `send` call holds the state of both transports. The
    /// object streams of an HTTP call are boxed, so the size of the future
    /// does not grow with them.
    #[test]
    fn the_send_future_is_small() {
        use crate::proto::{Encoding, HelloReply};
        use crate::{Compression, ObjectData, ObjectSource, PushSession, SessionOptions};

        struct NoSource;
        impl ObjectSource for NoSource {
            fn objects<'a>(
                &'a self,
                _: &'a ostrya_core::Checksum,
            ) -> crate::BoxFuture<'a, Result<Vec<ObjectName>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn open<'a>(
                &'a self,
                _: &'a ObjectName,
                _: Encoding,
            ) -> crate::BoxFuture<'a, Result<ObjectData>> {
                Box::pin(async { Err(invalid("no object")) })
            }
            fn detached_metadata<'a>(
                &'a self,
                _: &'a ostrya_core::Checksum,
            ) -> crate::BoxFuture<'a, Result<Option<ostrya_gvariant::Value>>> {
                Box::pin(async { Ok(None) })
            }
        }
        let reply = encode(&Message::HelloReply(HelloReply {
            version: PROTOCOL_VERSION,
            mode: "archive".into(),
            collection_id: None,
            max_frame: MIN_FRAME_LIMIT,
            max_have: 16_384,
            encodings: vec![Encoding::Raw],
            parallel_uploads: 1,
            refs: Vec::new(),
        }));
        let session = ostrya_rt::block_on(PushSession::over_stream(
            futures_lite::io::Cursor::new(reply),
            futures_lite::io::sink(),
            &[],
            SessionOptions::default(),
        ))
        .unwrap();
        let send = session.send(&NoSource, &[], &[], Compression::None);
        let size = std::mem::size_of_val(&send);
        eprintln!("the send future is {size} bytes");
        assert!(size <= 4096, "the send future is {size} bytes");
    }

    /// The futures of `missing`, `commit`, `connect`, its two steps, and the
    /// tree pushes hold the state of both transports. The upload request, the read of its
    /// reply, and the construction of the fetcher are boxed, so none of them
    /// sits inline in these futures.
    #[test]
    fn the_session_futures_are_small() {
        use crate::proto::{Encoding, HelloReply};
        use crate::{
            ConnectOptions, PushRemote, PushSession, SessionOptions, TreePushOptions, push_tree,
            push_tree_prepared,
        };

        let reply = encode(&Message::HelloReply(HelloReply {
            version: PROTOCOL_VERSION,
            mode: "archive".into(),
            collection_id: None,
            max_frame: MIN_FRAME_LIMIT,
            max_have: 16_384,
            encodings: vec![Encoding::Raw],
            parallel_uploads: 1,
            refs: vec![crate::RefState {
                name: "main".into(),
                commit: None,
            }],
        }));
        let open = || {
            ostrya_rt::block_on(PushSession::over_stream(
                futures_lite::io::Cursor::new(reply.clone()),
                futures_lite::io::sink(),
                &["main".to_owned()],
                SessionOptions::default(),
            ))
            .unwrap()
        };
        let session = open();
        let missing = std::mem::size_of_val(&session.missing(&[]));
        let commit = std::mem::size_of_val(&open().commit(&[], false));
        let remote = PushRemote::parse("https://h/repo").unwrap();
        let refs = ["main".to_owned()];
        let connect = std::mem::size_of_val(&PushSession::connect(
            &remote,
            ConnectOptions::default(),
            &refs,
            SessionOptions::default(),
        ));
        let root = std::path::Path::new("/nonexistent");
        let tree = std::mem::size_of_val(&push_tree(
            &remote,
            root,
            ConnectOptions::default(),
            TreePushOptions::default(),
        ));
        let prepare =
            std::mem::size_of_val(&PushSession::prepare(&remote, ConnectOptions::default()));
        // An ssh address needs no runtime to prepare.
        let ssh = PushRemote::parse("ssh://h/repo").unwrap();
        let prepared =
            || ostrya_rt::block_on(PushSession::prepare(&ssh, ConnectOptions::default())).unwrap();
        let open = std::mem::size_of_val(&prepared().open(&refs, SessionOptions::default()));
        let tree_prepared = std::mem::size_of_val(&push_tree_prepared(
            prepared(),
            root,
            TreePushOptions::default(),
        ));
        eprintln!(
            "missing {missing}, commit {commit}, connect {connect}, prepare {prepare}, \
             open {open}, push_tree {tree}, push_tree_prepared {tree_prepared} bytes"
        );
        assert!(missing <= 1024, "the missing future is {missing} bytes");
        assert!(commit <= 3072, "the commit future is {commit} bytes");
        assert!(connect <= 4096, "the connect future is {connect} bytes");
        assert!(prepare <= 2048, "the prepare future is {prepare} bytes");
        assert!(open <= 4096, "the open future is {open} bytes");
        assert!(tree <= 6144, "the push_tree future is {tree} bytes");
        assert!(
            tree_prepared <= 6144,
            "the push_tree_prepared future is {tree_prepared} bytes"
        );
    }

    /// A `Commit` request that the fetcher did not hand over is a definite
    /// failure. Each failure after the hand-over leaves the outcome unknown,
    /// a response that the fetcher refuses for its coding included.
    #[test]
    fn a_commit_failure_after_the_hand_over_is_unknown() {
        let unknown = |message: String| Error::CommitOutcomeUnknown {
            refs: vec!["main".into()],
            message,
        };
        let unsent = ostrya_fetch::Error::Fetch("connect to h:443 failed".into());
        assert!(matches!(
            commit_failure(unsent, unknown),
            Error::Fetch(ostrya_fetch::Error::Fetch(_))
        ));
        let coded = ostrya_fetch::Error::UploadInterrupted {
            url: "https://h/commit".into(),
            message: "response for https://h/commit carries the coding gzip".into(),
        };
        match commit_failure(coded, unknown) {
            Error::CommitOutcomeUnknown { refs, message } => {
                assert_eq!(refs, ["main"]);
                assert!(message.contains("coding gzip"), "{message}");
            }
            other => panic!("expected an unknown outcome, got {other:?}"),
        }
    }

    /// A worker is polled when the call starts and then when its own waker
    /// wakes. The other workers are not polled for it, and a wake-up during
    /// a poll of the call is not lost.
    #[test]
    fn join_polls_the_workers_that_woke() {
        use std::sync::atomic::AtomicUsize;

        /// A worker that counts its polls and ends once `done` is set.
        struct Probe {
            polls: Arc<AtomicUsize>,
            done: Arc<AtomicBool>,
            waker: Arc<Mutex<Option<Waker>>>,
        }
        impl Future for Probe {
            type Output = Result<()>;
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                if self.done.load(Ordering::SeqCst) {
                    return Poll::Ready(Ok(()));
                }
                *self.waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
        }
        /// The waker of the task, which counts its wakes.
        struct Task(AtomicUsize);
        impl Wake for Task {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let probes: Vec<_> = (0..3)
            .map(|_| {
                (
                    Arc::new(AtomicUsize::new(0)),
                    Arc::new(AtomicBool::new(false)),
                    Arc::new(Mutex::new(None::<Waker>)),
                )
            })
            .collect();
        let workers: Vec<Worker<'_>> = probes
            .iter()
            .map(|(polls, done, waker)| {
                Box::pin(Probe {
                    polls: Arc::clone(polls),
                    done: Arc::clone(done),
                    waker: Arc::clone(waker),
                }) as Worker<'_>
            })
            .collect();
        let polls = |i: usize| probes[i].0.load(Ordering::SeqCst);
        let wake = |i: usize| probes[i].2.lock().unwrap().take().unwrap().wake();
        let task = Arc::new(Task(AtomicUsize::new(0)));
        let task_waker = Waker::from(Arc::clone(&task));
        let mut cx = Context::from_waker(&task_waker);
        let mut join = std::pin::pin!(join_workers(workers, || {}));

        assert!(join.as_mut().poll(&mut cx).is_pending());
        assert_eq!([polls(0), polls(1), polls(2)], [1, 1, 1]);
        // A poll with no wake-up polls no worker.
        assert!(join.as_mut().poll(&mut cx).is_pending());
        assert_eq!([polls(0), polls(1), polls(2)], [1, 1, 1]);

        wake(1);
        assert_eq!(task.0.load(Ordering::SeqCst), 1);
        assert!(join.as_mut().poll(&mut cx).is_pending());
        assert_eq!([polls(0), polls(1), polls(2)], [1, 2, 1]);

        // Two wake-ups before the next poll: both workers are polled once.
        probes[0].1.store(true, Ordering::SeqCst);
        wake(0);
        wake(2);
        assert!(join.as_mut().poll(&mut cx).is_pending());
        assert_eq!([polls(0), polls(1), polls(2)], [2, 2, 2]);

        probes[1].1.store(true, Ordering::SeqCst);
        probes[2].1.store(true, Ordering::SeqCst);
        wake(1);
        wake(2);
        assert!(join.as_mut().poll(&mut cx).is_ready());
        assert_eq!([polls(0), polls(1), polls(2)], [2, 3, 3]);
    }

    /// At the first error the call stops the upload and waits for the other
    /// workers, and it gives each error.
    #[test]
    fn join_stops_at_the_first_error_and_waits_for_every_worker() {
        let stopped = AtomicBool::new(false);
        let workers: Vec<Worker<'_>> = vec![
            Box::pin(async { Err(invalid("first")) }),
            Box::pin(async {
                // The worker yields once, so it ends after the error.
                futures_lite::future::yield_now().await;
                Ok(())
            }),
            Box::pin(async { Err(Error::Transport("second".into())) }),
        ];
        let errors = ostrya_rt::block_on(join_workers(workers, || {
            stopped.store(true, Ordering::SeqCst)
        }));
        assert!(stopped.load(Ordering::SeqCst));
        assert_eq!(errors.len(), 2);
        // A call with no worker ends at once.
        assert!(ostrya_rt::block_on(join_workers(Vec::new(), || {})).is_empty());
    }

    /// A call runs one stream for each permit, no more than one for each
    /// name, and one for a call with no name.
    #[test]
    fn the_streams_of_a_call_are_bounded_by_the_permits_and_the_names() {
        assert_eq!(worker_count(1, 1000), 1);
        assert_eq!(worker_count(3, 1000), 3);
        assert_eq!(worker_count(31, 2), 2);
        assert_eq!(worker_count(4, 0), 1);
        assert_eq!(worker_count(4, 1), 1);
        assert_eq!(worker_count(4, 4), 4);
    }

    /// An error of the client wins over an error of the server, which wins
    /// over the error of a step that the abort of the session failed.
    #[test]
    fn the_error_of_a_call_is_chosen_by_rank() {
        let source = Error::Source("read failed".into());
        let local = invalid("bad data");
        let server = Error::ChecksumMismatch("object".into());
        let cascade = Error::Protocol(format!("{SESSION_ABORTED}: checksum-mismatch"));
        let other = Error::Io(std::io::ErrorKind::BrokenPipe.into());
        assert_eq!(rank(&source), 0);
        assert_eq!(rank(&local), 0);
        assert_eq!(rank(&server), 1);
        assert_eq!(rank(&Error::Protocol("bad frame".into())), 1);
        assert_eq!(rank(&cascade), 2);
        assert_eq!(rank(&other), 2);
        assert_eq!(rank(&Error::Transport("x".into())), 2);
    }
}
