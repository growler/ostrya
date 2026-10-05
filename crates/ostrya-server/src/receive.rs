//! The receive endpoint: the push sessions over HTTP.
//!
//! Each request carries one step of a session of [`ReceiveService`]. The
//! bodies of `session`, `have`, and `commit` hold one frame, and the body of
//! `objects` holds one object stream. Each response body is one frame: the
//! reply of the step, or an `Error`.

use std::future::Future;
use std::sync::Arc;

use futures_lite::future;
use hyper::body::{Body, Bytes, Frame};
use hyper::header::{
    ALLOW, CONNECTION, CONTENT_LENGTH, HeaderName, HeaderValue, TRANSFER_ENCODING,
};
use hyper::{Method, Request, Response, StatusCode, Version};
use ostrya::push::proto::{ErrorMessage, MAX_FRAME, Message};
use ostrya::push::{self, ErrorCode};
use ostrya::{ReceiveReport, ReceiveService, ReceiveStep, ReceiveWarning, Repo};
use ostrya_rt as rt;

use crate::body::ServeBody;
use crate::receive_auth::{ReceiveAuth, Refusal, RequestKind};
use crate::request::{RequestBody, drain, read_message};
use crate::router::empty;
use crate::session::{Active, Begin, Cancel, Deleted, SessionId, SessionTable};

/// The path prefix of the endpoint. No repository layout uses it.
pub(crate) const PREFIX: &str = "/_ostrya/receive/v1/";

/// The response header that carries the id of a new session.
const SESSION_HEADER: HeaderName = HeaderName::from_static("ostrya-session");

/// The headers of a refusal of the host that the endpoint drops, because it
/// sets the framing and the connection state of the response itself.
const OWN_HEADERS: [HeaderName; 3] = [CONTENT_LENGTH, TRANSFER_ENCODING, CONNECTION];

/// The callback of [`ServeOptions::on_report`](crate::ServeOptions::on_report).
pub(crate) type OnReport = Arc<dyn Fn(ReceiveReport) + Send + Sync>;

/// The receive endpoint of a server, with the authentication `A`.
pub(crate) struct Receive<A> {
    pub(crate) repo: Repo,
    pub(crate) auth: A,
    pub(crate) parallel_uploads: u32,
    pub(crate) on_report: Option<OnReport>,
    pub(crate) table: Arc<SessionTable>,
}

/// A request path under [`PREFIX`].
#[derive(Clone, Copy)]
enum Route {
    /// `session`: open a session.
    Open,
    /// `session/ID`: end a session.
    Session(SessionId),
    /// `session/ID/STEP`: one step of a session.
    Step(SessionId, Step),
}

#[derive(Clone, Copy)]
enum Step {
    Have,
    Objects,
    Commit,
}

impl Route {
    /// The route of the raw request path `path`, with no percent-decoding.
    fn parse(path: &str) -> Option<Route> {
        let rest = path.strip_prefix(PREFIX)?;
        if rest == "session" {
            return Some(Route::Open);
        }
        let rest = rest.strip_prefix("session/")?;
        let (id, step) = match rest.split_once('/') {
            Some((id, step)) => (id, Some(step)),
            None => (rest, None),
        };
        let id = SessionId::parse(id)?;
        Some(match step {
            None => Route::Session(id),
            Some("have") => Route::Step(id, Step::Have),
            Some("objects") => Route::Step(id, Step::Objects),
            Some("commit") => Route::Step(id, Step::Commit),
            Some(_) => return None,
        })
    }

    /// The kind of the route, which the authentication gets.
    fn kind(self) -> RequestKind {
        match self {
            Route::Open => RequestKind::Open,
            Route::Session(_) => RequestKind::Delete,
            Route::Step(_, Step::Have) => RequestKind::Have,
            Route::Step(_, Step::Objects) => RequestKind::Objects,
            Route::Step(_, Step::Commit) => RequestKind::Commit,
        }
    }

    /// The method of the route.
    fn method(self) -> Method {
        match self {
            Route::Session(_) => Method::DELETE,
            Route::Open | Route::Step(..) => Method::POST,
        }
    }

    /// The `Allow` header of the route.
    fn allow(self) -> HeaderValue {
        HeaderValue::from_static(match self {
            Route::Session(_) => "DELETE",
            Route::Open | Route::Step(..) => "POST",
        })
    }
}

impl<A: ReceiveAuth> Receive<A> {
    /// The response to a request under [`PREFIX`] with a method other than
    /// `GET` and `HEAD`, which go to the archive view. The authentication
    /// runs before a byte of the body is read.
    pub(crate) async fn handle<B>(&self, req: Request<B>) -> Response<ServeBody>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let version = req.version();
        let Some(route) = Route::parse(req.uri().path()) else {
            let response = empty(StatusCode::NOT_FOUND);
            return self.refuse(version, req.into_body(), response).await;
        };
        if *req.method() != route.method() {
            let mut response = empty(StatusCode::METHOD_NOT_ALLOWED);
            response.headers_mut().insert(ALLOW, route.allow());
            return self.refuse(version, req.into_body(), response).await;
        }
        let (parts, body) = req.into_parts();
        let principal = self.auth.authenticate(&parts, route.kind()).await;
        // The read of the body and the steps of the session do not hold the
        // head of the request.
        drop(parts);
        let principal = match principal {
            Ok(principal) => principal,
            Err(refusal) => {
                return self.refuse(version, body, refusal_response(refusal)).await;
            }
        };
        let owner = A::owner(&principal);
        match route {
            Route::Open => self.open(&principal, body).await,
            Route::Session(id) => {
                let response = match self.table.delete(&id, owner) {
                    Deleted::Done => no_content(),
                    Deleted::Committing => failure(&committing()),
                    Deleted::NotFound => empty(StatusCode::NOT_FOUND),
                };
                self.refuse(version, body, response).await
            }
            Route::Step(id, step) => {
                let Some(mut active) = self.table.lookup(&id, owner) else {
                    let response = empty(StatusCode::NOT_FOUND);
                    return self.refuse(version, body, response).await;
                };
                let body = RequestBody::new(body, Some(active.track()));
                let response = match step {
                    Step::Have => have(&active, body).await,
                    Step::Objects => objects(&active, body).await,
                    Step::Commit => self.commit(&active, body).await,
                };
                active.complete();
                response
            }
        }
    }

    /// Answer a request of `version` with `response` before its `body` is
    /// read. The body is read and dropped first, up to 1 MiB within the idle
    /// timeout or 5 seconds, whichever is shorter, so the client can read
    /// the response. On HTTP/1 a body that did not reach its end closes the
    /// connection after the response.
    async fn refuse<B>(
        &self,
        version: Version,
        body: B,
        mut response: Response<ServeBody>,
    ) -> Response<ServeBody>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let drained = drain(body, self.table.idle()).await;
        if !drained && version <= Version::HTTP_11 {
            response
                .headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }
        response
    }

    /// `POST session` of `principal`: read `Hello`, refuse a `Hello` with
    /// `one-way` true, check `Hello`, take a slot of the session limit, get
    /// the setup of the session from the authentication, and open the
    /// session. The body must arrive in full within the idle timeout. A
    /// refusal of the authentication frees the slot.
    async fn open<B>(&self, principal: &A::Principal, body: B) -> Response<ServeBody>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let mut body = RequestBody::new(body, None);
        let read = future::or(async { Some(read_message(&mut body).await) }, async {
            rt::Timer::after(self.table.idle()).await;
            None
        })
        .await;
        let hello = match read {
            Some(Ok(Message::Hello(hello))) => hello,
            Some(Ok(other)) => {
                return failure(&protocol(format!("{:?} in place of Hello", other.kind())));
            }
            Some(Err(e)) => return failure(&e.into()),
            None => {
                return failure(&protocol(
                    "the request body did not arrive within the idle timeout",
                ));
            }
        };
        drop(body);
        // The text of the refusal of `ReceiveService::hello`, which comes
        // before the check of the version.
        if hello.one_way {
            return failure(&protocol(
                "a Hello with one-way true opens a one-way stream, which this session does not \
                 read",
            ));
        }
        if let Err(e) = ReceiveService::check_hello(&self.repo, &hello) {
            return failure(&e);
        }
        let Some(slot) = self.table.reserve() else {
            return no_more_sessions();
        };
        let id = match SessionId::new() {
            Ok(id) => id,
            Err(e) => {
                let message = error_message(
                    ErrorCode::Internal,
                    format!("the random source of the session id failed: {e}"),
                );
                return frame(StatusCode::INTERNAL_SERVER_ERROR, &message);
            }
        };
        let setup = match self.auth.open(principal, &hello).await {
            Ok(setup) => setup,
            Err(refusal) => return refusal_response(refusal),
        };
        let opened = ReceiveService::hello(
            self.repo.clone(),
            setup.policy,
            self.parallel_uploads,
            hello,
        )
        .await;
        let (service, reply) = match opened {
            Ok(opened) => opened,
            Err(e) => return failure(&e),
        };
        let bytes = match encode(&Message::HelloReply(reply)) {
            Ok(bytes) => bytes,
            // `check_hello` refuses a `Hello` whose reply, with a commit for
            // each ref, is over the frame limit, so this arm is not reached.
            Err(e) => {
                debug_assert!(false, "the reply of a Hello does not fit: {e}");
                return failure(&e.into());
            }
        };
        if !slot.insert(id, service, A::owner(principal).to_owned()) {
            return no_more_sessions();
        }
        let mut response = full(StatusCode::OK, bytes);
        let value = HeaderValue::from_str(&id.to_string()).expect("hex is a header value");
        response.headers_mut().insert(SESSION_HEADER, value);
        response
    }

    /// `POST session/ID/commit`: read `Commit`, and run the commit in a task
    /// of its own, which no disconnect, `DELETE`, or idle timeout stops. A
    /// session that commits already gets `protocol`, and its commit goes on.
    /// The task ends the session when the commit ends: with the cause of a
    /// commit when it succeeded, and with the cause of a failed request when
    /// it failed, panicked, or was dropped.
    async fn commit<B>(&self, active: &Active, mut body: RequestBody<B>) -> Response<ServeBody>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let read = cancellable(active.cancel(), async {
            match read_message(&mut body).await? {
                Message::Commit(request) => Ok(request),
                other => Err(protocol(format!("{:?} in place of Commit", other.kind()))),
            }
        })
        .await;
        drop(body);
        let request = match read {
            None => return failure(&aborted(active.cancel())),
            Some(Ok(request)) => request,
            Some(Err(e)) => {
                active.table().fail(&active.id());
                return failure(&e);
            }
        };
        let mut end = match active.begin_commit() {
            Begin::Started(end) => end,
            Begin::Committing => return failure(&committing()),
            Begin::Ended => return failure(&aborted(active.cancel())),
        };
        let service = active.service().clone();
        let on_report = self.on_report.clone();
        let task = rt::spawn(async move {
            let result = service.commit(request).await;
            if result.is_ok() {
                end.committed();
            }
            drop(end);
            result.map(|report| Delivery {
                report: Some(report),
                on_report,
                delivered: false,
            })
        });
        match task.await {
            Ok(delivery) => {
                let reply = Message::CommitReply(delivery.report().refs.clone());
                match encode(&reply) {
                    Ok(bytes) => reply_response(bytes, delivery),
                    // The commit refuses updates whose longest reply is over
                    // the frame limit before it writes a ref, so this arm is
                    // not reached. It stays as a guard: an error here follows
                    // a commit that wrote its refs.
                    Err(e) => {
                        debug_assert!(false, "the reply of a commit does not fit: {e}");
                        failure(&e.into())
                    }
                }
            }
            Err(e) => failure(&e),
        }
    }
}

/// `POST session/ID/have`: read `Have`, and answer it.
async fn have<B>(active: &Active, mut body: RequestBody<B>) -> Response<ServeBody>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let result = cancellable(active.cancel(), async {
        let names = match read_message(&mut body).await? {
            Message::Have(names) => names,
            other => return Err(protocol(format!("{:?} in place of Have", other.kind()))),
        };
        drop(body);
        active.service().have(names).await
    })
    .await;
    step_response(active, result.map(|r| r.map(Message::HaveReply)))
}

/// `POST session/ID/objects`: read one object stream.
async fn objects<B>(active: &Active, body: RequestBody<B>) -> Response<ServeBody>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let result = cancellable(active.cancel(), active.service().objects(body)).await;
    step_response(active, result.map(|r| r.map(Message::ObjectsReply)))
}

/// The response of a step: its reply, its error, or the cause that ended
/// the session while it ran. A failed step ends the session.
fn step_response(active: &Active, result: Option<ostrya::Result<Message>>) -> Response<ServeBody> {
    match result {
        None => failure(&aborted(active.cancel())),
        Some(Ok(reply)) => match encode(&reply) {
            Ok(bytes) => full(StatusCode::OK, bytes),
            Err(e) => {
                active.table().fail(&active.id());
                failure(&e.into())
            }
        },
        Some(Err(e)) => {
            active.table().fail(&active.id());
            failure(&e)
        }
    }
}

/// Run `step` until it completes, or until the session ends. `None` when the
/// session ended first, and the step is dropped. The end of the session is
/// checked first, so a step that the end of the session fails reports the
/// cause of the end.
async fn cancellable<T>(cancel: &Cancel, step: impl Future<Output = T>) -> Option<T> {
    future::or(
        async {
            cancel.wait().await;
            None
        },
        async { Some(step.await) },
    )
    .await
}

fn protocol(message: impl Into<String>) -> ostrya::Error {
    ostrya::Error::Push(push::Error::Protocol(message.into()))
}

/// The error of a request that finds its session committing.
fn committing() -> ostrya::Error {
    protocol("the session is committing")
}

/// The error of a request of a session that the host ended.
fn aborted(cancel: &Cancel) -> ostrya::Error {
    protocol(format!("the session was aborted: {}", cancel.cause()))
}

fn error_message(code: ErrorCode, message: String) -> ErrorMessage {
    ErrorMessage {
        code,
        message,
        missing: Vec::new(),
        current: None,
    }
}

/// The status and the `Error` message of a failed request.
/// `ref-mismatch` and `non-fast-forward` get 409, `internal` and each error
/// with no wire code get 500, `unauthorized` gets 403, and every other code
/// gets 422. An error with no wire code is `internal` with its text. The
/// service gives no `unauthorized`: the refusal of the authorization states
/// its own status, 401 or 403.
pub(crate) fn status(e: &ostrya::Error) -> (StatusCode, ErrorMessage) {
    let message = match e {
        ostrya::Error::Push(e) => e.to_message(),
        other => error_message(ErrorCode::Internal, other.to_string()),
    };
    let status = match message.code {
        ErrorCode::RefMismatch | ErrorCode::NonFastForward => StatusCode::CONFLICT,
        ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        ErrorCode::Unauthorized => StatusCode::FORBIDDEN,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    (status, message)
}

/// The response of a refusal of the authentication: its status, an
/// `unauthorized` frame with its message, and its headers in order, except
/// the headers that the endpoint sets itself.
fn refusal_response(refusal: Refusal) -> Response<ServeBody> {
    let Refusal {
        status,
        message,
        headers,
    } = refusal;
    let mut response = frame(status, &error_message(ErrorCode::Unauthorized, message));
    let out = response.headers_mut();
    for (name, value) in headers {
        if !OWN_HEADERS.contains(&name) {
            out.append(name, value);
        }
    }
    response
}

/// The 503 of a `session` request that gets no slot: the sessions are at
/// the limit, or the server stopped.
fn no_more_sessions() -> Response<ServeBody> {
    let message = error_message(
        ErrorCode::LimitExceeded,
        "the server serves no more sessions".into(),
    );
    frame(StatusCode::SERVICE_UNAVAILABLE, &message)
}

/// The 204 of a `DELETE`, with no body and no `Content-Length`, which a 204
/// must not carry.
fn no_content() -> Response<ServeBody> {
    let mut response = Response::new(ServeBody::Empty);
    *response.status_mut() = StatusCode::NO_CONTENT;
    response
}

/// The response of a failed request.
fn failure(e: &ostrya::Error) -> Response<ServeBody> {
    let (status, message) = status(e);
    frame(status, &message)
}

/// A response of `status` with the `Error` frame of `message`. A message
/// past the frame limit goes as `internal` with a short text.
fn frame(status: StatusCode, message: &ErrorMessage) -> Response<ServeBody> {
    match encode(&Message::Error(message.clone())) {
        Ok(bytes) => full(status, bytes),
        Err(e) => {
            let message = error_message(
                ErrorCode::Internal,
                format!("the error of the request does not fit in a frame: {e}"),
            );
            let bytes = encode(&Message::Error(message)).expect("a short error fits in a frame");
            full(StatusCode::INTERNAL_SERVER_ERROR, bytes)
        }
    }
}

/// The frame of `msg`: the length, the kind, and the body. A frame past
/// [`MAX_FRAME`] is `limit-exceeded`.
fn encode(msg: &Message) -> Result<Bytes, push::Error> {
    let body = msg.encode_body()?;
    let len = u32::try_from(body.len() + 1)
        .ok()
        .filter(|len| *len <= MAX_FRAME)
        .ok_or_else(|| {
            push::Error::LimitExceeded(format!(
                "a reply frame of {} bytes is over the limit {MAX_FRAME}",
                body.len() + 1
            ))
        })?;
    let mut frame = Vec::with_capacity(4 + len as usize);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.push(msg.kind().as_u8());
    frame.extend_from_slice(&body);
    Ok(Bytes::from(frame))
}

/// A response of `status` with `bytes` as its body.
fn full(status: StatusCode, bytes: Bytes) -> Response<ServeBody> {
    let len = bytes.len() as u64;
    let mut response = Response::new(ServeBody::Full(Some(bytes)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from(len));
    response
}

/// The 200 response of a commit, whose body gives the report to
/// `on_report` when it drops.
fn reply_response(bytes: Bytes, delivery: Delivery) -> Response<ServeBody> {
    let len = bytes.len() as u64;
    let mut response = Response::new(ServeBody::Reply(ReplyBody {
        frame: Some(bytes),
        delivery,
    }));
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from(len));
    response
}

/// The report of a commit on its way to the client. When it drops, it gives
/// the report to `on_report`, with a warning of the step
/// [`ReceiveStep::ReplyNotDelivered`] unless the connection took the
/// `CommitReply` frame. The connection took the frame when hyper polled it
/// from the body. hyper can still fail to write it, so the warning is best
/// effort.
pub(crate) struct Delivery {
    report: Option<ReceiveReport>,
    on_report: Option<OnReport>,
    delivered: bool,
}

impl Delivery {
    fn report(&self) -> &ReceiveReport {
        self.report.as_ref().expect("the report goes at the drop")
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        let Some(mut report) = self.report.take() else {
            return;
        };
        if !self.delivered {
            report.warnings.push(ReceiveWarning {
                step: ReceiveStep::ReplyNotDelivered,
                message: "the connection did not take the CommitReply response".into(),
            });
        }
        if let Some(on_report) = &self.on_report {
            on_report(report);
        }
    }
}

/// The body of the response of a commit: the `CommitReply` frame, and the
/// report it delivers.
pub(crate) struct ReplyBody {
    frame: Option<Bytes>,
    delivery: Delivery,
}

impl ReplyBody {
    pub(crate) fn poll_frame(&mut self) -> Option<Frame<Bytes>> {
        let bytes = self.frame.take()?;
        self.delivery.delivered = true;
        Some(Frame::data(bytes))
    }

    pub(crate) fn remaining(&self) -> u64 {
        self.frame.as_ref().map_or(0, |b| b.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io;
    use std::marker::PhantomData;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use hyper::header::WWW_AUTHENTICATE;
    use hyper::http::request::Parts;

    use super::*;
    use crate::ServeOptions;
    use crate::SessionSetup;
    use crate::auth::{FileAuth, Peer};
    use crate::body::tests::frames;
    use crate::request::MAX_DRAIN;
    use crate::session::tests::TmpRepo;
    use ostrya::push::proto::{CommitRequest, Hello, Kind};
    use ostrya::push::{Expected, RefOutcome, RefUpdate};
    use ostrya::{Checksum, ObjectName, ObjectType, ReceivePolicy, ReceiveRule, TransactionStats};
    use ostrya_rt::block_on;

    #[test]
    fn errors_map_to_their_status() {
        let cases: Vec<(ostrya::Error, u16, ErrorCode)> = vec![
            (
                push::Error::RefMismatch {
                    message: "m".into(),
                    name: "main".into(),
                    current: None,
                }
                .into(),
                409,
                ErrorCode::RefMismatch,
            ),
            (
                push::Error::NonFastForward("m".into()).into(),
                409,
                ErrorCode::NonFastForward,
            ),
            (
                push::Error::Internal("m".into()).into(),
                500,
                ErrorCode::Internal,
            ),
            (
                push::Error::Protocol("m".into()).into(),
                422,
                ErrorCode::Protocol,
            ),
            (
                push::Error::ModeRefused("m".into()).into(),
                422,
                ErrorCode::ModeRefused,
            ),
            (
                push::Error::LimitExceeded("m".into()).into(),
                422,
                ErrorCode::LimitExceeded,
            ),
            (
                push::Error::MissingObjects {
                    message: "m".into(),
                    missing: Vec::new(),
                }
                .into(),
                422,
                ErrorCode::MissingObjects,
            ),
            (
                push::Error::Unauthorized("m".into()).into(),
                403,
                ErrorCode::Unauthorized,
            ),
            (push::Error::Aborted.into(), 500, ErrorCode::Internal),
            (
                ostrya::Error::Io(std::io::ErrorKind::Other.into()),
                500,
                ErrorCode::Internal,
            ),
            (
                ostrya::Error::InvalidFormat("bad".into()),
                500,
                ErrorCode::Internal,
            ),
        ];
        for (e, want, code) in cases {
            let (got, message) = status(&e);
            assert_eq!(got.as_u16(), want, "{e}");
            assert_eq!(message.code, code, "{e}");
        }
        let (_, message) = status(&ostrya::Error::InvalidFormat("bad".into()));
        assert!(message.message.contains("bad"), "{}", message.message);
        let (_, message) = status(
            &push::Error::RefMismatch {
                message: "m".into(),
                name: "main".into(),
                current: None,
            }
            .into(),
        );
        assert_eq!(message.current.unwrap().name, "main");
    }

    /// Every response that the endpoint builds itself goes without
    /// `Content-Type` and without `Retry-After`, and a frame response states
    /// its length.
    #[test]
    fn a_frame_response_has_its_length_and_no_type() {
        let response = failure(&protocol("x"));
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(response.headers().get("content-type").is_none());
        assert!(response.headers().get("retry-after").is_none());
        let len: u64 = response.headers()[CONTENT_LENGTH]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let bytes = block_on(frames(response.into_body())).unwrap().concat();
        assert_eq!(bytes.len() as u64, len);
        assert_eq!(&bytes[4..5], &[10u8], "the kind of an Error frame");
    }

    fn report() -> ReceiveReport {
        ReceiveReport {
            refs: Vec::new(),
            stats: TransactionStats::default(),
            warnings: Vec::new(),
        }
    }

    /// The report of a commit reaches `on_report` once, with a warning of
    /// `ReplyNotDelivered` when the body dropped before hyper took its frame.
    #[test]
    fn an_undelivered_reply_adds_a_warning() {
        let seen = Arc::new(Mutex::new(Vec::<ReceiveReport>::new()));
        let sink = seen.clone();
        let on_report: OnReport = Arc::new(move |report| sink.lock().unwrap().push(report));
        let body = |on_report: &OnReport| ReplyBody {
            frame: Some(Bytes::from_static(b"frame")),
            delivery: Delivery {
                report: Some(report()),
                on_report: Some(on_report.clone()),
                delivered: false,
            },
        };

        drop(body(&on_report));
        let mut taken = body(&on_report);
        assert_eq!(taken.remaining(), 5);
        assert!(taken.poll_frame().is_some());
        assert_eq!(taken.remaining(), 0);
        assert!(taken.poll_frame().is_none());
        drop(taken);

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].warnings.len(), 1);
        assert_eq!(seen[0].warnings[0].step, ReceiveStep::ReplyNotDelivered);
        assert!(seen[1].warnings.is_empty());
    }

    #[test]
    fn routes_take_the_raw_path() {
        let id = "ab".repeat(32);
        let ok = |path: &str| Route::parse(path).map(|r| r.method());
        assert_eq!(ok("/_ostrya/receive/v1/session"), Some(Method::POST));
        assert_eq!(
            ok(&format!("/_ostrya/receive/v1/session/{id}")),
            Some(Method::DELETE)
        );
        for step in ["have", "objects", "commit"] {
            assert_eq!(
                ok(&format!("/_ostrya/receive/v1/session/{id}/{step}")),
                Some(Method::POST)
            );
        }
        let upper = id.to_ascii_uppercase();
        for bad in [
            "/_ostrya/receive/v1/".to_string(),
            "/_ostrya/receive/v1/session/".to_string(),
            "/_ostrya/receive/v1/%73ession".to_string(),
            format!("/_ostrya/receive/v1/session/{upper}"),
            format!("/_ostrya/receive/v1/session/{id}/"),
            format!("/_ostrya/receive/v1/session/{id}/other"),
            format!("/_ostrya/receive/v1/session/{id}/have/x"),
        ] {
            assert!(ok(&bad).is_none(), "{bad}");
        }
    }

    /// One step of a [`Pieces`] body.
    enum Piece {
        Bytes(Bytes),
        /// `Pending` once, with the task woken at once.
        Wait,
        /// An error of the body.
        Fail,
    }

    /// A request body that gives its bytes in pieces, with a wait before
    /// each piece. It has the shape of the body of a router: `Send` and
    /// `Unpin`, and not `Sync`.
    struct Pieces {
        steps: VecDeque<Piece>,
        _not_sync: PhantomData<Cell<()>>,
    }

    impl Pieces {
        /// The body of `bytes` in pieces of `size` bytes. With `fail_after`,
        /// the body fails in place of the piece of that index.
        fn new(bytes: &[u8], size: usize, fail_after: Option<usize>) -> Pieces {
            let mut steps = VecDeque::new();
            for (index, piece) in bytes.chunks(size).enumerate() {
                steps.push_back(Piece::Wait);
                if fail_after == Some(index) {
                    steps.push_back(Piece::Fail);
                    break;
                }
                steps.push_back(Piece::Bytes(Bytes::copy_from_slice(piece)));
            }
            Pieces {
                steps,
                _not_sync: PhantomData,
            }
        }
    }

    impl Body for Pieces {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
            match self.steps.pop_front() {
                None => Poll::Ready(None),
                Some(Piece::Bytes(bytes)) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                Some(Piece::Wait) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Some(Piece::Fail) => Poll::Ready(Some(Err(io::Error::other("the body broke")))),
            }
        }
    }

    /// `Pieces` is `Send` and `Unpin`, and not `Sync`. The second check is
    /// ambiguous, and does not compile, for a type that is `Sync`.
    const _: fn() = || {
        fn send_unpin<T: Send + Unpin>() {}
        send_unpin::<Pieces>();

        trait NotSync<A> {
            fn check() {}
        }
        impl<T: ?Sized> NotSync<()> for T {}
        struct IsSync;
        impl<T: ?Sized + Sync> NotSync<IsSync> for T {}
        <Pieces as NotSync<_>>::check();
    };

    /// `future`, which must be `Send`.
    fn send<F: Future + Send>(future: F) -> F {
        future
    }

    /// An endpoint over `tmp` with the authentication `auth` and at most
    /// `max` sessions.
    fn endpoint_with<A: ReceiveAuth>(tmp: &TmpRepo, max: usize, auth: A) -> Receive<A> {
        Receive {
            repo: tmp.repo.clone(),
            auth,
            parallel_uploads: 1,
            on_report: None,
            table: SessionTable::new(max, Duration::from_secs(60)),
        }
    }

    /// An endpoint over `tmp` with anonymous push and at most `max`
    /// sessions.
    fn endpoint(tmp: &TmpRepo, max: usize) -> Receive<FileAuth> {
        let opts = ServeOptions {
            allow_anonymous_push: true,
            ..ServeOptions::default()
        };
        let auth = FileAuth::new(&opts, Arc::new(ReceivePolicy::default())).unwrap();
        endpoint_with(tmp, max, auth)
    }

    /// The response to a `POST` of `path` under [`PREFIX`], with the frame of
    /// `message` as a [`Pieces`] body in pieces of 3 bytes.
    async fn post<A: ReceiveAuth>(
        receive: &Receive<A>,
        path: &str,
        message: &Message,
        fail_after: Option<usize>,
    ) -> Response<ServeBody> {
        post_as(receive, "anonymous", path, message, fail_after).await
    }

    /// [`post`] with the header `x-principal: principal`, which [`TestAuth`]
    /// reads. The request carries the peer of a connection over plain HTTP,
    /// as each request of the server does.
    async fn post_as<A: ReceiveAuth>(
        receive: &Receive<A>,
        principal: &str,
        path: &str,
        message: &Message,
        fail_after: Option<usize>,
    ) -> Response<ServeBody> {
        let bytes = encode(message).unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("{PREFIX}{path}"))
            .header("x-principal", principal)
            .extension(Peer {
                tls: false,
                cert: None,
            })
            .body(Pieces::new(&bytes, 3, fail_after))
            .unwrap();
        send(receive.handle(req)).await
    }

    /// The status of `response`, and the message of its body.
    async fn answer(response: Response<ServeBody>) -> (StatusCode, Message) {
        let status = response.status();
        let bytes = frames(response.into_body()).await.unwrap().concat();
        let message = Message::decode(Kind::from_u8(bytes[4]).unwrap(), &bytes[5..]).unwrap();
        (status, message)
    }

    fn hello() -> Message {
        Message::Hello(Hello {
            version: 1,
            agent: None,
            refs: vec!["main".into()],
            one_way: false,
        })
    }

    fn delete_main() -> Message {
        Message::Commit(CommitRequest {
            updates: vec![RefUpdate {
                name: "main".into(),
                expected: Expected::Absent,
                new: None,
            }],
            force: false,
        })
    }

    /// Open a session, and give its id.
    async fn open<A: ReceiveAuth>(receive: &Receive<A>) -> String {
        open_as(receive, "anonymous").await
    }

    /// Open a session of `principal`, and give its id.
    async fn open_as<A: ReceiveAuth>(receive: &Receive<A>, principal: &str) -> String {
        let response = post_as(receive, principal, "session", &hello(), None).await;
        let id = response.headers()[SESSION_HEADER]
            .to_str()
            .unwrap()
            .to_owned();
        let (status, reply) = answer(response).await;
        assert_eq!(status, StatusCode::OK);
        assert!(matches!(reply, Message::HelloReply(_)), "{reply:?}");
        id
    }

    /// The `Error` message of a failed step.
    fn error(reply: Message) -> ErrorMessage {
        match reply {
            Message::Error(e) => e,
            other => panic!("{other:?}"),
        }
    }

    /// Each step of a session takes a body that is not `Sync`, and the
    /// future of the request is `Send`. A body that fails inside its frame
    /// is `internal` and ends the session, and after its response an
    /// `open` whose body fails holds no slot.
    #[test]
    fn the_steps_take_a_body_that_is_not_sync() {
        let tmp = TmpRepo::new("receive-steps");
        let receive = endpoint(&tmp, 2);
        block_on(async {
            let id = open(&receive).await;
            let absent = ObjectName::new(Checksum::sha256(b"absent"), ObjectType::DirTree);
            let have = Message::Have(vec![absent]);
            let response = post(&receive, &format!("session/{id}/have"), &have, None).await;
            let (status, reply) = answer(response).await;
            assert_eq!(status, StatusCode::OK);
            let Message::HaveReply(reply) = reply else {
                panic!("{reply:?}");
            };
            assert!(reply.is_missing(0));

            let end = Message::ObjectsEnd;
            let response = post(&receive, &format!("session/{id}/objects"), &end, None).await;
            let (status, reply) = answer(response).await;
            assert_eq!(status, StatusCode::OK);
            let Message::ObjectsReply(reply) = reply else {
                panic!("{reply:?}");
            };
            assert_eq!(reply.objects, 0);

            let commit = delete_main();
            let response = post(&receive, &format!("session/{id}/commit"), &commit, None).await;
            let (status, reply) = answer(response).await;
            assert_eq!(status, StatusCode::OK);
            let Message::CommitReply(refs) = reply else {
                panic!("{reply:?}");
            };
            let outcome = RefOutcome {
                name: "main".into(),
                old: None,
                new: None,
            };
            assert_eq!(refs, vec![outcome]);
            let id = SessionId::parse(&id).unwrap();
            assert!(receive.table.lookup(&id, "anonymous").is_none());

            let id = open(&receive).await;
            let response = post(&receive, &format!("session/{id}/commit"), &commit, Some(2)).await;
            let (status, reply) = answer(response).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            let e = error(reply);
            assert_eq!(e.code, ErrorCode::Internal);
            assert!(e.message.contains("the body broke"), "{}", e.message);
            let response = post(&receive, &format!("session/{id}/have"), &have, None).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);

            let response = post(&receive, "session", &hello(), Some(1)).await;
            let (status, reply) = answer(response).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            let e = error(reply);
            assert_eq!(e.code, ErrorCode::Internal);
            assert!(e.message.contains("the body broke"), "{}", e.message);
            open(&receive).await;
            open(&receive).await;
            let response = post(&receive, "session", &hello(), None).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            receive.table.close_all();
        });
    }

    /// A refusal drains a body that is not `Sync`. A body that reaches its
    /// end keeps the connection, and a body that fails closes it.
    #[test]
    fn a_refusal_drains_a_body_that_is_not_sync() {
        let tmp = TmpRepo::new("receive-refusal");
        let receive = endpoint(&tmp, 1);
        block_on(async {
            let response = post(&receive, "nope", &hello(), None).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert!(response.headers().get(CONNECTION).is_none());
            let response = post(&receive, "nope", &hello(), Some(1)).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(response.headers()[CONNECTION], "close");
        });
    }

    /// An authentication of a host for the tests. The principal of a
    /// request is its `x-principal` header. `authenticate` refuses the
    /// principal `deny`. `open` refuses the principal `forbidden`, gives the
    /// principal `strict` a policy that accepts no update, and gives each
    /// other principal the default policy.
    struct TestAuth {
        /// The bytes that an [`Endless`] body of the test gave.
        polled: Arc<AtomicU64>,
        /// `polled` when `authenticate` last ran, `u64::MAX` before.
        polled_at_authenticate: AtomicU64,
        /// The count of `open` calls.
        opens: AtomicUsize,
    }

    impl TestAuth {
        fn new() -> TestAuth {
            TestAuth {
                polled: Arc::new(AtomicU64::new(0)),
                polled_at_authenticate: AtomicU64::new(u64::MAX),
                opens: AtomicUsize::new(0),
            }
        }

        fn opens(&self) -> usize {
            self.opens.load(Ordering::SeqCst)
        }
    }

    const REASON: HeaderName = HeaderName::from_static("x-reason");

    impl ReceiveAuth for TestAuth {
        type Principal = String;

        fn owner(principal: &String) -> &str {
            principal
        }

        async fn authenticate(&self, parts: &Parts, _kind: RequestKind) -> Result<String, Refusal> {
            let polled = self.polled.load(Ordering::SeqCst);
            self.polled_at_authenticate.store(polled, Ordering::SeqCst);
            let principal = parts.headers["x-principal"].to_str().unwrap();
            if principal == "deny" {
                let refusal = Refusal::unauthorized("the test denies the request")
                    .with_header(REASON, HeaderValue::from_static("deny"));
                return Err(refusal);
            }
            Ok(principal.to_owned())
        }

        async fn open(&self, principal: &String, _hello: &Hello) -> Result<SessionSetup, Refusal> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            let policy = match principal.as_str() {
                "forbidden" => {
                    let value = HeaderValue::from_static;
                    let refusal = Refusal::forbidden("the test forbids the session")
                        .with_header(WWW_AUTHENTICATE, value("Test first"))
                        .with_header(CONTENT_LENGTH, value("999"))
                        .with_header(TRANSFER_ENCODING, value("chunked"))
                        .with_header(CONNECTION, value("keep-alive"))
                        .with_header(WWW_AUTHENTICATE, value("Test second"))
                        .with_header(REASON, value("forbidden"));
                    return Err(refusal);
                }
                "strict" => ReceivePolicy {
                    default_rule: ReceiveRule {
                        accept: false,
                        ..ReceiveRule::default()
                    },
                    ..ReceivePolicy::default()
                },
                _ => ReceivePolicy::default(),
            };
            Ok(SessionSetup {
                policy: Arc::new(policy),
            })
        }
    }

    /// The bytes of one frame of an [`Endless`] body.
    static CHUNK: [u8; 64 * 1024] = [0; 64 * 1024];

    /// A request body of data frames of 64 KiB without end, which counts the
    /// bytes it gives. It has the shape of the body of a router.
    struct Endless {
        polled: Arc<AtomicU64>,
        _not_sync: PhantomData<Cell<()>>,
    }

    impl Body for Endless {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
            self.polled.fetch_add(CHUNK.len() as u64, Ordering::SeqCst);
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(&CHUNK)))))
        }
    }

    /// A refusal of `authenticate` comes before a byte of the body is read,
    /// also before the lookup of a session. The endpoint then reads at most
    /// the drain limit and one frame of an endless body, and closes the
    /// connection. The response has the status and the headers of the
    /// refusal and an `unauthorized` frame, and no header of the endpoint.
    #[test]
    fn a_refusal_of_authenticate_reads_no_byte_of_the_body() {
        let tmp = TmpRepo::new("receive-auth-refused");
        let receive = endpoint_with(&tmp, 1, TestAuth::new());
        block_on(async {
            let unknown = "ab".repeat(32);
            for path in ["session".to_string(), format!("session/{unknown}/have")] {
                receive.auth.polled.store(0, Ordering::SeqCst);
                let req = Request::builder()
                    .method(Method::POST)
                    .uri(format!("{PREFIX}{path}"))
                    .header("x-principal", "deny")
                    .body(Endless {
                        polled: receive.auth.polled.clone(),
                        _not_sync: PhantomData,
                    })
                    .unwrap();
                let response = send(receive.handle(req)).await;
                let at_authenticate = receive.auth.polled_at_authenticate.load(Ordering::SeqCst);
                assert_eq!(at_authenticate, 0, "{path}");
                let polled = receive.auth.polled.load(Ordering::SeqCst);
                assert!(polled > MAX_DRAIN, "{path}: {polled}");
                assert!(polled <= MAX_DRAIN + CHUNK.len() as u64, "{path}: {polled}");

                assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
                let headers = response.headers();
                assert_eq!(headers[REASON], "deny");
                assert!(headers.get(WWW_AUTHENTICATE).is_none());
                assert_eq!(headers[CONNECTION], "close");
                let (_, reply) = answer(response).await;
                let e = error(reply);
                assert_eq!(e.code, ErrorCode::Unauthorized);
                assert_eq!(e.message, "the test denies the request");
            }
            assert_eq!(receive.auth.opens(), 0);
        });
    }

    /// A refusal of `open` gets its status, its headers in order, and an
    /// `unauthorized` frame with its message. The headers that the endpoint
    /// sets itself are dropped. The refusal frees the slot of the session.
    #[test]
    fn a_refusal_of_open_gets_its_status_and_headers_and_frees_the_slot() {
        let tmp = TmpRepo::new("receive-open-refused");
        let receive = endpoint_with(&tmp, 1, TestAuth::new());
        block_on(async {
            let response = post_as(&receive, "forbidden", "session", &hello(), None).await;
            let headers = response.headers().clone();
            let (status, reply) = answer(response).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let challenges: Vec<_> = headers.get_all(WWW_AUTHENTICATE).iter().collect();
            assert_eq!(challenges, ["Test first", "Test second"]);
            assert_eq!(headers[REASON], "forbidden");
            assert!(headers.get(TRANSFER_ENCODING).is_none());
            assert!(headers.get(CONNECTION).is_none());
            assert!(headers.get(SESSION_HEADER).is_none());
            let lengths: Vec<_> = headers.get_all(CONTENT_LENGTH).iter().collect();
            let frame = encode(&reply).unwrap();
            assert_eq!(lengths, [frame.len().to_string().as_str()]);
            let e = error(reply);
            assert_eq!(e.code, ErrorCode::Unauthorized);
            assert_eq!(e.message, "the test forbids the session");
            assert_eq!(receive.auth.opens(), 1);

            open_as(&receive, "alice").await;
            assert_eq!(receive.auth.opens(), 2);
            receive.table.close_all();
        });
    }

    /// A refusal with a message of 2 MiB keeps its status and its headers,
    /// and its `unauthorized` frame carries the message cut to at most
    /// 4096 bytes at a character boundary.
    #[test]
    fn a_long_refusal_message_is_cut_to_fit_its_frame() {
        let long = format!("a{}", "é".repeat(1 << 20));
        let refusal = Refusal::unauthorized(long.clone())
            .with_header(REASON, HeaderValue::from_static("long"));
        let response = refusal_response(refusal);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[REASON], "long");
        let (_, reply) = block_on(answer(response));
        let e = error(reply);
        assert_eq!(e.code, ErrorCode::Unauthorized);
        assert!(e.message.len() <= 4096, "{}", e.message.len());
        assert!(long.starts_with(&e.message));
        assert!(e.message.len() > 4000, "{}", e.message.len());
    }

    /// The session takes the policy that `open` gives for its principal, and
    /// a request of another principal gets the 404 of an unknown session.
    #[test]
    fn the_policy_of_open_is_the_policy_of_the_session() {
        let tmp = TmpRepo::new("receive-open-policy");
        let receive = endpoint_with(&tmp, 2, TestAuth::new());
        block_on(async {
            let strict = open_as(&receive, "strict").await;
            let alice = open_as(&receive, "alice").await;
            let commit = delete_main();

            let path = format!("session/{strict}/commit");
            let response = post_as(&receive, "alice", &path, &commit, None).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let (status, reply) =
                answer(post_as(&receive, "strict", &path, &commit, None).await).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(error(reply).code, ErrorCode::RefDenied);

            let path = format!("session/{alice}/commit");
            let (status, reply) =
                answer(post_as(&receive, "alice", &path, &commit, None).await).await;
            assert_eq!(status, StatusCode::OK);
            assert!(matches!(reply, Message::CommitReply(_)), "{reply:?}");
        });
    }

    /// A `Hello` with a bad ref name gets `invalid-ref` with 422 before
    /// `open` runs and before a slot is taken, so a full table does not
    /// change the answer.
    #[test]
    fn a_bad_ref_name_is_invalid_ref_before_open() {
        let tmp = TmpRepo::new("receive-bad-name");
        let receive = endpoint_with(&tmp, 1, TestAuth::new());
        block_on(async {
            let bad = Message::Hello(Hello {
                version: 1,
                agent: None,
                refs: vec!["main".into(), "a//b".into()],
                one_way: false,
            });
            for open_before in [false, true] {
                if open_before {
                    open_as(&receive, "alice").await;
                }
                let opens = receive.auth.opens();
                let (status, reply) =
                    answer(post_as(&receive, "alice", "session", &bad, None).await).await;
                assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
                assert_eq!(error(reply).code, ErrorCode::InvalidRef);
                assert_eq!(receive.auth.opens(), opens);
            }
            receive.table.close_all();
        });
    }

    /// A `Hello` with `one-way` true gets `protocol` with the text of the
    /// two-way service, before the check of its version and before `open`.
    #[test]
    fn a_one_way_hello_is_protocol_before_its_version() {
        let tmp = TmpRepo::new("receive-one-way");
        let receive = endpoint_with(&tmp, 1, TestAuth::new());
        block_on(async {
            let one_way = Message::Hello(Hello {
                version: 2,
                agent: None,
                refs: vec!["main".into()],
                one_way: true,
            });
            let (status, reply) =
                answer(post_as(&receive, "alice", "session", &one_way, None).await).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            let e = error(reply);
            assert_eq!(e.code, ErrorCode::Protocol);
            assert_eq!(
                e.message,
                "a Hello with one-way true opens a one-way stream, which this session does not read"
            );
            assert_eq!(receive.auth.opens(), 0);
        });
    }

    /// A `session` request past the session limit, and one after the stop,
    /// gets 503 before `open` runs.
    #[test]
    fn a_full_table_gets_503_before_open() {
        let tmp = TmpRepo::new("receive-full");
        let receive = endpoint_with(&tmp, 1, TestAuth::new());
        block_on(async {
            open_as(&receive, "alice").await;
            assert_eq!(receive.auth.opens(), 1);
            for stopped in [false, true] {
                if stopped {
                    receive.table.close_all();
                }
                let (status, reply) =
                    answer(post_as(&receive, "alice", "session", &hello(), None).await).await;
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "stopped {stopped}");
                assert_eq!(error(reply).code, ErrorCode::LimitExceeded);
                assert_eq!(receive.auth.opens(), 1);
            }
        });
    }

    /// The future of a request is `Send` for every authentication and a
    /// body that is not `Sync`. The return type of the generic function is
    /// checked for every `A`.
    const _: fn() = || {
        fn handle_is_send<A: ReceiveAuth>(
            receive: &Receive<A>,
            req: Request<Pieces>,
        ) -> impl Future<Output = Response<ServeBody>> + Send {
            receive.handle(req)
        }
        let _ = handle_is_send::<TestAuth>;
    };
}
