//! The receive endpoint: the push sessions over HTTP.
//!
//! Each request carries one step of a session of [`ReceiveService`]. The
//! bodies of `session`, `have`, and `commit` hold one frame, and the body of
//! `objects` holds one object stream. Each response body is one frame: the
//! reply of the step, or an `Error`.

use std::future::Future;
use std::sync::Arc;

use futures_lite::future;
use hyper::body::{Bytes, Frame, Incoming};
use hyper::header::{ALLOW, CONNECTION, CONTENT_LENGTH, HeaderName, HeaderValue, WWW_AUTHENTICATE};
use hyper::{Method, Request, Response, StatusCode, Version};
use ostrya::push::proto::{ErrorMessage, MAX_FRAME, Message};
use ostrya::push::{self, ErrorCode};
use ostrya::{ReceivePolicy, ReceiveReport, ReceiveService, ReceiveStep, ReceiveWarning, Repo};
use ostrya_rt as rt;

use crate::auth::{Auth, Owner, Peer};
use crate::body::ServeBody;
use crate::request::{RequestBody, drain, read_message};
use crate::router::empty;
use crate::session::{Active, Begin, Cancel, Deleted, SessionId, SessionTable};

/// The path prefix of the endpoint. No repository layout uses it.
pub(crate) const PREFIX: &str = "/_ostrya/receive/v1/";

/// The response header that carries the id of a new session.
const SESSION_HEADER: HeaderName = HeaderName::from_static("ostrya-session");

/// The `WWW-Authenticate` headers of a 401: the two schemes of a credential.
const CHALLENGES: [&str; 2] = [r#"Bearer realm="ostrya""#, r#"Basic realm="ostrya""#];

/// The callback of [`ServeOptions::on_report`](crate::ServeOptions::on_report).
pub(crate) type OnReport = Arc<dyn Fn(ReceiveReport) + Send + Sync>;

/// The receive endpoint of a server.
pub(crate) struct Receive {
    pub(crate) repo: Repo,
    pub(crate) policy: Arc<ReceivePolicy>,
    pub(crate) auth: Auth,
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

impl Receive {
    /// The response to a request under [`PREFIX`] with a method other than
    /// `GET` and `HEAD`, which go to the archive view.
    pub(crate) async fn handle(&self, peer: &Peer, req: Request<Incoming>) -> Response<ServeBody> {
        let Some(route) = Route::parse(req.uri().path()) else {
            return self.refuse(req, empty(StatusCode::NOT_FOUND)).await;
        };
        if *req.method() != route.method() {
            let mut response = empty(StatusCode::METHOD_NOT_ALLOWED);
            response.headers_mut().insert(ALLOW, route.allow());
            return self.refuse(req, response).await;
        }
        let owner = match self.auth.authorize(req.headers(), peer) {
            Ok(owner) => owner,
            Err(refusal) => {
                let message = error_message(ErrorCode::Unauthorized, refusal.message);
                let mut response = frame(refusal.status, &message);
                if refusal.status == StatusCode::UNAUTHORIZED {
                    let headers = response.headers_mut();
                    for challenge in CHALLENGES {
                        headers.append(WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
                    }
                }
                return self.refuse(req, response).await;
            }
        };
        match route {
            Route::Open => self.open(owner, req).await,
            Route::Session(id) => match self.table.delete(&id, &owner) {
                Deleted::Done => self.refuse(req, no_content()).await,
                Deleted::Committing => self.refuse(req, failure(&committing())).await,
                Deleted::NotFound => self.refuse(req, empty(StatusCode::NOT_FOUND)).await,
            },
            Route::Step(id, step) => {
                let Some(mut active) = self.table.lookup(&id, &owner) else {
                    return self.refuse(req, empty(StatusCode::NOT_FOUND)).await;
                };
                let body = RequestBody::new(req.into_body(), Some(active.track()));
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

    /// Answer `req` with `response` before its body is read. The body is
    /// read and dropped first, up to 1 MiB within the idle timeout or
    /// 5 seconds, whichever is shorter, so the client can read the response.
    /// On HTTP/1 a body that did not reach its end closes the connection
    /// after the response.
    async fn refuse(
        &self,
        req: Request<Incoming>,
        mut response: Response<ServeBody>,
    ) -> Response<ServeBody> {
        let version = req.version();
        let drained = drain(req.into_body(), self.table.idle()).await;
        if !drained && version <= Version::HTTP_11 {
            response
                .headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }
        response
    }

    /// `POST session`: read `Hello`, take a slot of the session limit, and
    /// open the session. The body must arrive in full within the idle
    /// timeout.
    async fn open(&self, owner: Owner, req: Request<Incoming>) -> Response<ServeBody> {
        let mut body = RequestBody::new(req.into_body(), None);
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
        let opened = ReceiveService::hello(
            self.repo.clone(),
            self.policy.clone(),
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
            Err(e) => return failure(&e.into()),
        };
        if !slot.insert(id, service, owner) {
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
    async fn commit(&self, active: &Active, mut body: RequestBody) -> Response<ServeBody> {
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
                    Err(e) => failure(&e.into()),
                }
            }
            Err(e) => failure(&e),
        }
    }
}

/// `POST session/ID/have`: read `Have`, and answer it.
async fn have(active: &Active, mut body: RequestBody) -> Response<ServeBody> {
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
async fn objects(active: &Active, body: RequestBody) -> Response<ServeBody> {
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
    use std::sync::Mutex;

    use super::*;
    use crate::body::tests::frames;
    use ostrya::TransactionStats;
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

    /// Every response of the endpoint goes without `Content-Type` and
    /// without `Retry-After`, and a frame response states its length.
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
}
