//! The authentication of the receive endpoint by its host.

use std::future::Future;
use std::sync::Arc;

use hyper::StatusCode;
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::request::Parts;
use ostrya::ReceivePolicy;
use ostrya::push::proto::Hello;

/// The authentication of the requests of the receive endpoint.
///
/// [`authenticate`](Self::authenticate) runs for each request with a known
/// route and method. [`open`](Self::open) runs for a `session` request whose
/// `Hello` passes its checks and gets a session slot. A refusal of either
/// gets its status, its headers, and an `unauthorized` frame with its
/// message. The endpoint adds no `WWW-Authenticate` header of its own.
pub trait ReceiveAuth: Send + Sync + 'static {
    /// The identity of a request.
    type Principal: Send + Sync + 'static;

    /// The owner key of a principal. A session belongs to the key of its
    /// `session` request. Two requests of one session must give equal keys,
    /// or the second request gets 404, the answer of an unknown session.
    fn owner(principal: &Self::Principal) -> &str;

    /// The principal of a request, or its refusal. It is called for each
    /// request with a known route and method, before the endpoint reads a
    /// byte of the body. `kind` is the route of the request. The endpoint
    /// answers a refusal after it reads and drops up to 1 MiB of the body.
    fn authenticate(
        &self,
        parts: &Parts,
        kind: RequestKind,
    ) -> impl Future<Output = Result<Self::Principal, Refusal>> + Send;

    /// The setup of the session that `hello` opens for `principal`, or its
    /// refusal.
    ///
    /// It is called for a `session` request after the endpoint reads
    /// `Hello`, after the checks of
    /// [`ReceiveService::check_hello`](ostrya::ReceiveService::check_hello),
    /// and after the endpoint reserves a session slot. `hello` thus holds
    /// valid ref names alone. A refusal frees the slot. The session limit
    /// thus also limits the count of `open` calls that run at one time.
    ///
    /// A session can fail to start after `open` returns: for example, a read
    /// of the repository configuration fails, or a `bare` repository gets
    /// `mode-refused` because the server does not run as root. So the host
    /// must not hold state from `open` alone.
    fn open(
        &self,
        principal: &Self::Principal,
        hello: &Hello,
    ) -> impl Future<Output = Result<SessionSetup, Refusal>> + Send;
}

/// The route of a request of the receive endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestKind {
    /// `POST session`: open a session.
    Open,
    /// `POST session/ID/have`.
    Have,
    /// `POST session/ID/objects`.
    Objects,
    /// `POST session/ID/commit`.
    Commit,
    /// `DELETE session/ID`: end a session.
    Delete,
}

/// A refusal of [`ReceiveAuth::authenticate`] or [`ReceiveAuth::open`]: the
/// status, 401 or 403, the message of its `unauthorized` frame, and the
/// response headers it adds.
#[derive(Debug)]
pub struct Refusal {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
    /// The headers, in the order they were added.
    pub(crate) headers: Vec<(HeaderName, HeaderValue)>,
}

/// The longest message of a refusal, in bytes.
const MAX_MESSAGE: usize = 4096;

impl Refusal {
    /// A refusal with the status 401. A message longer than 4096 bytes is
    /// cut at a character boundary.
    pub fn unauthorized(message: impl Into<String>) -> Refusal {
        Refusal::new(StatusCode::UNAUTHORIZED, message.into())
    }

    /// A refusal with the status 403. A message longer than 4096 bytes is
    /// cut at a character boundary.
    pub fn forbidden(message: impl Into<String>) -> Refusal {
        Refusal::new(StatusCode::FORBIDDEN, message.into())
    }

    fn new(status: StatusCode, mut message: String) -> Refusal {
        // The cut keeps the frame of the refusal under the frame limit.
        message.truncate(message.floor_char_boundary(MAX_MESSAGE));
        Refusal {
            status,
            message,
            headers: Vec::new(),
        }
    }

    /// The refusal with one more response header, for example
    /// `WWW-Authenticate`. The headers go in the order they were added, and
    /// a name added two times gives two headers. The endpoint drops a header
    /// named `Content-Length`, `Transfer-Encoding`, or `Connection`, because
    /// it sets the framing and the connection state of the response itself.
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Refusal {
        self.headers.push((name, value));
        self
    }
}

/// What [`ReceiveAuth::open`] gives to the session.
pub struct SessionSetup {
    /// The receive policy of the session.
    pub policy: Arc<ReceivePolicy>,
}
