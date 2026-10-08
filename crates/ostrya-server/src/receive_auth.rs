//! The authentication of the receive endpoint by its host.

use std::future::Future;
use std::sync::Arc;

use hyper::StatusCode;
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::request::Parts;
use ostrya::push::proto::Hello;
use ostrya::{ReceiveHooks, ReceivePolicy};

/// The authentication of the requests of the receive endpoint.
///
/// A refusal of [`authenticate`](Self::authenticate) or [`open`](Self::open)
/// gets its status, its headers, and an `unauthorized` frame with its
/// message. The endpoint adds no `WWW-Authenticate` header of its own.
///
/// # Call order
///
/// The endpoint calls [`authenticate`](Self::authenticate) for each request
/// with a known route and method, before it reads a byte of the body. It
/// gives the [`RequestKind`] of the route. For a `session` request, the
/// endpoint then does these steps, in this order:
///
/// 1. It reads `Hello`.
/// 2. It refuses a `Hello` that has `one-way` set to `true`, with the error
///    code `protocol`. This step comes before the check of the version.
/// 3. It checks `Hello` with
///    [`ReceiveService::check_hello`](ostrya::ReceiveService::check_hello).
/// 4. It takes a slot of the session limit, or answers 503.
/// 5. It calls [`open`](Self::open), which gives the [`SessionSetup`] of the
///    session. A refusal frees the slot.
/// 6. It opens the session.
///
/// The checks of `Hello` come before the slot. A bad `Hello` gets 422 also
/// when the sessions are at the limit or the endpoint stopped.
///
/// # Examples
///
/// An implementation with one bearer token, which gives the same receive
/// policy to each session:
///
/// ```
/// use std::sync::Arc;
///
/// use hyper::http::request::Parts;
/// use ostrya::push::proto::Hello;
/// use ostrya::{ReceivePolicy, Repo};
/// use ostrya_server::{
///     EndpointOptions, ReceiveAuth, ReceiveEndpoint, Refusal, RequestKind, SessionSetup,
/// };
///
/// struct OneToken {
///     header: String,
///     policy: Arc<ReceivePolicy>,
/// }
///
/// impl ReceiveAuth for OneToken {
///     type Principal = String;
///
///     fn owner(principal: &String) -> &str {
///         principal
///     }
///
///     async fn authenticate(&self, parts: &Parts, _kind: RequestKind) -> Result<String, Refusal> {
///         // A real host compares a digest of the token in constant time.
///         match parts.headers.get("authorization") {
///             Some(value) if value.as_bytes() == self.header.as_bytes() => Ok("builder".into()),
///             _ => Err(Refusal::unauthorized("a valid token is necessary")),
///         }
///     }
///
///     async fn open(&self, _principal: &String, _hello: &Hello) -> Result<SessionSetup, Refusal> {
///         Ok(SessionSetup { policy: self.policy.clone(), hooks: None })
///     }
/// }
///
/// fn endpoint(repo: Repo, token: &str) -> ostrya_server::Result<ReceiveEndpoint<OneToken>> {
///     let auth = OneToken {
///         header: format!("Bearer {token}"),
///         policy: Arc::new(ReceivePolicy::default()),
///     };
///     ReceiveEndpoint::new(repo, auth, EndpointOptions::default())
/// }
/// ```
pub trait ReceiveAuth: Send + Sync + 'static {
    /// The identity of a request.
    type Principal: Send + Sync + 'static;

    /// Returns the owner key of a principal.
    ///
    /// A session belongs to the key of its `session` request. If a later
    /// request of the session gives a different key, it gets 404, the answer
    /// to an unknown session.
    fn owner(principal: &Self::Principal) -> &str;

    /// Returns the principal of a request, or its refusal.
    ///
    /// The endpoint calls it in the [call order](ReceiveAuth#call-order), with
    /// the route of the request as `kind`. If it returns a refusal, the
    /// endpoint reads and drops up to 1 MiB of the body before it answers.
    ///
    /// # Errors
    ///
    /// - [`Refusal`] to refuse the request. The endpoint answers with the
    ///   status, the headers, and the message of the refusal.
    fn authenticate(
        &self,
        parts: &Parts,
        kind: RequestKind,
    ) -> impl Future<Output = Result<Self::Principal, Refusal>> + Send;

    /// Returns the setup of the session that `hello` opens for `principal`.
    ///
    /// The setup holds the receive policy and the hooks of the session. The
    /// endpoint calls `open` in the [call order](ReceiveAuth#call-order),
    /// after the checks of `Hello` and after it reserves a session slot.
    /// Because of these checks, `hello` holds valid ref names alone.
    ///
    /// Each `open` call holds a slot, so the session limit also limits the
    /// count of `open` calls that run at one time.
    ///
    /// The host must not keep state from `open` alone, because a session can
    /// fail to start after `open` returns. For example, a read of the
    /// repository configuration fails, or a `bare` repository gets
    /// `mode-refused` because the server does not run as root.
    ///
    /// # Errors
    ///
    /// - [`Refusal`] to refuse the session. The endpoint answers with the
    ///   status, the headers, and the message of the refusal, and frees the
    ///   slot.
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
    /// The `POST session` request, which opens a session.
    Open,
    /// The `POST session/ID/have` request.
    Have,
    /// The `POST session/ID/objects` request.
    Objects,
    /// The `POST session/ID/commit` request.
    Commit,
    /// The `DELETE session/ID` request, which ends a session.
    Delete,
}

/// A refusal of [`ReceiveAuth::authenticate`] or [`ReceiveAuth::open`].
///
/// A refusal holds:
///
/// - the status, 401 or 403
/// - the message of its `unauthorized` frame
/// - the response headers that it adds
#[derive(Debug)]
pub struct Refusal {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
    /// The headers, in the order of the `with_header` calls.
    pub(crate) headers: Vec<(HeaderName, HeaderValue)>,
}

/// The longest message of a refusal, in bytes.
const MAX_MESSAGE: usize = 4096;

impl Refusal {
    /// Creates a refusal with the status 401.
    ///
    /// If `message` is longer than 4096 bytes, `unauthorized` cuts it to at
    /// most 4096 bytes, at a character boundary.
    pub fn unauthorized(message: impl Into<String>) -> Refusal {
        Refusal::new(StatusCode::UNAUTHORIZED, message.into())
    }

    /// Creates a refusal with the status 403.
    ///
    /// If `message` is longer than 4096 bytes, `forbidden` cuts it to at most
    /// 4096 bytes, at a character boundary.
    pub fn forbidden(message: impl Into<String>) -> Refusal {
        Refusal::new(StatusCode::FORBIDDEN, message.into())
    }

    fn new(status: StatusCode, mut message: String) -> Refusal {
        // The cut keeps the frame of the refusal in the frame limit.
        message.truncate(message.floor_char_boundary(MAX_MESSAGE));
        Refusal {
            status,
            message,
            headers: Vec::new(),
        }
    }

    /// Returns the refusal with one more response header.
    ///
    /// An example is a `WWW-Authenticate` header. The response holds the
    /// headers in the order of the calls. If the host adds a name two times,
    /// the response holds two headers.
    ///
    /// The endpoint drops a header named `Content-Length`,
    /// `Transfer-Encoding`, or `Connection`, because it sets the framing and
    /// the connection state of the response itself.
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Refusal {
        self.headers.push((name, value));
        self
    }
}

/// The receive policy and the hooks that [`ReceiveAuth::open`] gives to a
/// session.
pub struct SessionSetup {
    /// The receive policy of the session.
    pub policy: Arc<ReceivePolicy>,
    /// The hooks of the session, or `None` for a session with no hooks.
    ///
    /// The endpoint opens the session with
    /// [`ReceiveService::hello_with_hooks`](ostrya::ReceiveService::hello_with_hooks).
    /// The commit of the session calls [`ReceiveHooks::before_update`] just
    /// before the update lock. It calls [`ReceiveHooks::after_update`] after
    /// it releases the update lock.
    ///
    /// # Refusals and errors of a hook
    ///
    /// - A refusal of `before_update` with
    ///   [`HookRefusal::denied`](ostrya::HookRefusal::denied) gets 422 with
    ///   `ref-denied`.
    /// - A refusal of `before_update` with
    ///   [`HookRefusal::internal`](ostrya::HookRefusal::internal) gets 500
    ///   with `internal`.
    /// - An error of `after_update` gets 500 with `internal`. The refs and
    ///   the detached metadata stay written, and the session ends as aborted.
    ///   The endpoint does not call
    ///   [`EndpointOptions::on_report`](crate::EndpointOptions::on_report).
    ///
    /// The client gets the message of the refusal or of the error in the
    /// `Error` frame, as the hook wrote it, cut at 4096 bytes. The host must
    /// not put secrets or internal details in the message, because the
    /// client sees it.
    ///
    /// # Session state during a hook
    ///
    /// While a hook runs, the session commits:
    ///
    /// - It keeps its slot of
    ///   [`EndpointOptions::max_sessions`](crate::EndpointOptions::max_sessions).
    /// - The idle timeout, a `DELETE`, and
    ///   [`ReceiveEndpoint::shutdown`](crate::ReceiveEndpoint::shutdown) do
    ///   not end it.
    /// - During `before_update`, it also holds a shared lock of the
    ///   repository, so a prune waits.
    ///
    /// Because the response to `commit` waits for both hooks, the host must
    /// limit the time of its hooks.
    ///
    /// # Checks after the hook
    ///
    /// The commit runs these checks after `before_update` returns its plan,
    /// so a commit can fail after a plan from the hook:
    ///
    /// - Before the update lock, a plan that the checks refuse gets 500 with
    ///   `internal`. [`ReceiveHooks`] states the checks of the plan.
    /// - Before the update lock, a merged dict with the host entries that is
    ///   larger than the size limit gets 422 with `limit-exceeded`.
    /// - Under the update lock, these updates get 422 with `ref-denied`:
    ///   - a ref that is an alias
    ///   - a path that a ref write cannot replace
    ///   - two updates of which one names a directory of the other
    /// - Under the update lock, `ref-mismatch` and `non-fast-forward` get
    ///   409, and `delete-denied` gets 422.
    /// - Under the update lock, if the stored dict changed after the plan, a
    ///   merged dict over the size limit gets 422 with `limit-exceeded`.
    pub hooks: Option<Arc<dyn ReceiveHooks>>,
}
