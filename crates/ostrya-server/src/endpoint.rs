//! The receive endpoint that a host mounts in its own router.

use std::fmt;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;

use futures_lite::future;
use hyper::body::{Body, Bytes};
use hyper::{Request, Response};
use ostrya::{ReceiveReport, Repo};

use crate::body::ReceiveBody;
use crate::error::{Error, Result};
use crate::receive::Receive;
use crate::receive_auth::ReceiveAuth;
use crate::session::SessionTable;
use crate::shutdown::Shutdown;

/// The values of `parallel_uploads` that an endpoint takes.
const PARALLEL_UPLOADS: RangeInclusive<u32> = 1..=31;

/// The HTTP/2 receive window of one stream of a connection to an endpoint.
/// The window of the connection is this value times `parallel_uploads`.
const UPLOAD_WINDOW: u32 = 2 * 1024 * 1024;

/// The options of [`ReceiveEndpoint::new`].
///
/// [`EndpointOptions::default`] holds the default value of each field.
#[derive(Clone)]
pub struct EndpointOptions {
    /// The number of object streams that one session runs at the same time.
    ///
    /// `HelloReply` announces this number. The value is in `1..=31`, and the
    /// default is 4. [`ReceiveEndpoint::h2_windows`] gives the HTTP/2
    /// windows that follow from it.
    pub parallel_uploads: u32,
    /// The longest time that a session stays with no request in progress.
    ///
    /// It is also the longest time that a request body of a session delivers
    /// no byte. After this time, the endpoint aborts the session. The default
    /// is 300 seconds, and [`ReceiveEndpoint::new`] refuses zero.
    pub session_idle_timeout: Duration,
    /// The largest number of sessions that are open at the same time.
    ///
    /// The default is 16, and [`ReceiveEndpoint::new`] refuses zero.
    pub max_sessions: usize,
    /// The callback that gets the report of each session that committed.
    ///
    /// The endpoint calls it when the response body of the commit drops. If
    /// the connection did not take the `CommitReply` frame, the report holds a
    /// warning of the step
    /// [`ReplyNotDelivered`](ostrya::ReceiveStep::ReplyNotDelivered). hyper
    /// can take the frame and still fail to write it, so a reply that the
    /// client did not get can come with no warning.
    ///
    /// The call runs on a task of the host, so the callback must return soon.
    /// The default is `None`.
    ///
    /// In a session with hooks, the call comes after
    /// [`ReceiveHooks::after_update`](ostrya::ReceiveHooks::after_update),
    /// and only if `after_update` succeeds. If `after_update` returns an
    /// error, only `after_update` gets the report.
    /// [`SessionSetup::hooks`](crate::SessionSetup::hooks) states the other
    /// effects of that error.
    pub on_report: Option<Arc<dyn Fn(ReceiveReport) + Send + Sync>>,
}

/// The debug text shows `<callback>` for a report callback that is set.
impl fmt::Debug for EndpointOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointOptions")
            .field("parallel_uploads", &self.parallel_uploads)
            .field("session_idle_timeout", &self.session_idle_timeout)
            .field("max_sessions", &self.max_sessions)
            .field("on_report", &self.on_report.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

impl Default for EndpointOptions {
    fn default() -> EndpointOptions {
        EndpointOptions {
            parallel_uploads: 4,
            session_idle_timeout: Duration::from_secs(300),
            max_sessions: 16,
            on_report: None,
        }
    }
}

/// The receive endpoint of a push, which a host mounts in its own router.
///
/// The endpoint serves one repository and uses the authentication `A`. It
/// opens no listener and does no TLS. [`Server`](crate::Server) runs the
/// same endpoint with its built-in authentication methods.
///
/// # Mounting
///
/// - [`handle`](ReceiveEndpoint::handle) takes a raw path that starts with
///   `/_ostrya/receive/v1/`. If a host mounts the endpoint under a prefix,
///   for example `/api/v1/push`, the host removes the prefix before the call.
///   `Router::nest_service` of axum removes the prefix itself. The push
///   address of a client is then `https://HOST/api/v1/push`.
/// - The request body does not need to be `Sync`, so the body of axum fits.
///   The response body is [`ReceiveBody`], which makes no promise of `Sync`.
/// - The endpoint is `Send + Sync` and has no `Clone`. A host shares it in an
///   `Arc`.
/// - Run the future of [`sweep`](ReceiveEndpoint::sweep) once, in a task of
///   its own, when the host starts. If no task runs it, no session reaches
///   its idle timeout.
/// - Call [`shutdown`](ReceiveEndpoint::shutdown) before the graceful
///   shutdown of the listener.
/// - Serve the endpoint on a dedicated listener, with a port or an SNI name
///   of its own. A listener for other routes keeps its own windows.
/// - On that listener, set the HTTP/2 windows of
///   [`h2_windows`](ReceiveEndpoint::h2_windows). Set the maximum number of
///   concurrent streams of one connection to 32, the value of the server.
///   Both HTTP/2 settings apply only to a TLS listener that offers `h2`
///   through ALPN, because the push client speaks HTTP/1.1 over cleartext.
/// - The request bytes that the host did not read are at most the
///   connection window times the number of open connections. The host grants
///   the windows when it sets up a connection, before it authenticates a
///   request.
/// - The runtime backend of the crate must be the runtime of the host: the
///   `tokio` feature for a host on tokio. Under tokio,
///   [`handle`](ReceiveEndpoint::handle) and
///   [`sweep`](ReceiveEndpoint::sweep) must run within a tokio runtime with
///   the time driver enabled.
///
/// # Responses
///
/// Each request under the raw path prefix `/_ostrya/receive/v1/` is one
/// step of a push session of [`ReceiveService`](ostrya::ReceiveService).
/// [The receive endpoint] specifies the routes, the request bodies, the
/// session id, the statuses, and the end of a session. [Error codes] gives
/// the status of each wire code.
/// [Authentication of the receive endpoint] gives the refusals of the
/// authentication.
///
/// [`EndpointOptions::parallel_uploads`] is the number of `objects` requests
/// that one session runs at the same time. One more `objects` request gets
/// 422 with `limit-exceeded`, and the session ends.
/// [`EndpointOptions::max_sessions`] is the number of sessions that are open
/// at the same time. A `session` request past the limit gets 503 with
/// `limit-exceeded`. A refusal of the authentication carries the headers
/// that the [`ReceiveAuth`] adds to it, except `Content-Length`,
/// `Transfer-Encoding`, and `Connection`, which the endpoint sets itself.
///
/// A refusal can come before the endpoint reads the body, for example a 404
/// or a 405. Before such a refusal, the endpoint reads and drops up to 1 MiB
/// of the body. The time limit of this read is the idle timeout or 5
/// seconds, whichever is shorter. On HTTP/1.1 and HTTP/1.0, if the body did
/// not reach its end, the response gets `Connection: close`.
///
/// # Sessions
///
/// If a session has no request in progress for
/// [`EndpointOptions::session_idle_timeout`], the endpoint aborts it. The
/// endpoint also aborts a session with a request body that delivers no byte
/// for that time. While the endpoint does not read a request body, that body
/// does not count as silent. The body of a `session` request must arrive in
/// full within the idle timeout.
///
/// The future of [`sweep`](ReceiveEndpoint::sweep) applies the timeout. A
/// session that commits is never aborted. It holds its slot until the commit
/// ends, also if the commit fails or panics.
///
/// [`shutdown`](ReceiveEndpoint::shutdown) aborts every session that does
/// not commit. A `session` request after the call gets 503. A commit that
/// runs goes on to its end.
///
/// The endpoint reads the repository settings once, at start. A change of
/// the settings applies at the next start.
///
/// [The receive endpoint]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#the-receive-endpoint
/// [Error codes]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#error-codes
/// [Authentication of the receive endpoint]: https://github.com/growler/ostrya/blob/main/docs/format-reference.md#authentication-of-the-receive-endpoint
///
/// # Examples
///
/// A host that mounts the endpoint under the prefix `/api/v1/push`:
///
/// ```no_run
/// use std::sync::Arc;
///
/// use hyper::body::Incoming;
/// use hyper::{Request, Response};
/// use ostrya_server::{ReceiveAuth, ReceiveBody, ReceiveEndpoint};
///
/// // Runs the idle sweep in a task of its own, once, when the host starts.
/// fn start<A: ReceiveAuth>(endpoint: &Arc<ReceiveEndpoint<A>>) {
///     let endpoint = endpoint.clone();
///     drop(ostrya_rt::spawn(async move { endpoint.sweep().await }));
/// }
///
/// // Removes the prefix of the host, then lets the endpoint answer.
/// async fn route<A: ReceiveAuth>(
///     endpoint: &ReceiveEndpoint<A>,
///     mut req: Request<Incoming>,
/// ) -> Response<ReceiveBody> {
///     let path = req.uri().path().strip_prefix("/api/v1/push").unwrap_or("/");
///     *req.uri_mut() = path.parse().expect("a path is a valid URI");
///     endpoint.handle(req).await
/// }
/// ```
pub struct ReceiveEndpoint<A: ReceiveAuth> {
    inner: Receive<A>,
    /// Fires at [`shutdown`](ReceiveEndpoint::shutdown), and ends
    /// [`sweep`](ReceiveEndpoint::sweep).
    stop: Arc<Shutdown>,
}

/// The debug text shows the options. It leaves out the repository and the
/// authentication.
impl<A: ReceiveAuth> fmt::Debug for ReceiveEndpoint<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiveEndpoint")
            .field("parallel_uploads", &self.inner.parallel_uploads)
            .field("session_idle_timeout", &self.inner.table.idle())
            .field("max_sessions", &self.inner.table.max())
            .finish_non_exhaustive()
    }
}

impl<A: ReceiveAuth> ReceiveEndpoint<A> {
    /// Creates an endpoint over `repo` with the authentication `auth`.
    ///
    /// # Errors
    ///
    /// - [`Error::Options`] if
    ///   [`parallel_uploads`](EndpointOptions::parallel_uploads) is outside
    ///   `1..=31`.
    /// - [`Error::Options`] if
    ///   [`session_idle_timeout`](EndpointOptions::session_idle_timeout) is
    ///   zero.
    /// - [`Error::Options`] if
    ///   [`max_sessions`](EndpointOptions::max_sessions) is zero.
    pub fn new(repo: Repo, auth: A, options: EndpointOptions) -> Result<ReceiveEndpoint<A>> {
        if !PARALLEL_UPLOADS.contains(&options.parallel_uploads) {
            return Err(Error::Options(format!(
                "parallel_uploads {} is outside {}..={}",
                options.parallel_uploads,
                PARALLEL_UPLOADS.start(),
                PARALLEL_UPLOADS.end()
            )));
        }
        if options.session_idle_timeout.is_zero() {
            return Err(Error::Options("a session idle timeout of zero".into()));
        }
        if options.max_sessions == 0 {
            return Err(Error::Options("a session limit of zero".into()));
        }
        Ok(ReceiveEndpoint {
            inner: Receive {
                repo,
                auth,
                parallel_uploads: options.parallel_uploads,
                on_report: options.on_report,
                table: SessionTable::new(options.max_sessions, options.session_idle_timeout),
            },
            stop: Arc::new(Shutdown::default()),
        })
    }

    /// Returns the response to one request of the endpoint.
    ///
    /// The raw request path must start with `/_ostrya/receive/v1/`. The path
    /// is not percent-decoded, and the endpoint ignores the query.
    /// [Mounting](ReceiveEndpoint#mounting) states how a host removes its
    /// prefix. [Responses](ReceiveEndpoint#responses) links the specification
    /// of the routes and the responses.
    ///
    /// A request body that fails counts as a request that ended before its
    /// response. The request gets 500 with `internal`, and its session ends,
    /// unless the session commits.
    ///
    /// Under the tokio backend, the call must run within a tokio runtime
    /// with the time driver enabled. The commit runs in a task of its own,
    /// and the time limits use the timer. A server signer that runs the
    /// GnuPG binaries also needs the IO driver.
    ///
    /// # Panics
    ///
    /// A panic in the commit or in a hook of the session is not caught. The
    /// commit runs in a task of its own. The panic resumes in this call when
    /// the call joins that task, so it panics the request task of the host.
    ///
    /// Over HTTP/2, hyper then resets the stream. Over HTTP/1.1, hyper closes
    /// the connection. The session ends and frees its slot. A panic in
    /// [`ReceiveHooks::after_update`](ostrya::ReceiveHooks::after_update)
    /// occurs after the endpoint writes the refs.
    ///
    /// If the future of `handle` is dropped first, for example because the
    /// client resets the stream, the commit task becomes detached. The
    /// runtime then catches the panic and drops it.
    pub async fn handle<B>(&self, req: Request<B>) -> Response<ReceiveBody>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.inner.handle(req).await.map(ReceiveBody)
    }

    /// Aborts each session past its idle timeout, until
    /// [`shutdown`](ReceiveEndpoint::shutdown).
    ///
    /// The future also aborts each session with a request body that delivered
    /// no byte for that time. A session that commits is never aborted. After
    /// `shutdown`, the future completes at once.
    ///
    /// The host runs the future once, in a task of its own, while the
    /// endpoint serves. If no task runs it, no session reaches its idle
    /// timeout. Under the tokio backend, the future must run within a tokio
    /// runtime with the time driver enabled.
    pub async fn sweep(&self) {
        future::or(self.stop.wait(), self.inner.table.sweep()).await
    }

    /// Stops the endpoint.
    ///
    /// The call aborts each session that does not commit, and ends
    /// [`sweep`](ReceiveEndpoint::sweep). A commit that runs goes on to its
    /// end, also through the hooks of its session. A `session` request after
    /// the call gets 503. A second call has no further effect.
    pub fn shutdown(&self) {
        self.stop.fire();
        self.inner.table.close_all();
    }

    /// Returns the HTTP/2 receive windows for a connection to the endpoint.
    ///
    /// The first value is the window of each stream, 2 MiB. The second value
    /// is the window of the connection: 2 MiB for each of the
    /// [`parallel_uploads`](EndpointOptions::parallel_uploads) object streams
    /// of a session. The request bodies of one connection hold at most this
    /// number of bytes that the host did not read.
    pub fn h2_windows(&self) -> (u32, u32) {
        (UPLOAD_WINDOW, UPLOAD_WINDOW * self.inner.parallel_uploads)
    }
}

#[cfg(test)]
mod tests {
    use hyper::{Method, StatusCode};
    use ostrya::remote::ErrorCode;
    use ostrya::remote::proto::{Hello, Kind, Message};
    use ostrya_rt::block_on;

    use super::*;
    use crate::auth::{GroupAuth, Peer};
    use crate::body::ServeBody;
    use crate::body::tests::frames;
    use crate::receive::PREFIX;
    use crate::session::tests::{ANONYMOUS_PUSH, TmpRepo};

    /// The built-in authentication with a group of anonymous push.
    fn anonymous(tmp: &TmpRepo) -> GroupAuth {
        GroupAuth::new(tmp.policies(ANONYMOUS_PUSH), false)
    }

    fn endpoint(tmp: &TmpRepo, options: EndpointOptions) -> Result<ReceiveEndpoint<GroupAuth>> {
        ReceiveEndpoint::new(tmp.repo.clone(), anonymous(tmp), options)
    }

    #[test]
    fn bad_options_are_refused() {
        let tmp = TmpRepo::new("endpoint-options");
        let cases = [
            (
                EndpointOptions {
                    parallel_uploads: 0,
                    ..EndpointOptions::default()
                },
                "parallel_uploads 0 is outside 1..=31",
            ),
            (
                EndpointOptions {
                    parallel_uploads: 32,
                    ..EndpointOptions::default()
                },
                "parallel_uploads 32 is outside 1..=31",
            ),
            (
                EndpointOptions {
                    session_idle_timeout: Duration::ZERO,
                    ..EndpointOptions::default()
                },
                "a session idle timeout of zero",
            ),
            (
                EndpointOptions {
                    max_sessions: 0,
                    ..EndpointOptions::default()
                },
                "a session limit of zero",
            ),
        ];
        for (options, want) in cases {
            match endpoint(&tmp, options) {
                Err(Error::Options(message)) => assert_eq!(message, want),
                other => panic!("{want}: {other:?}"),
            }
        }
    }

    /// The window of a connection follows `parallel_uploads`, and the widest
    /// one is less than the HTTP/2 maximum.
    #[test]
    fn the_h2_windows_follow_parallel_uploads() {
        let tmp = TmpRepo::new("endpoint-windows");
        let windows = |parallel_uploads| {
            let options = EndpointOptions {
                parallel_uploads,
                ..EndpointOptions::default()
            };
            endpoint(&tmp, options).unwrap().h2_windows()
        };
        assert_eq!(windows(4), (2 << 20, 8 << 20));
        let (_, widest) = windows(*PARALLEL_UPLOADS.end());
        assert_eq!(widest, 62 << 20);
        assert!(widest < 1 << 31);
    }

    /// The debug text states the options and leaves out the callback.
    #[test]
    fn debug_states_the_options() {
        let tmp = TmpRepo::new("endpoint-debug");
        let options = EndpointOptions {
            on_report: Some(Arc::new(|_| {})),
            ..EndpointOptions::default()
        };
        let text = format!("{options:?}");
        assert!(text.contains("<callback>"), "{text}");
        let text = format!("{:?}", endpoint(&tmp, options).unwrap());
        assert!(text.contains("parallel_uploads: 4"), "{text}");
        assert!(text.contains("max_sessions: 16"), "{text}");
        assert!(text.contains("300s"), "{text}");
    }

    /// After `shutdown`, the sweep completes, a second `shutdown` does
    /// nothing more, and a `session` request gets 503 with
    /// `limit-exceeded`.
    #[test]
    fn shutdown_ends_the_sweep_and_refuses_new_sessions() {
        let tmp = TmpRepo::new("endpoint-shutdown");
        let ep = endpoint(&tmp, EndpointOptions::default()).unwrap();
        block_on(async {
            assert!(
                future::poll_once(Box::pin(ep.sweep())).await.is_none(),
                "the sweep runs until shutdown"
            );
            ep.shutdown();
            ep.shutdown();
            ep.sweep().await;
            let hello = Message::Hello(Hello {
                version: 1,
                agent: None,
                refs: vec!["main".into()],
                one_way: false,
            });
            let mut bytes = Vec::new();
            let body = hello.encode_body().unwrap();
            bytes.extend_from_slice(&(body.len() as u32 + 1).to_be_bytes());
            bytes.push(hello.kind().as_u8());
            bytes.extend_from_slice(&body);
            let req = Request::builder()
                .method(Method::POST)
                .uri(format!("{PREFIX}session"))
                .extension(Peer {
                    tls: false,
                    addr: std::net::Ipv4Addr::LOCALHOST.into(),
                    cert: None,
                })
                .body(ServeBody::Full(Some(Bytes::from(bytes))))
                .unwrap();
            let response = ep.handle(req).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let bytes = frames(response.into_body().into_serve())
                .await
                .unwrap()
                .concat();
            let reply = Message::decode(Kind::from_u8(bytes[4]).unwrap(), &bytes[5..]).unwrap();
            let Message::Error(e) = reply else {
                panic!("{reply:?}");
            };
            assert_eq!(e.code, ErrorCode::LimitExceeded);
        });
    }
}
