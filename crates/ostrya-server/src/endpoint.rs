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

/// The values of `parallel_uploads` an endpoint takes.
const PARALLEL_UPLOADS: RangeInclusive<u32> = 1..=31;

/// The HTTP/2 receive window of one stream of a connection to an endpoint.
/// The window of the connection is this value times `parallel_uploads`.
const UPLOAD_WINDOW: u32 = 2 * 1024 * 1024;

/// The options of [`ReceiveEndpoint::new`]. Start from
/// [`EndpointOptions::default`] and set the fields.
#[derive(Clone)]
pub struct EndpointOptions {
    /// The number of object streams one session runs at the same time, which
    /// `HelloReply` announces. The value is in `1..=31`, and the default
    /// is 4. [`ReceiveEndpoint::h2_windows`] gives the HTTP/2 windows that
    /// follow from it.
    pub parallel_uploads: u32,
    /// The time a session may stay with no request in progress, and the time
    /// a request body of a session may deliver no byte. Past it the endpoint
    /// aborts the session. The default is 300 seconds, and zero is refused.
    pub session_idle_timeout: Duration,
    /// The most sessions open at the same time. The default is 16, and zero
    /// is refused.
    pub max_sessions: usize,
    /// Called with the report of each session that committed, after the
    /// endpoint sent `CommitReply` or failed to send it. A reply that the
    /// connection did not take adds a warning of the step
    /// [`ReplyNotDelivered`](ostrya::ReceiveStep::ReplyNotDelivered). The
    /// call runs on a task of the host, so it must return soon. The default
    /// is `None`.
    ///
    /// In a session with hooks, the call comes after
    /// [`ReceiveHooks::after_update`](ostrya::ReceiveHooks::after_update),
    /// and only when `after_update` succeeds. When `after_update` returns an
    /// error, the client gets 500 with `internal`, the refs and the detached
    /// metadata stay written, the session ends as aborted, and the call does
    /// not occur. The host has the report in `after_update`. The client gets
    /// the message of the error in the `Error` frame, as the hook wrote it,
    /// cut at 4096 bytes. A host must thus not put secrets or internal
    /// details in it.
    pub on_report: Option<Arc<dyn Fn(ReceiveReport) + Send + Sync>>,
}

/// The report callback is stated by whether it is set.
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

/// The receive endpoint of a push over one repository, with the
/// authentication `A`, which a host mounts in its own router. The endpoint
/// opens no listener and does no TLS. The crate docs state how to mount
/// it.
pub struct ReceiveEndpoint<A: ReceiveAuth> {
    inner: Receive<A>,
    /// Fires at [`shutdown`](ReceiveEndpoint::shutdown), and ends
    /// [`sweep`](ReceiveEndpoint::sweep).
    stop: Arc<Shutdown>,
}

/// The repository and the authentication are left out.
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
    /// An endpoint over `repo` with the authentication `auth`. A
    /// `parallel_uploads` outside `1..=31`, a zero idle timeout, and a zero
    /// `max_sessions` are [`Error::Options`].
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

    /// The response to one request of the endpoint.
    ///
    /// The raw request path must start with `/_ostrya/receive/v1/`. A host
    /// that mounts the endpoint under a prefix removes the prefix before the
    /// call: `Router::nest_service` of axum does this. The path is not
    /// percent-decoded, and the query is ignored. Another path gets 404,
    /// and a `GET` or a `HEAD` of a route gets 405 with `Allow`. Before
    /// such an answer, the endpoint reads and drops up to 1 MiB of the
    /// body. The crate docs state the routes and the answers.
    ///
    /// A request body that fails is a request that ended before its
    /// response: the request gets 500 with `internal`, and its session
    /// ends.
    ///
    /// A panic in the commit, also in a hook of the session, is not caught.
    /// The commit runs in a task of its own, and the panic resumes in this
    /// call when the call joins that task. It thus panics the request task of
    /// the host: over HTTP/2 hyper resets the stream, and over HTTP/1.1 it
    /// closes the connection. The session ends and frees its slot. A panic in
    /// [`ReceiveHooks::after_update`](ostrya::ReceiveHooks::after_update)
    /// comes after the refs are written.
    ///
    /// Under the tokio backend, the call must run within a tokio runtime
    /// with the time driver enabled: the commit runs in a task of its own,
    /// and the time limits use the timer. A server signer that runs the
    /// GnuPG binaries also needs the IO driver.
    pub async fn handle<B>(&self, req: Request<B>) -> Response<ReceiveBody>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.inner.handle(req).await.map(ReceiveBody)
    }

    /// Abort each session past its idle timeout, and each session with a
    /// request body that delivered no byte for that time, until
    /// [`shutdown`](ReceiveEndpoint::shutdown). A session that commits is
    /// never aborted. Run the future once, in a task of its own, while the
    /// endpoint serves: without it no session reaches its idle timeout.
    /// After `shutdown` the future completes at once.
    ///
    /// Under the tokio backend, the future must run within a tokio runtime
    /// with the time driver enabled.
    pub async fn sweep(&self) {
        future::or(self.stop.wait(), self.inner.table.sweep()).await
    }

    /// Stop the endpoint: abort each session that does not commit, and end
    /// [`sweep`](ReceiveEndpoint::sweep). A commit that runs goes on to its
    /// end, also through the hooks of its session, and a `session` request
    /// after the call gets 503. A second call does nothing more.
    pub fn shutdown(&self) {
        self.stop.fire();
        self.inner.table.close_all();
    }

    /// The HTTP/2 receive windows for a connection that carries the
    /// endpoint: the window of each stream, 2 MiB, and the window of the
    /// connection, 2 MiB for each of the `parallel_uploads` object streams of
    /// a session. The request bodies of one connection thus hold at most
    /// that many bytes that the host did not read.
    pub fn h2_windows(&self) -> (u32, u32) {
        (UPLOAD_WINDOW, UPLOAD_WINDOW * self.inner.parallel_uploads)
    }
}

#[cfg(test)]
mod tests {
    use hyper::{Method, StatusCode};
    use ostrya::ReceivePolicy;
    use ostrya::push::ErrorCode;
    use ostrya::push::proto::{Hello, Kind, Message};
    use ostrya_rt::block_on;

    use super::*;
    use crate::ServeOptions;
    use crate::auth::{FileAuth, Peer};
    use crate::body::ServeBody;
    use crate::body::tests::frames;
    use crate::receive::PREFIX;
    use crate::session::tests::TmpRepo;

    /// The built-in authentication with anonymous push.
    fn anonymous() -> FileAuth {
        let opts = ServeOptions {
            allow_anonymous_push: true,
            ..ServeOptions::default()
        };
        FileAuth::new(&opts, Arc::new(ReceivePolicy::default())).unwrap()
    }

    fn endpoint(tmp: &TmpRepo, options: EndpointOptions) -> Result<ReceiveEndpoint<FileAuth>> {
        ReceiveEndpoint::new(tmp.repo.clone(), anonymous(), options)
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
    /// one is below the HTTP/2 maximum.
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
