#![forbid(unsafe_code)]

//! The HTTP server of ostrya.
//!
//! [`bind`] opens the listeners of a [`ServeOptions`], and [`Server::run`]
//! serves the archive view of one repository on them until its future is
//! dropped. [`serve`] does both. A pull of the `ostree` tool, or of the port,
//! reads the repository through it as an `archive` repository, whatever the
//! mode of the repository (see [`ostrya::ArchiveView`]). With
//! [`ServeOptions::receive`] the server also runs the receive endpoint of a
//! push (see below). A host with a router of its own mounts the endpoint
//! with [`ReceiveEndpoint`] (see "Mounting the endpoint").
//!
//! - `GET` and `HEAD` are served. Another method gets 405 with
//!   `Allow: GET, HEAD`, outside the receive endpoint.
//! - The request path is percent-decoded. A path that does not decode to
//!   UTF-8, or holds a NUL, gets 404. The query is ignored.
//! - A path the view does not find and a path it refuses both get 404 with an
//!   empty body, so a client cannot tell a private path from an absent one.
//!   An error of the view gets 500 with an empty body.
//! - A response with a known length carries `Content-Length`, and a `.filez`
//!   built on request carries none. The body is read in frames of at most
//!   64 KiB and is never collected whole. A `HEAD` takes the answer of
//!   [`ostrya::ArchiveView::head`]: it reads no byte of the file, and for a
//!   `.filez` built on request it reads no xattr and does no deflate work.
//! - Plain HTTP serves HTTP/1.1. Over TLS, ALPN selects HTTP/2 or HTTP/1.1.
//!   An HTTP/2 connection carries at most 32 streams at the same time. The
//!   TLS handshake of a connection has 30 seconds, and an HTTP/1.1
//!   connection has 30 seconds for the headers of each request.
//! - With a receive endpoint, the HTTP/2 receive window of a stream is
//!   2 MiB, and the window of a connection is 2 MiB for each of the
//!   [`ServeOptions::parallel_uploads`] object streams of a session. The
//!   request bodies of one connection thus hold at most that many bytes that
//!   the server did not read. A read-only server keeps the windows of
//!   hyper.
//! - A response body that waits longer than
//!   [`ServeOptions::body_timeout`] for the client to take its next bytes
//!   ends its connection, so a client that stops reading does not hold a
//!   file or a compressor. An HTTP/2 peer that does not answer a ping within
//!   that time loses its connection.
//! - A body that streams gives at most 256 KiB before it yields to the
//!   executor.
//! - With a client CA, a client certificate is verified against it, and a
//!   client that presents none is served.
//!
//! # The receive endpoint
//!
//! Each request under the raw path prefix `/_ostrya/receive/v1/` is one
//! step of a push session of [`ostrya::ReceiveService`]. The path is not
//! percent-decoded. The server runs the endpoint with
//! [`ServeOptions::receive`], and a host mounts it with [`ReceiveEndpoint`].
//! In the server, a `GET` or a `HEAD` under the prefix goes to the archive
//! view and gets 404. [`ReceiveEndpoint::handle`] answers a `GET` or a
//! `HEAD` of a route with 405 and `Allow`, as it answers each other wrong
//! method.
//!
//! - `POST session`, with a body of one `Hello` frame, opens a session. The
//!   response is 200 with the `HelloReply` frame, and the header
//!   `Ostrya-Session` carries the session id: 64 lowercase hex digits of 32
//!   bytes from the random source of the operating system.
//! - `POST session/ID/have`, with one `Have` frame, gets `HaveReply`.
//! - `POST session/ID/objects`, with one object stream, gets
//!   `ObjectsReply`. Up to [`EndpointOptions::parallel_uploads`] of these run
//!   at the same time in one session, and one more gets `limit-exceeded`.
//! - `POST session/ID/commit`, with one `Commit` frame, gets `CommitReply`.
//!   The commit runs in a task of its own, so a disconnect, a `DELETE`, or
//!   the idle timeout does not stop it. A second `commit` while the session
//!   commits gets 422 with `protocol`, and the first commit goes on.
//! - `DELETE session/ID` ends the session and the requests of the session
//!   in flight, and gets 204 with no body and no `Content-Length`. While the
//!   session commits it gets 422 with `protocol`, and the commit goes on.
//!
//! A path under the prefix that names no route, an id that is not a session
//! of the owner of the request, and a session that ended get 404 with no
//! body. A known path with another method gets 405 with `Allow: POST` or
//! `Allow: DELETE`. The body of `session`, `have`, and `commit` holds one
//! frame of at most 1 MiB, and an empty body or a byte after the frame is
//! `protocol`.
//!
//! Each other response body is one frame. An error is an `Error` frame:
//! `ref-mismatch` and `non-fast-forward` get 409, `internal` gets 500, and
//! every other code gets 422. An error of the server with no wire code gets
//! 500 with `internal` and the text of the error. A `session` request whose
//! `Hello` passes its checks gets 503 with `limit-exceeded` past
//! [`EndpointOptions::max_sessions`] (see below). A request that the
//! authentication refuses gets 401 or 403 with `unauthorized`. No response
//! that the endpoint builds itself carries `Content-Type` or `Retry-After`.
//! A refusal of the authentication carries the headers that it adds. Before
//! a refusal that comes before the body is read, the server reads and drops
//! up to 1 MiB of the body within the idle timeout or 5 seconds, whichever
//! is shorter. On HTTP/1.1 a body that did not reach its end then gets
//! `Connection: close`.
//!
//! A failed step ends its session, and the other requests of the session
//! in flight get 422 with `protocol` and the cause. A request that ends
//! before its response, as when the client closes the connection, ends its
//! session too, unless the session commits. A request body that fails, as
//! when the client closes the connection in the middle of the body, gives
//! the cause of a request that ended before its response. A session that
//! commits holds its slot until the commit ends, also when the commit fails
//! or panics. A session with no request in progress for
//! [`EndpointOptions::session_idle_timeout`] is aborted, and so is a session
//! with a request body that delivers no byte for that time. A request body
//! that the server does not read meanwhile does not count as silent. The
//! body of a `session` request must arrive in full within the idle timeout.
//! The future of [`ReceiveEndpoint::sweep`] applies the timeout. A session
//! that commits is never aborted. [`ReceiveEndpoint::shutdown`] aborts every
//! session that does not commit, and a session that opens after that gets
//! 503. [`Server::run`] runs the sweep in a task of its own, and calls
//! `shutdown` when its future drops.
//!
//! The report of each commit goes to [`EndpointOptions::on_report`] when the
//! response body drops. A `CommitReply` frame that hyper did not take from
//! the body adds a warning of the step
//! [`ReplyNotDelivered`](ostrya::ReceiveStep::ReplyNotDelivered). hyper can
//! take the frame and still fail to write it, so the warning is best
//! effort. The endpoint reads the receive policy and the repository
//! settings once, at start. A change applies at the next start. The server
//! takes the options of the endpoint from the fields of the same names in
//! [`ServeOptions`].
//!
//! # Authentication
//!
//! [`ReceiveAuth`] is the authentication of the endpoint. The endpoint calls
//! [`ReceiveAuth::authenticate`] for each request with a known route and
//! method, with the [`RequestKind`] of the route, before it reads a byte of
//! the body. For a `session` request it then does these steps, in this
//! order:
//!
//! 1. It reads `Hello`.
//! 2. It refuses a `Hello` with `one-way` true with `protocol`, before the
//!    check of the version.
//! 3. It checks `Hello` with [`ostrya::ReceiveService::check_hello`].
//! 4. It takes a slot of the session limit, or answers 503.
//! 5. It calls [`ReceiveAuth::open`], which gives the [`SessionSetup`] of
//!    the session: its receive policy. A refusal frees the slot.
//! 6. It opens the session.
//!
//! A bad `Hello` thus gets its 422 also when the sessions are at the limit
//! or the server stopped, and `open` sees valid ref names alone. The session
//! limit also limits the count of `open` calls that run at one time. A
//! session can fail to start after `open` returns, for example when a read
//! of the repository configuration fails, or when a `bare` repository gets
//! `mode-refused` because the server does not run as root.
//!
//! A [`Refusal`] of either call gets its status, 401 or 403, its headers,
//! and an `unauthorized` frame with its message. A message longer than
//! 4096 bytes is cut at a character boundary. The endpoint adds no
//! `WWW-Authenticate` header of its own. It drops a header of the refusal
//! named `Content-Length`, `Transfer-Encoding`, or `Connection`, because it
//! sets the framing and the connection state of the response itself. A
//! session belongs to the owner key, [`ReceiveAuth::owner`], of the
//! principal of its `session` request. A request of the session whose
//! principal gives another key gets the 404 of an unknown session.
//!
//! The server runs the endpoint with its built-in methods, and every
//! session gets the policy of [`ServeOptions::receive`]. [`bind`] refuses
//! an endpoint with no method. With no TLS, [`bind`] also refuses an
//! endpoint whose one method is the credential file, unless
//! [`ServeOptions::allow_cleartext_credentials`] is set. The methods are:
//!
//! - A bearer token, `Authorization: Bearer TOKEN`, which matches a line of
//!   [`ServeOptions::credentials`] by the SHA-256 digest of the token.
//! - A Basic credential, `Authorization: Basic` with the base64 of
//!   `NAME:TOKEN`, which matches the line of `NAME` by the digest of the
//!   token.
//! - A client certificate that the TLS handshake verified against the
//!   client CA of [`ServeOptions::tls`].
//! - [`ServeOptions::allow_anonymous_push`], for a request with no
//!   credential.
//!
//! The server compares the digest of a request with every line in constant
//! time, and does not stop at a match. The checks run in this order:
//!
//! 1. More than one `Authorization` header gets 401.
//! 2. A bearer or Basic credential on a connection without TLS gets 403,
//!    also where anonymous push is allowed, unless
//!    [`ServeOptions::allow_cleartext_credentials`] is set.
//! 3. An `Authorization` header that matches no line gets 401, also beside
//!    a client certificate.
//! 4. With no `Authorization` header, a client certificate gives its owner,
//!    then anonymous push where it is allowed. Else the request gets 401
//!    where the server has credential lines, and 403 where it has a client
//!    CA alone.
//!
//! The built-in methods add the headers `WWW-Authenticate: Bearer
//! realm="ostrya"` and `WWW-Authenticate: Basic realm="ostrya"` to each 401.
//! The owner key of a request has a prefix for each method: `token:NAME` for
//! a bearer token or a Basic credential, by the name of its credential line,
//! `cert:HEX` for a client certificate, by the lowercase hex SHA-256 digest
//! of its DER bytes, and `anonymous`. A bearer token and a Basic credential
//! of one line give one key. A `GET` and a `HEAD` of the archive view ignore
//! `Authorization`.
//!
//! # Mounting the endpoint
//!
//! [`ReceiveEndpoint`] is the receive endpoint with an authentication of the
//! host, [`ReceiveAuth`], which a host mounts in its own router. The
//! endpoint opens no listener and does no TLS. [`Server`] runs the same
//! endpoint with its built-in methods.
//!
//! - [`ReceiveEndpoint::handle`] takes the raw path from
//!   `/_ostrya/receive/v1/` on. A host that mounts the endpoint under a
//!   prefix, for example `/api/v1/push`, removes the prefix before the call.
//!   `Router::nest_service` of axum removes it itself. The push address of a
//!   client is then `https://HOST/api/v1/push`.
//! - The request body is any `B: Body<Data = Bytes> + Send + Unpin +
//!   'static` whose error converts into `Box<dyn Error + Send + Sync>`. The
//!   body need not be `Sync`, so the body of axum fits. The response body is
//!   [`ReceiveBody`].
//! - Run the future of [`ReceiveEndpoint::sweep`] once, in a task of its
//!   own, when the host starts. Without it no session reaches its idle
//!   timeout.
//! - Call [`ReceiveEndpoint::shutdown`] before the graceful shutdown of the
//!   listener. It aborts each session that does not commit, and each later
//!   `session` request gets 503. A commit that runs goes on to its end.
//! - Serve the endpoint on a dedicated listener, with a port or an SNI name
//!   of its own. On that listener, set the HTTP/2 windows of
//!   [`ReceiveEndpoint::h2_windows`], and set the most streams of one
//!   connection at the same time to 32, the value of the server. The
//!   request bytes that the host did not read are at most the connection
//!   window times the count of open connections, and the host grants the
//!   windows when it sets up a connection, before it authenticates a
//!   request. A listener for other routes keeps its own windows. The windows
//!   apply to a TLS listener that offers `h2` through ALPN, because the push
//!   client speaks HTTP/1.1 over cleartext.
//! - The runtime backend of the crate must be the runtime of the host: the
//!   `tokio` feature for a host on tokio. Under tokio, `handle` and `sweep`
//!   must run within a tokio runtime with the time driver enabled.
//!
//! The crate builds on Linux alone. The `smol` and `tokio` features select
//! the runtime backend of `ostrya-rt`.

mod auth;
mod body;
mod endpoint;
mod error;
mod options;
mod receive;
mod receive_auth;
mod request;
mod router;
mod server;
mod session;
mod shutdown;
mod stall;

pub use body::ReceiveBody;
pub use endpoint::{EndpointOptions, ReceiveEndpoint};
pub use error::{Error, Result};
pub use options::{ServeOptions, ServerTls};
pub use receive_auth::{ReceiveAuth, Refusal, RequestKind, SessionSetup};
pub use server::{Server, bind, serve};
