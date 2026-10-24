#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! An async HTTP/1.1 and HTTP/2 client over rustls, for the mirrors of a remote.
//!
//! A caller builds a [`Fetcher`] from the mirrors, headers, credentials, proxy,
//! TLS configuration, retry limits, and deadlines of one remote. The fetcher
//! downloads files with `GET` and sends uploads with `POST`, `PUT`, or
//! `DELETE`. A response body streams in bounded chunks, so no object is held
//! whole in memory.
//!
//! The [`Target`] of a request is a path under each mirror, a path with a
//! query string under each mirror, or an absolute URL. The fetcher sends a
//! path and a query as written, so the caller escapes them. A fetcher with a
//! [`RequestSigner`] sends a path in the form that
//! [`RequestSigner::request_path`] gives.
//!
//! A failed fetch gives the status of the response. On request, it also gives
//! the headers and a capped body of that response.
//!
//! # Entry points
//!
//! - [`Fetcher::new`] builds a fetcher from [`FetcherOptions`].
//! - [`Fetcher::fetch`] sends a [`FetchRequest`] and returns a [`Fetched`].
//! - [`ErrorResponse`] holds the headers and the capped body of an
//!   unsuccessful response, if the request asks for them.
//! - [`Body`] streams a response body in bounded chunks.
//! - [`Fetcher::refetching`] returns a [`Refetch`], which fetches a failed body again.
//! - [`Fetcher::upload`] sends an [`UploadRequest`] and returns an [`Uploaded`].
//! - [`UploadBody`] gives an upload body whole or streams it from an [`UploadWriter`].
//! - [`RequestSigner`] signs each attempt through [`FetcherOptions::signer`],
//!   and gives the form of each request path.
//! - [`Error`] is the error of each fallible operation of the crate.
//!
//! # Modules
//!
//! - [`gate`]: the priority admission gate that bounds concurrent work.
//!
//! # Features
//!
//! - `smol` (default): the `smol` backend of `ostrya-rt`.
//! - `tokio`: the `tokio` backend of `ostrya-rt`, with tokio I/O impls on [`Body`] and [`UploadWriter`].
//!
//! # Examples
//!
//! ```no_run
//! use futures_lite::AsyncReadExt;
//! use ostrya_fetch::{FetchRequest, Fetched, Fetcher, FetcherOptions};
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let fetcher = Fetcher::new(FetcherOptions::new("https://example.com/repo")).await?;
//! if let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::path("config")).await? {
//!     let mut config = Vec::new();
//!     body.read_to_end(&mut config).await?;
//! }
//! # Ok(())
//! # }
//! ```

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use futures_io::{AsyncRead, AsyncWrite};
use hyper::body::{Body as _, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::uri::Scheme;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use ostrya_rt as rt;
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};

mod error;
pub mod gate;
mod io;
mod tls;

pub use self::error::{Error, Result};

use gate::{Gate, Permit};
#[doc(hidden)]
pub use io::{FuturesIo, RtExecutor, RtTimer, WriteVectored};
use tls::{ClientConfigs, client_config};
pub use tls::{ClientIdentity, TlsOptions, TrustRoots};
#[doc(hidden)]
pub use tls::{client_cert_verifier, server_config};

/// The `User-Agent` value of each request. A `User-Agent` header of the fetcher
/// or of the request replaces it.
const USER_AGENT: &str = concat!("ostrya/", env!("CARGO_PKG_VERSION"));

/// The one content coding that a fetch accepts, which is no coding. Each
/// request asks for it, and a response that declares another coding fails the
/// attempt. An `Accept-Encoding` header of the fetcher or of the request
/// replaces the value that the fetcher sends.
const IDENTITY: &str = "identity";

/// The one transfer coding that a response can declare. It frames a message,
/// and the connection removes the framing, so the caller gets the body as the
/// remote wrote it. The fetcher sends no `TE` header, so another transfer coding
/// is a server fault. A response that declares one fails the attempt.
const CHUNKED: &str = "chunked";

/// The variables that [`Proxy::Environment`] reads, in the order of preference
/// of a lookup.
///
/// The list holds the lower-case name of each variable, and the upper-case name
/// where the lookup reads one. Nothing reads `HTTP_PROXY`. A CGI gateway gives a
/// request header `Proxy` to the program as `HTTP_PROXY`, so a client can set
/// that variable with a request.
const PROXY_VARIABLES: [&str; 7] = [
    "http_proxy",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
];

/// The scheme of a proxy URL. A proxy connection opens with this scheme alone.
const PROXY_SCHEME: &str = "http://";

/// The statuses at which a fetch follows a redirect. A fetch is a GET, so none
/// of the five changes the method of the next hop. The statuses that differ in
/// the method are one case here. An upload follows [`UPLOAD_REDIRECTS`] alone.
const REDIRECTS: [StatusCode; 5] = [
    StatusCode::MOVED_PERMANENTLY,
    StatusCode::FOUND,
    StatusCode::SEE_OTHER,
    StatusCode::TEMPORARY_REDIRECT,
    StatusCode::PERMANENT_REDIRECT,
];

/// The statuses at which an upload follows a redirect. These two keep the
/// method and the body, so the next hop sends the same request again.
const UPLOAD_REDIRECTS: [StatusCode; 2] = [
    StatusCode::TEMPORARY_REDIRECT,
    StatusCode::PERMANENT_REDIRECT,
];

/// The message for a layer that sets both credentials and an `Authorization`
/// header. The layer does not state which of the two the request sends. A
/// choice of one sends a credential that the caller did not choose.
const AMBIGUOUS_AUTHORIZATION: &str =
    "basic-auth credentials and an authorization header both set Authorization: pass one of them";

/// The message for a layer that sets both a bearer token and an
/// `Authorization` header, for the reason that [`AMBIGUOUS_AUTHORIZATION`]
/// states.
const AMBIGUOUS_BEARER: &str =
    "a bearer token and an authorization header both set Authorization: pass one of them";

/// The message for a layer that sets both basic-auth credentials and a bearer
/// token, for the reason that [`AMBIGUOUS_AUTHORIZATION`] states.
const BASIC_AND_BEARER: &str =
    "basic-auth credentials and a bearer token both set Authorization: pass one of them";

/// The message for a fetcher that has a request signer, and basic-auth
/// credentials on the fetcher or on a request. A signer sets the headers of
/// its signature, which can include `Authorization`, so the reason of
/// [`AMBIGUOUS_AUTHORIZATION`] applies.
const SIGNER_AND_BASIC: &str =
    "a request signer and basic-auth credentials both authorize the request: pass one of them";

/// The message for a fetcher that has a request signer, and a bearer token on
/// the fetcher or on a request, for the reason that [`SIGNER_AND_BASIC`]
/// states.
const SIGNER_AND_BEARER: &str =
    "a request signer and a bearer token both authorize the request: pass one of them";

/// The message for a fetcher that has a request signer, and an
/// `Authorization` header on the fetcher or on a request, for the reason that
/// [`SIGNER_AND_BASIC`] states.
const SIGNER_AND_AUTHORIZATION: &str =
    "a request signer and an authorization header both authorize the request: pass one of them";

/// The message for a layer that sets a `Host` header. The header states the
/// authority of the destination, and the fetcher reads it from the URL.
const HOST_COMES_FROM_THE_URL: &str = "the host header is set from the url the request is sent to";

/// The header names that the connection layer sets.
///
/// These names frame a request, or state what happens to the connection that
/// carries it. A value of the caller puts the wire and the connection pool out
/// of step. For example, a `Content-Length` of the caller ends the HTTP/1.1
/// connection under a pooled sender. The next fetch over that fetcher then
/// fails on a channel that the connection task dropped.
const CONNECTION_HEADERS: [&str; 9] = [
    "connection",
    "content-length",
    "expect",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The size of the frames of an upload body.
///
/// The writer fills one frame while the slot holds the frame that it handed
/// over last, so the writer holds at most two frames. hyper takes a body given
/// whole in frames of this size.
///
/// The connection buffers more of the body. Over HTTP/1.1, hyper takes another
/// frame while it holds fewer than 16 frames and less than 408 KiB. Over HTTP/2,
/// it holds up to two frames.
const UPLOAD_FRAME: usize = 64 * 1024;

/// The size under which a flush hands over a copy of its part-filled frame and
/// keeps the buffer. So a small frame that waits in the connection does not hold
/// a whole frame of memory.
const SMALL_FRAME: usize = 4 * 1024;

/// The longest idle time in the pool of an HTTP/1.1 connection that an upload
/// takes. [`Inner::take_upload`] states why an upload takes only a connection
/// that became idle a short time ago.
const UPLOAD_IDLE: Duration = Duration::from_secs(2);

/// The largest declared response body that a failed attempt reads to the end,
/// so that its HTTP/1.1 connection goes back to the pool. If the declared length
/// is larger, or if the response declares no length, the fetcher closes the
/// connection.
const DRAIN_LIMIT: u64 = 64 * 1024;

/// The largest capacity that a kept error body reserves before its bytes
/// arrive: 64 KiB. The declared length of the body is a claim of the server,
/// so it does not size an allocation.
const CAPTURE_RESERVE: u64 = 64 * 1024;

/// The HTTP/2 flow-control window of each stream. The default of hyper is
/// 64 KiB, which limits the throughput of one stream on a link with a high
/// bandwidth-delay product. An object fetch is one stream, so this window limits
/// it.
const H2_STREAM_WINDOW: u32 = 2 * 1024 * 1024;

/// The largest flow-control window the protocol allows, 2^31 - 1.
const H2_MAX_WINDOW: u32 = i32::MAX as u32;

/// How often an HTTP/2 connection with an open stream pings its peer, and how
/// long it waits for the reply. Both values are less than the default
/// [`progress_timeout`](FetcherOptions::progress_timeout). So the ping reports a
/// peer that went away, and no read waits for ever.
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(15);

/// The priority of a request that waits for admission to a [`Fetcher`].
///
/// If [`max_outstanding`](FetcherOptions::max_outstanding) requests are in
/// flight, a new request waits in a queue. The queue serves the highest
/// priority first, and requests of one priority in arrival order. The
/// [`gate`] module holds the queue.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum Priority {
    /// The lowest priority, for bulk content.
    Low,
    /// The middle priority, which is the default.
    #[default]
    Normal,
    /// The highest priority, for metadata that other work waits for.
    High,
}

/// The HTTP version of a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    /// HTTP/1.1.
    Http11,
    /// HTTP/2.
    Http2,
}

/// The credentials of HTTP basic authentication.
///
/// The [`Debug`] output shows the user name and a fixed word in place of the
/// password. So the log of a struct that holds credentials does not show the
/// password.
#[derive(Clone, Eq, PartialEq)]
pub struct BasicAuth {
    /// The user name.
    pub user: String,
    /// The password.
    pub password: String,
}

impl std::fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicAuth")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// A token for `Authorization: Bearer`.
///
/// The fetcher sends the token as written, so the token must have the token68
/// syntax of HTTP authentication. This is one or more ASCII letters, digits,
/// `-`, `.`, `_`, `~`, `+`, or `/`, then any number of `=`. If the token has
/// another form, [`Error::Fetch`] occurs. A request fails before admission, and
/// [`FetcherOptions::bearer_token`] fails [`Fetcher::new`]. The message holds
/// no part of the token.
///
/// The [`Debug`] output shows a fixed word in place of the token. So the log of
/// a struct that holds a token does not show it.
#[derive(Clone, Eq, PartialEq)]
pub struct BearerToken {
    /// The token.
    pub token: String,
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerToken")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// A signer that adds the headers of a request signature to each attempt.
///
/// [`FetcherOptions::signer`] holds the signer of a fetcher. The fetcher calls
/// [`sign`](RequestSigner::sign) once for each request that it sends to the
/// origin that the route names. This includes each retry, each round, and
/// each redirect hop at that origin. The call occurs after the fetcher takes
/// the connection, so a signature with a date is fresh when the request
/// leaves. An upload over a pooled HTTP/1.1 connection that the server closed
/// continues over a new connection, and the fetcher calls the signer again.
///
/// A redirect hop at another origin gets no signature. No later hop of that
/// attempt gets one, also a hop back to the named origin.
///
/// The fetcher calls the signer on the task of the request. A signer that
/// hashes a body given whole does that work on the task, on each call. A
/// caller with a large body gives the SHA-256 of the body with
/// [`UploadBody::bytes_with_sha256`], so that the signer gets
/// [`SignPayload::Sha256`] and hashes no byte of the body.
///
/// The path of a [`Target::Path`] or a [`Target::PathQuery`] goes through
/// [`request_path`](RequestSigner::request_path) before the fetcher adds it
/// to the base path of a mirror. So a signer that signs a canonical form of
/// the path gets a request that carries that form. A [`Target::Url`] goes on
/// the wire as written.
///
/// The [`Debug`] output of a signer must show no secret, because the
/// [`Debug`] output of [`FetcherOptions`] includes it.
pub trait RequestSigner: Send + Sync + std::fmt::Debug {
    /// Returns `path`, the path of a [`Target::Path`] or a
    /// [`Target::PathQuery`], in the form that the request carries.
    ///
    /// The fetcher calls this method once for each fetch and each upload
    /// with a path target, before admission. It adds the result to the base
    /// path of each mirror, in place of `path`. The fetcher does not call it
    /// for a [`Target::Url`], or for the query of a [`Target::PathQuery`].
    ///
    /// The default returns `path` unchanged. A signer whose signature covers
    /// a canonical form of the path returns that form, so the request
    /// carries the bytes that the signature covers.
    ///
    /// # Errors
    ///
    /// The fetcher passes an error of this method through unchanged, and the
    /// request ends with it before admission. Usually, the error is
    /// [`Error::Fetch`].
    fn request_path<'a>(&self, path: &'a str) -> Result<Cow<'a, str>> {
        Ok(Cow::Borrowed(path))
    }

    /// Returns the headers that sign `request`. Each one replaces a header of
    /// the same name.
    ///
    /// The fetcher refuses a returned header as it refuses a request header:
    /// an invalid name or value, a `Host` header, and a header that the
    /// connection layer sets. Each returned value is marked sensitive, so an
    /// HTTP/2 connection never adds it to its header compression table. Two
    /// returned headers of one name both go on the wire.
    ///
    /// # Errors
    ///
    /// The fetcher passes an error of this method through unchanged, and the
    /// request ends with it. The request sends nothing for the attempt, and
    /// the fetcher tries no other destination and no other round. An error on
    /// a redirect hop of an upload ends the upload with
    /// [`Error::UploadInterrupted`], because the first hop sent the request.
    /// Usually, the error is [`Error::Fetch`].
    fn sign(&self, request: &SignRequest<'_>) -> Result<Vec<(String, String)>>;
}

/// The parts of one attempt that a signer signs, as the request carries them.
#[derive(Clone, Copy, Debug)]
pub struct SignRequest<'a> {
    /// The method: `GET`, `POST`, `PUT`, or `DELETE`.
    pub method: &'a str,
    /// The `host[:port]` of the request, which is the `Host` header of an
    /// HTTP/1.1 request and the `:authority` of an HTTP/2 request.
    ///
    /// It has no default port of the scheme. An IPv6 literal keeps its
    /// brackets.
    pub authority: &'a str,
    /// The path of the request target, as the request carries it. It includes
    /// the base path of a mirror, and the escapes of the caller.
    pub path: &'a str,
    /// The query string of the request target, without the `?`.
    ///
    /// It is `None` if the target has no `?`. A target that ends in `?` has an
    /// empty query.
    pub query: Option<&'a str>,
    /// The body of the request.
    pub payload: SignPayload<'a>,
}

/// The body of a signed request.
///
/// The [`Debug`] output of [`Bytes`](SignPayload::Bytes) and of
/// [`Sha256`](SignPayload::Sha256) shows the length of the body, and not its
/// bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignPayload<'a> {
    /// No body: a `GET` or a `DELETE`.
    Empty,
    /// The whole body of a `POST` or a `PUT` that [`UploadBody::bytes`] gives.
    /// An empty body is also this variant.
    ///
    /// The signer gets the whole body on each attempt, and it runs on the task
    /// that sends the request. So the time to hash the body on that task grows
    /// with the size of the body. For a large body,
    /// [`UploadBody::bytes_with_sha256`] gives the signer the SHA-256 of the
    /// body as [`Sha256`](SignPayload::Sha256).
    Bytes(&'a [u8]),
    /// The whole body of a `POST` or a `PUT` that
    /// [`UploadBody::bytes_with_sha256`] gives, with the SHA-256 of the body
    /// that the caller computed.
    ///
    /// The fetcher does not check the digest. A wrong digest signs other
    /// bytes than the bytes that the request sends, and the server refuses
    /// the request.
    Sha256 {
        /// The whole body.
        bytes: &'a [u8],
        /// The SHA-256 of `bytes`, as the caller gave it.
        sha256: [u8; 32],
    },
    /// The body of a `POST` or a `PUT` that streams from an [`UploadWriter`].
    /// Its bytes are not known when the fetcher calls the signer.
    Streamed,
}

impl std::fmt::Debug for SignPayload<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignPayload::Empty => f.write_str("Empty"),
            SignPayload::Bytes(bytes) => f.debug_tuple("Bytes").field(&bytes.len()).finish(),
            SignPayload::Sha256 { bytes, .. } => {
                f.debug_tuple("Sha256").field(&bytes.len()).finish()
            }
            SignPayload::Streamed => f.write_str("Streamed"),
        }
    }
}

/// The validators of a response, which make a later fetch conditional.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Validators {
    /// The `ETag` of the response, sent back as `If-None-Match`.
    pub etag: Option<String>,
    /// The `Last-Modified` of the response, sent back as `If-Modified-Since`.
    pub last_modified: Option<String>,
}

impl Validators {
    /// Returns `true` if no validator holds a value.
    pub fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

/// The lowest transfer rate that a fetch accepts.
///
/// The fetcher samples the rate of a transfer once a second. Each sample is the
/// bytes of the last five seconds divided by five. In the first five seconds, a
/// sample is the bytes so far divided by the whole seconds so far.
///
/// If the rate stays at `limit` or less for `time` without a break, the
/// transfer fails as a transport failure. A transfer starts under the limit,
/// because it carried no bytes. A sample over the limit starts the count of
/// `time` again. For the response head, the count starts at the start of the
/// attempt, and for the body, at the first read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LowSpeed {
    /// The rate in bytes per second that a transfer must keep.
    ///
    /// A zero fails [`Fetcher::new`].
    pub limit: u32,
    /// The longest time that the rate can stay at `limit` or less.
    ///
    /// A zero fails [`Fetcher::new`]. The fetcher samples the rate once a
    /// second, so a part of a second counts as a whole second.
    pub time: Duration,
}

impl LowSpeed {
    /// Returns `time` rounded up to whole seconds. The addition saturates at the
    /// maximum and does not wrap.
    fn whole_seconds(&self) -> Duration {
        let partial = u64::from(self.time.subsec_nanos() > 0);
        Duration::from_secs(self.time.as_secs().saturating_add(partial))
    }
}

/// How often the low-speed rule samples the rate of a body.
const SAMPLE_PERIOD: Duration = Duration::from_secs(1);

/// The number of samples over which the low-speed rule measures the rate.
const RATE_SPAN: usize = 5;

/// The proxy through which a [`Fetcher`] reaches each origin.
///
/// [`Fetcher::new`] resolves each form once, and refuses a proxy URL that the
/// fetcher cannot connect through. A request does not read the environment
/// again.
///
/// The [`Debug`] output does not show the userinfo of a proxy URL. So the log
/// of a struct that holds proxy credentials does not show them.
///
/// # Variables
///
/// `http_proxy` serves `http` origins, and `https_proxy` serves `https`
/// origins. If the variable of the scheme is unset, `all_proxy` serves the
/// origin. The fetcher also reads each name in upper case, except `HTTP_PROXY`.
/// A CGI gateway gives a request header `Proxy` to the program as `HTTP_PROXY`,
/// so a client can set that variable with a request.
///
/// The lower-case name has priority over the upper-case name. An empty value
/// counts as unset.
///
/// # White space
///
/// If the value of `http_proxy`, `https_proxy`, or `all_proxy`, or of an
/// upper-case name, has white space at its start or end, [`Fetcher::new`]
/// fails with [`Error::Unsupported`]. A value of white space alone also fails.
/// It is not empty, so it counts as set and hides the upper-case name.
///
/// The fetcher checks the value of each variable that the lookup reads, when it
/// builds the fetcher. It checks a variable also if no request goes through
/// that proxy. The message names the variable and holds no part of the value,
/// which can hold a password. The fetcher trims the URL of [`Proxy::Url`] and
/// each `no_proxy` entry.
///
/// # Proxy URL
///
/// A proxy URL has the form `http://host[:port]`, and the port is 80 by
/// default. The URL has no path other than `/`, no query, and no fragment. The
/// fetcher percent-decodes the userinfo and sends it to the proxy as
/// `Proxy-Authorization: Basic`.
///
/// Any other form fails [`Fetcher::new`] with [`Error::Unsupported`], for
/// example an `https://` or a `socks5://` proxy. This applies to a URL from the
/// options and to a URL from the environment. The message names the value
/// without its userinfo.
///
/// # Exemptions
///
/// `no_proxy` is a comma-separated list of the origins that the two
/// environment forms exempt. An entry holds a host text, with one leading `.`
/// if it is written with one, and `:port` if it names a port. The fetcher
/// ignores the space around an entry. An entry that names no host exempts
/// nothing, for example an empty entry, `.`, or `:8080`.
///
/// If the port text of an entry is not a number from 0 to 65535, the whole
/// entry is one host text. No origin holds that text, so the entry exempts
/// nothing.
///
/// `*` as a whole entry exempts all hosts. It is the one wildcard that the list
/// reads. `*.example.com` is a host text, and no origin holds it.
///
/// An entry matches an origin if it equals the host, or if the host ends with a
/// `.` and the entry. The fetcher removes one leading `.` from the entry first,
/// so `.example.com` and `example.com` both exempt `a.example.com`. A second
/// leading `.` is part of the host text of the entry. An entry with `:port`
/// matches that port alone.
///
/// The match compares the host text of the URL, with ASCII case ignored. It
/// never compares the address of the host. So `localhost` exempts no origin
/// written as `127.0.0.1`, and an entry that is an IP literal matches that text
/// alone.
///
/// An entry in CIDR notation names no network. The fetcher reads it as a host
/// text, which no origin holds. This is a divergence from curl 7.86 and later,
/// which read such an entry as a network. An empty `no_proxy` value exempts
/// nothing, and [`Proxy::Url`] reads no exemptions.
///
/// # Cleartext origins
///
/// The fetcher reaches a cleartext origin behind a proxy over a connection to
/// the proxy. The request carries the absolute-form target, the whole
/// `http://host/path` URL, and the `Host` header of the origin. Such a
/// connection uses HTTP/1.1, because cleartext HTTP/2 needs prior knowledge or
/// an upgrade.
///
/// The pool keeps such a connection under the proxy endpoint, so one proxy
/// connection carries requests for all cleartext origins. The pool key marks a
/// connection as a proxy connection. So the pool never gives a direct
/// connection to the proxy endpoint to a proxied request, or the reverse. The
/// two request forms differ, and a server answers the unexpected form with a
/// 404.
///
/// # TLS origins
///
/// The fetcher reaches a TLS origin behind a proxy over a `CONNECT` tunnel. The
/// request names the target as `host:port`. The port is always written, and an
/// IPv6 literal keeps its brackets. If the proxy URL holds userinfo, the
/// `CONNECT` carries the same `Proxy-Authorization`.
///
/// On a 2xx answer, the fetcher gets the tunneled socket back. The TLS
/// handshake, the ALPN selection, and the pool entry are then the same as for a
/// direct connection to that origin. Nothing follows a `CONNECT` response, so a
/// byte that arrives before the client sends fails the connect.
///
/// A non-2xx answer is a retryable failure, and a 407 is a definitive failure.
/// Both are [`Error::Fetch`] and name the proxy.
/// [`connect_timeout`](FetcherOptions::connect_timeout) is the limit for all
/// these steps together: the connect to the proxy, the `CONNECT` exchange, the
/// TLS handshake, and the HTTP handshake.
///
/// # Proxy credential
///
/// The proxy credential belongs to the connection layer. It goes to the proxy
/// on a proxied cleartext request and on a `CONNECT`, and to no origin. It is
/// not in the merged header list, so the cleartext credential check and the
/// redirect scoping do not read it. A tunnel carries no part of it.
///
/// A `Proxy-Authorization` header that a caller sets keeps the meaning that it
/// has without a proxy. It is a credential in the merged list. A fetch refuses
/// it for a cleartext destination, as it refuses an `Authorization` or a
/// `Cookie` header.
///
/// On a proxied cleartext request, the header of the caller replaces the proxy
/// credential of the fetcher. Two values for one header give two answers to one
/// question. Over a tunnel, the two never meet. The header of the caller goes
/// to the origin, and the credential of the fetcher goes to the proxy.
///
/// # Redirects
///
/// The fetcher makes the proxy decision for each hop, from the origin of that
/// hop. So a redirect to another origin goes the same way as a route that names
/// that origin. A proxy does not change the cleartext rule: a cleartext origin
/// is cleartext also through a proxy.
///
/// # Examples
///
/// ```no_run
/// use ostrya_fetch::{Fetcher, FetcherOptions, Proxy};
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let mut options = FetcherOptions::new("https://example.com/repo");
/// options.proxy = Proxy::Variables(vec![
///     ("https_proxy".into(), "http://proxy.example.com:3128".into()),
///     ("no_proxy".into(), ".internal.example.com".into()),
/// ]);
/// let fetcher = Fetcher::new(options).await?;
/// # let _ = fetcher;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default)]
pub enum Proxy {
    /// A direct connection, whatever the environment holds.
    None,
    /// The proxy variables of the process environment.
    ///
    /// [`Fetcher::new`] reads the variables once. This is the default.
    /// [Variables](Proxy#variables) states the names, and
    /// [White space](Proxy#white-space) states the check of each value.
    #[default]
    Environment,
    /// The proxy variables, given as name and value pairs.
    ///
    /// The fetcher does not read the process environment. It ignores a name
    /// that the environment forms do not read. Of two entries of one name, the
    /// first entry with a value counts. [White space](Proxy#white-space) states
    /// the check of each value.
    Variables(Vec<(String, String)>),
    /// One `http://` proxy URL for all origins.
    ///
    /// The fetcher sends the userinfo of the URL as
    /// `Proxy-Authorization: Basic`. No origin is exempt, because the fetcher
    /// reads the environment for neither the proxy nor the exemptions. The
    /// fetcher trims white space around the URL.
    Url(String),
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Proxy::None => f.write_str("None"),
            Proxy::Environment => f.write_str("Environment"),
            Proxy::Variables(variables) => f
                .debug_tuple("Variables")
                .field(&RedactedVariables { variables })
                .finish(),
            Proxy::Url(url) => f.debug_tuple("Url").field(&RedactedUrl::url(url)).finish(),
        }
    }
}

/// The proxy variables in a [`Debug`] output: a list of name and value pairs.
///
/// Each value shows as [`RedactedUrl`] shows an absolute URL.
struct RedactedVariables<'a> {
    variables: &'a [(String, String)],
}

impl std::fmt::Debug for RedactedVariables<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let RedactedVariables { variables } = self;
        f.debug_list()
            .entries(
                variables
                    .iter()
                    .map(|(name, value)| (name, RedactedUrl::url(value))),
            )
            .finish()
    }
}

/// The headers in a [`Debug`] output: a list of name and `<redacted>` pairs.
///
/// A header value can be a credential, so no value shows. Each call of `names`
/// gives the name of each header value, in order.
struct RedactedHeaders<F> {
    names: F,
}

impl<'a, F, I> std::fmt::Debug for RedactedHeaders<F>
where
    F: Fn() -> I,
    I: Iterator<Item = &'a str>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries((self.names)().map(|name| (name, "<redacted>")))
            .finish()
    }
}

/// A URL or a request path in a [`Debug`] output, with no userinfo, query
/// value, or fragment value.
///
/// The userinfo of an absolute URL is the text after the `://` of the scheme,
/// up to and including the last `@`. When the text has no valid scheme before
/// the first `://`, the userinfo is the text from the start up to and including
/// the last `@`. A password can hold a `/`, `?`, or `#`, so the output removes
/// the userinfo first and leaves no marker for it. Then a query shows as
/// `?<redacted>`, and a fragment shows as `#<redacted>`. A path has no
/// userinfo. Each other part shows as the [`Debug`] output of a `str` shows it.
struct RedactedUrl<'a> {
    text: &'a str,
    /// `true` if `text` is an absolute URL, which can hold userinfo.
    absolute: bool,
}

impl<'a> RedactedUrl<'a> {
    /// Shows an absolute URL.
    fn url(text: &'a str) -> RedactedUrl<'a> {
        RedactedUrl {
            text,
            absolute: true,
        }
    }

    /// Shows a request path.
    fn path(text: &'a str) -> RedactedUrl<'a> {
        RedactedUrl {
            text,
            absolute: false,
        }
    }
}

impl std::fmt::Debug for RedactedUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;

        let RedactedUrl { text, absolute } = *self;
        let (scheme, rest) = if absolute {
            let end = scheme_len(text);
            let rest = &text[end..];
            let rest = rest.rfind('@').map_or(rest, |at| &rest[at + 1..]);
            (&text[..end], rest)
        } else {
            ("", text)
        };
        let (shown, query, fragment) = match rest.find(['?', '#']) {
            None => (rest, false, false),
            Some(at) if rest[at..].starts_with('#') => (&rest[..at], false, true),
            Some(at) => (&rest[..at], true, rest[at..].contains('#')),
        };
        // The `Debug` output of a `str` escapes each `char` as
        // `char::escape_debug` does, except `'`, which it writes as it is.
        f.write_char('"')?;
        for c in scheme.chars().chain(shown.chars()) {
            if c == '\'' {
                f.write_char(c)?;
            } else {
                for escaped in c.escape_debug() {
                    f.write_char(escaped)?;
                }
            }
        }
        if query {
            f.write_str("?<redacted>")?;
        }
        if fragment {
            f.write_str("#<redacted>")?;
        }
        f.write_char('"')
    }
}

/// A list of URLs in a [`Debug`] output, each one shown as [`RedactedUrl`]
/// shows an absolute URL.
struct RedactedUrls<'a> {
    urls: &'a [String],
}

impl std::fmt::Debug for RedactedUrls<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let RedactedUrls { urls } = self;
        f.debug_list()
            .entries(urls.iter().map(|url| RedactedUrl::url(url)))
            .finish()
    }
}

/// The options of a [`Fetcher`]: the remote, the credentials, and the limits.
///
/// [`FetcherOptions::default`] sets each field to the default that the field
/// states. [`FetcherOptions::new`] also sets one mirror.
///
/// The [`Debug`] output shows the name of each header, and `<redacted>` in
/// place of its value. The output also shows no password of `basic_auth`, no
/// token of `bearer_token`, no client key or passphrase, and no userinfo of a
/// proxy URL. Each mirror URL shows with no userinfo. A query shows as
/// `?<redacted>`, and a fragment shows as `#<redacted>`. The signer shows as
/// its own [`Debug`] output shows it.
#[derive(Clone)]
pub struct FetcherOptions {
    /// The base URLs, tried in order for each request that names a
    /// [`Target::Path`] or a [`Target::PathQuery`].
    ///
    /// A remote with a mirror list gives one entry for each mirror. A base URL
    /// is a scheme, an authority, and a path. A query string or userinfo fails
    /// [`Fetcher::new`], so neither part of a base URL reaches the wire. A
    /// request target is the base path, then `/` and the request path, then
    /// `?` and the query of a [`Target::PathQuery`]. With a
    /// [`signer`](FetcherOptions::signer), the request path is the path that
    /// [`RequestSigner::request_path`] gives.
    ///
    /// An empty list serves [`Target::Url`] requests alone. The default is an
    /// empty list.
    pub mirrors: Vec<String>,
    /// The extra headers of each request, to each destination and redirect hop.
    ///
    /// A request header of the same name replaces an entry. The fetcher sets
    /// `User-Agent` and `Accept-Encoding: identity`, and an entry of one of
    /// these names replaces the value of the fetcher. Other headers go as
    /// written. The default is an empty list.
    ///
    /// An `Authorization`, `Proxy-Authorization`, or `Cookie` header is a
    /// credential, because its value is a secret, whatever it holds. A
    /// credential goes to the origin that the route names, and to a redirect hop
    /// at that origin alone.
    ///
    /// [`Fetcher::new`] refuses these entries:
    ///
    /// - a credential header, if a mirror is cleartext `http` and
    ///   [`allow_cleartext_credentials`](FetcherOptions::allow_cleartext_credentials)
    ///   is `false`
    /// - a `Host` header
    /// - a header that the connection layer sets: a framing name or a
    ///   hop-by-hop name
    /// - an `Authorization` header beside
    ///   [`basic_auth`](FetcherOptions::basic_auth)
    /// - an `Authorization` header beside
    ///   [`bearer_token`](FetcherOptions::bearer_token)
    /// - an `Authorization` header beside [`signer`](FetcherOptions::signer)
    /// - an invalid header name or value.
    pub headers: Vec<(String, String)>,
    /// The credentials for `Authorization: Basic`, sent with each request.
    ///
    /// The credentials go to each destination, and to a redirect hop at the
    /// origin that the route names. [`FetchRequest::basic_auth`] replaces them
    /// for one request. The default is `None`.
    ///
    /// Each mirror must be `https`, unless
    /// [`allow_cleartext_credentials`](FetcherOptions::allow_cleartext_credentials)
    /// is `true`. [`Fetcher::new`] refuses a cleartext mirror, so the
    /// credentials go in cleartext only with that permission. An
    /// `Authorization` entry in [`headers`](FetcherOptions::headers), a
    /// [`bearer_token`](FetcherOptions::bearer_token), or a
    /// [`signer`](FetcherOptions::signer) beside these also fails
    /// [`Fetcher::new`], because each of them can set the same header.
    pub basic_auth: Option<BasicAuth>,
    /// The token for `Authorization: Bearer`, sent with each request.
    ///
    /// The token goes to each destination, and to a redirect hop at the origin
    /// that the route names. Each of these replaces it for one request:
    /// [`FetchRequest::basic_auth`], [`UploadRequest::basic_auth`],
    /// [`UploadRequest::bearer_token`], or an `Authorization` entry in the
    /// headers of the request. The default is `None`.
    ///
    /// [`Fetcher::new`] refuses a token that does not have the token68 syntax
    /// that [`BearerToken`] states. It also refuses the token beside
    /// [`basic_auth`](FetcherOptions::basic_auth), beside an
    /// `Authorization` entry in [`headers`](FetcherOptions::headers), or
    /// beside a [`signer`](FetcherOptions::signer), because each of them can
    /// set the same header.
    ///
    /// Each mirror must be `https`, unless
    /// [`allow_cleartext_credentials`](FetcherOptions::allow_cleartext_credentials)
    /// is `true`.
    pub bearer_token: Option<BearerToken>,
    /// The signer that adds a signature to each attempt at the origin that
    /// the route names.
    ///
    /// [`RequestSigner`] states when the fetcher calls the signer. The headers
    /// of the signer replace the headers of the same name in each layer: the
    /// fetcher and the request. A redirect hop at another origin gets no
    /// signature. The default is `None`.
    ///
    /// The signer is a credential. [`Fetcher::new`] refuses it beside
    /// [`basic_auth`](FetcherOptions::basic_auth), beside
    /// [`bearer_token`](FetcherOptions::bearer_token), and beside an
    /// `Authorization` entry in [`headers`](FetcherOptions::headers), because
    /// a signature can set the same header. For the same reason, a fetch or an
    /// upload with a credential of its own fails before admission: basic-auth
    /// credentials, a bearer token, or an `Authorization` request header.
    ///
    /// Each mirror must be `https`, unless
    /// [`allow_cleartext_credentials`](FetcherOptions::allow_cleartext_credentials)
    /// is `true`.
    pub signer: Option<Arc<dyn RequestSigner>>,
    /// The permission for a credential to reach a cleartext origin.
    ///
    /// If this is `true`, [`Fetcher::new`] does not refuse a cleartext mirror
    /// beside a credential: [`basic_auth`](FetcherOptions::basic_auth),
    /// [`bearer_token`](FetcherOptions::bearer_token),
    /// [`signer`](FetcherOptions::signer), or a credential header in
    /// [`headers`](FetcherOptions::headers). A fetch or an upload also does
    /// not refuse a credential for a cleartext destination, whatever the flag
    /// of the request is. [`FetchRequest::allow_cleartext_credentials`] states
    /// that rule.
    ///
    /// The redirect rules apply with this flag. A hop at another origin gets no
    /// credential and no signature, and a hop from `https` to `http` is
    /// refused. The default is `false`.
    ///
    /// A caller sets it for a server on a loopback address, or for a server
    /// behind a proxy that terminates TLS.
    pub allow_cleartext_credentials: bool,
    /// The trust anchors and the client certificate for `https` mirrors.
    ///
    /// The default is [`TlsOptions::default`]: [`TrustRoots::System`] and no
    /// client identity.
    pub tls: TlsOptions,
    /// The proxy through which the fetcher reaches an origin.
    ///
    /// [`Fetcher::new`] resolves the value once, and a request does not read it
    /// again. It refuses a proxy URL that is not `http://host[:port]`, and a
    /// proxy variable with [white space](Proxy#white-space) around its value.
    /// The default is [`Proxy::Environment`], the proxy that the process
    /// environment names.
    pub proxy: Proxy,
    /// The switch that offers HTTP/2 in ALPN.
    ///
    /// If this is `false`, the fetcher uses HTTP/1.1, also with a server that
    /// supports HTTP/2. The default is `true`.
    pub http2: bool,
    /// The number of times that a fetch repeats a round after a retryable
    /// failure.
    ///
    /// [`Fetcher::fetch`] states the retry rules. The default is 5.
    pub max_retries: u32,
    /// The number of redirects that one attempt against one destination
    /// follows.
    ///
    /// The attempt follows a 301, 302, 303, 307, or 308 while it followed fewer
    /// redirects than this value. If the next one names a URL, the attempt fails
    /// definitively with [`Error::RedirectLimit`]. If it names no URL, the
    /// attempt reports its own status.
    ///
    /// Zero follows nothing, so each of those statuses is then a definitive
    /// answer. A fetch with [`FetchRequest::max_error_body`] then gets the
    /// headers of the redirect, `Location` included, in its
    /// [`Error::HttpStatus`]. The count belongs to one attempt, so a repeated
    /// round counts again from the destination that the route names.
    /// [`Fetcher::fetch`] states the redirect rules. The default is 10.
    pub max_redirects: u32,
    /// The number of requests in flight at one time.
    ///
    /// The fetcher admits this many requests at a time, and serves the queue in
    /// [`Priority`] order. A request holds its permit until the fetch fails, or
    /// until its response body reaches its end or is dropped. A body in flight
    /// occupies a connection, so it keeps the permit.
    ///
    /// The default is 8. The fetcher admits at least one request, so 0 admits
    /// one request.
    pub max_outstanding: usize,
    /// The time limit to open a connection.
    ///
    /// The limit applies to the TCP connect, the TLS handshake, and the HTTP
    /// handshake together. Through a proxy, it also applies to the connect to
    /// the proxy and to the `CONNECT` exchange.
    ///
    /// The TCP connect resolves the host name, then races the addresses that
    /// the resolver gave. A new attempt starts every 250ms, and an attempt that
    /// fails starts the next one immediately. So the limit includes the
    /// resolution and all attempts.
    ///
    /// The expiry is a transport failure. So it is retryable, and the fetch
    /// tries the next destination. The default is 30 s.
    pub connect_timeout: Duration,
    /// The longest time that a response can go without bytes.
    ///
    /// The window applies to the wait for the response head and to each stall
    /// of the body. It measures the silence since a read asked for bytes. So it
    /// limits silence, and leaves the transfer time unlimited.
    ///
    /// The window runs from the read that finds no bytes until bytes arrive.
    /// After a read found no bytes, the window runs also when no read is
    /// outstanding. A body that no read found empty is not on the clock.
    ///
    /// If the body stalls, the read fails with
    /// [`io::ErrorKind::TimedOut`](std::io::ErrorKind::TimedOut), and each
    /// later read fails the same way. An expired wait for the head is a
    /// retryable transport failure, so the fetch tries the next destination.
    /// The default is 60 s.
    pub progress_timeout: Duration,
    /// The lowest transfer rate that an attempt accepts, as [`LowSpeed`]
    /// states.
    ///
    /// The response head must arrive within `time` of the start of the attempt,
    /// rounded up to whole seconds, redirects included. The rate of the body
    /// counts from its first read. So the fetcher does not measure a body that
    /// waits for its consumer before the consumer asks for bytes.
    ///
    /// The fetcher samples the body only while a read is outstanding. A gap
    /// between reads that is longer than a second counts as one second. The
    /// bytes that arrived in the gap count at the next read.
    ///
    /// A transfer slower than the rate is a transport failure. A slow head is a
    /// retryable failure of the attempt. A slow body fails the read with
    /// [`io::ErrorKind::TimedOut`](std::io::ErrorKind::TimedOut).
    ///
    /// `None` checks no rate. The default is `None`.
    pub low_speed: Option<LowSpeed>,
    /// The longest time that one fetch can take to get a response head.
    ///
    /// The limit includes all rounds, all retries, and the delays between them,
    /// from the admission of the fetch until the response head arrives. Only
    /// [`progress_timeout`](FetcherOptions::progress_timeout) limits the body
    /// that follows. `None` sets no limit. The default is 300 s.
    ///
    /// This limit is the longest time that a fetch with no response holds an
    /// admission permit. So a caller sizes it against
    /// [`max_outstanding`](FetcherOptions::max_outstanding). Without this
    /// limit, an unresponsive peer can stall a fetch for a product of three
    /// values. These are the destination count, the retry count, and the two
    /// deadlines of an attempt.
    ///
    /// On expiry, the fetch fails with [`Error::Fetch`] and tries nothing more.
    /// The attempt that the expiry cancels releases the admission permit. An
    /// upload has a narrower limit, which [`Fetcher::upload`] states.
    pub fetch_timeout: Option<Duration>,
}

impl Default for FetcherOptions {
    fn default() -> Self {
        FetcherOptions {
            mirrors: Vec::new(),
            headers: Vec::new(),
            basic_auth: None,
            bearer_token: None,
            signer: None,
            allow_cleartext_credentials: false,
            tls: TlsOptions::default(),
            proxy: Proxy::default(),
            http2: true,
            max_retries: 5,
            max_redirects: 10,
            max_outstanding: 8,
            connect_timeout: Duration::from_secs(30),
            progress_timeout: Duration::from_secs(60),
            low_speed: None,
            fetch_timeout: Some(Duration::from_secs(300)),
        }
    }
}

impl std::fmt::Debug for FetcherOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let FetcherOptions {
            mirrors,
            headers,
            basic_auth,
            bearer_token,
            signer,
            allow_cleartext_credentials,
            tls,
            proxy,
            http2,
            max_retries,
            max_redirects,
            max_outstanding,
            connect_timeout,
            progress_timeout,
            low_speed,
            fetch_timeout,
        } = self;
        let headers = RedactedHeaders {
            names: || headers.iter().map(|(name, _)| name.as_str()),
        };
        f.debug_struct("FetcherOptions")
            .field("mirrors", &RedactedUrls { urls: mirrors })
            .field("headers", &headers)
            .field("basic_auth", basic_auth)
            .field("bearer_token", bearer_token)
            .field("signer", signer)
            .field("allow_cleartext_credentials", allow_cleartext_credentials)
            .field("tls", tls)
            .field("proxy", proxy)
            .field("http2", http2)
            .field("max_retries", max_retries)
            .field("max_redirects", max_redirects)
            .field("max_outstanding", max_outstanding)
            .field("connect_timeout", connect_timeout)
            .field("progress_timeout", progress_timeout)
            .field("low_speed", low_speed)
            .field("fetch_timeout", fetch_timeout)
            .finish()
    }
}

impl FetcherOptions {
    /// Creates options with one base URL and the default of each other field.
    pub fn new(url: impl Into<String>) -> FetcherOptions {
        FetcherOptions {
            mirrors: vec![url.into()],
            ..FetcherOptions::default()
        }
    }
}

/// The target of a request.
///
/// The [`Debug`] output shows no userinfo of a URL. A query shows as
/// `?<redacted>`, and a fragment shows as `#<redacted>`, in a URL and in a
/// path. The query of [`Target::PathQuery`] shows as `<redacted>`.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Target<'a> {
    /// A path under the base URL of each mirror.
    Path(&'a str),
    /// A path under the base URL of each mirror, with a query string.
    ///
    /// The fetcher adds `?` and the query to the URL of each mirror. It sends
    /// the query as written, so the query carries the escapes that the server
    /// expects.
    PathQuery {
        /// The path, read as [`Target::Path`] is.
        path: &'a str,
        /// The query string, without the `?`.
        query: &'a str,
    },
    /// An absolute `http` or `https` URL.
    ///
    /// The fetcher does not use the mirror list for it.
    Url(&'a str),
}

impl std::fmt::Debug for Target<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Target::Path(path) => f
                .debug_tuple("Path")
                .field(&RedactedUrl::path(path))
                .finish(),
            Target::PathQuery { path, query: _ } => f
                .debug_struct("PathQuery")
                .field("path", &RedactedUrl::path(path))
                .field("query", &"<redacted>")
                .finish(),
            Target::Url(url) => f.debug_tuple("Url").field(&RedactedUrl::url(url)).finish(),
        }
    }
}

impl<'a> Target<'a> {
    /// Returns the text that names the target in each message: the path, the
    /// path with `?` and its query, or the URL, as the caller wrote it.
    fn describe(&self) -> Cow<'a, str> {
        match *self {
            Target::Path(path) => Cow::Borrowed(path),
            Target::PathQuery { path, query } => Cow::Owned(format!("{path}?{query}")),
            Target::Url(url) => Cow::Borrowed(url),
        }
    }
}

/// The request of one fetch.
///
/// The [`Debug`] output shows the name of each header, and `<redacted>` in
/// place of its value. The target shows as the [`Debug`] output of [`Target`]
/// shows it.
#[derive(Clone)]
pub struct FetchRequest<'a> {
    /// The target: a path under the base URL of each mirror, the same with a
    /// query string, or an absolute URL.
    ///
    /// The fetcher adds a path to the base path as written, so the path carries
    /// the escapes that the server expects. A path holds no `?` and no `#`,
    /// because neither is part of a path. Either one fails the fetch before
    /// admission. If the fetcher has a
    /// [`signer`](FetcherOptions::signer), the fetcher adds the path that
    /// [`RequestSigner::request_path`] gives in place of the path.
    ///
    /// The fetcher adds `?` and the query of [`Target::PathQuery`] after the
    /// path, as written, so the query carries the escapes that the server
    /// expects. A query holds no `#`, because a `#` starts a fragment. A `#`
    /// fails the fetch before admission.
    ///
    /// The fetcher sends the query string of a URL as written. A fragment in a
    /// URL fails the fetch, because no request sends a fragment. A character
    /// that a request target cannot hold fails the fetch when the fetcher
    /// assembles the URL.
    pub target: Target<'a>,
    /// The place of the request in the queue when the fetcher is at its limit.
    pub priority: Priority,
    /// The validators of a previous fetch.
    ///
    /// If the server reports that the copy is still current, the fetch gives
    /// [`Fetched::NotModified`].
    pub validators: Option<&'a Validators>,
    /// The largest response body, in bytes, that the fetch accepts.
    ///
    /// A larger `Content-Length` fails the fetch with [`Error::FetchTooLarge`].
    /// If a body grows past the cap while it streams, the read fails with
    /// [`io::ErrorKind::FileTooLarge`](std::io::ErrorKind::FileTooLarge). The
    /// fetcher compares the cap with the response that answers, and does not
    /// measure an intermediate redirect response.
    pub max_size: Option<u64>,
    /// Headers merged over the headers of the fetcher.
    ///
    /// An entry replaces a fetcher header of the same name. Names compare as
    /// `HeaderName`, so the comparison ignores case. Two entries of one name
    /// both go on the wire. An invalid name or value fails the fetch before
    /// admission.
    ///
    /// The fetcher sets `User-Agent` and `Accept-Encoding: identity`, and an
    /// entry of one of these names replaces the value. An entry can ask for a
    /// content coding. A response that declares a coding fails with
    /// [`Error::ContentEncoded`], whichever layer asked for it.
    ///
    /// A `Host` entry fails the fetch, because the header comes from the URL. A
    /// header that the connection layer sets fails at both layers: a framing
    /// name or a hop-by-hop name. The connection owns the framing of a request
    /// and the state of its connection. A value of the caller puts the wire and
    /// the connection pool out of step.
    ///
    /// # Authorization
    ///
    /// The request carries the `Authorization` header of the first of these
    /// that is set:
    ///
    /// 1. [`FetchRequest::basic_auth`]
    /// 2. an `Authorization` entry in these headers
    /// 3. [`FetcherOptions::basic_auth`] or [`FetcherOptions::bearer_token`]
    /// 4. an `Authorization` entry in [`FetcherOptions::headers`].
    ///
    /// Credentials beside an `Authorization` header in one layer give two
    /// answers to one question. [`Fetcher::new`] refuses them on the fetcher,
    /// and the fetch refuses them on a request.
    ///
    /// A fetcher with a [`signer`](FetcherOptions::signer) takes no
    /// credential of a request. [`basic_auth`](FetchRequest::basic_auth) or
    /// an `Authorization` entry in these headers then fails the fetch before
    /// admission with [`Error::Fetch`]. [`Fetcher::new`] refuses layers 3 and
    /// 4 beside a signer. So the signature is the one credential of the
    /// request, and each header that the signer returns replaces the header
    /// of the same name.
    pub headers: &'a [(String, String)],
    /// Credentials that replace the credentials of the fetcher for this
    /// request.
    ///
    /// These set the `Authorization` header, so an `Authorization` entry in
    /// [`headers`](FetchRequest::headers) beside them fails the fetch. A
    /// [`signer`](FetcherOptions::signer) of the fetcher beside them also
    /// fails the fetch before admission with [`Error::Fetch`].
    ///
    /// The fetcher encodes the header value for each request. A caller that
    /// sends one credential over many requests can encode the `Authorization`
    /// value once and set it in [`headers`](FetchRequest::headers). That entry
    /// replaces the credential of the fetcher for the request in the same way.
    pub basic_auth: Option<&'a BasicAuth>,
    /// The permission for a credential to reach a cleartext origin.
    ///
    /// If this is `false` and the merged headers carry a credential, the fetch
    /// fails if a destination that it can reach is `http`. The merged headers
    /// include the credentials of the fetcher. The check of [`Fetcher::new`] on
    /// the mirror list applies whatever this value is. The default is `false`.
    ///
    /// [`FetcherOptions::allow_cleartext_credentials`] lifts this refusal for
    /// each request of the fetcher.
    ///
    /// A redirect hop never carries a credential to a cleartext origin of its
    /// own. The fetcher removes the credential for a hop at another origin, and
    /// refuses a hop from `https` to `http`. [`Fetcher::fetch`] states the
    /// redirect rules.
    ///
    /// # Cleartext credentials
    ///
    /// The fetcher withholds a credential from no destination that a route
    /// names. So it refuses a credential and a cleartext destination together.
    /// The credentials are [`basic_auth`](FetchRequest::basic_auth), and an
    /// `Authorization`, `Proxy-Authorization`, or `Cookie` entry in the merged
    /// headers. [`FetcherOptions::basic_auth`] and
    /// [`FetcherOptions::bearer_token`] are `Authorization` entries in the
    /// merged headers. [`FetcherOptions::signer`] is also a credential.
    ///
    /// If a fetch carries a credential and a destination that it can reach is
    /// `http`, the fetch fails before admission with [`Error::Fetch`]. The
    /// message names that origin. The other choice is to withhold the
    /// credential from that one destination. That choice turns a configuration
    /// mistake into a 401 that names nothing.
    pub allow_cleartext_credentials: bool,
    /// The largest body of an unsuccessful response that the fetch keeps.
    ///
    /// With `Some(cap)`, a fetch that fails with [`Error::HttpStatus`] gives
    /// the headers of the reported response in that error. It also gives the
    /// body, if the whole body is `cap` bytes or less. `Some(0)` keeps the
    /// headers and an empty body. [`ErrorResponse`] states when the body is
    /// absent.
    ///
    /// `None` keeps nothing, and the fetch discards each unsuccessful
    /// response. The default is `None`.
    ///
    /// [`Fetcher::fetch`] states the rules in its section "Error responses".
    pub max_error_body: Option<u64>,
}

impl std::fmt::Debug for FetchRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let FetchRequest {
            target,
            priority,
            validators,
            max_size,
            headers,
            basic_auth,
            allow_cleartext_credentials,
            max_error_body,
        } = self;
        let headers = RedactedHeaders {
            names: || headers.iter().map(|(name, _)| name.as_str()),
        };
        f.debug_struct("FetchRequest")
            .field("target", target)
            .field("priority", priority)
            .field("validators", validators)
            .field("max_size", max_size)
            .field("headers", &headers)
            .field("basic_auth", basic_auth)
            .field("allow_cleartext_credentials", allow_cleartext_credentials)
            .field("max_error_body", max_error_body)
            .finish()
    }
}

impl<'a> FetchRequest<'a> {
    /// Creates a request for `path` under each mirror.
    ///
    /// The request has normal priority, no validators, and no size cap. It
    /// carries the headers and the credentials of the fetcher.
    pub fn path(path: &'a str) -> FetchRequest<'a> {
        FetchRequest::for_target(Target::Path(path))
    }

    /// Creates a request for `path` with the query string `query` under each
    /// mirror.
    ///
    /// The query has no leading `?`. The request has normal priority, no
    /// validators, and no size cap. It carries the headers and the
    /// credentials of the fetcher.
    pub fn path_query(path: &'a str, query: &'a str) -> FetchRequest<'a> {
        FetchRequest::for_target(Target::PathQuery { path, query })
    }

    /// Creates a request for the absolute URL `url`.
    ///
    /// The request has normal priority, no validators, and no size cap. It
    /// carries the headers and the credentials of the fetcher.
    pub fn url(url: &'a str) -> FetchRequest<'a> {
        FetchRequest::for_target(Target::Url(url))
    }

    /// Creates a request for `target` with the default of each other field.
    fn for_target(target: Target<'a>) -> FetchRequest<'a> {
        FetchRequest {
            target,
            priority: Priority::default(),
            validators: None,
            max_size: None,
            headers: &[],
            basic_auth: None,
            allow_cleartext_credentials: false,
            max_error_body: None,
        }
    }
}

/// The result of a fetch.
#[derive(Debug)]
// The body variant is much larger than the other variant. A box adds an
// allocation on the path of each object, so the variant stays inline.
#[allow(clippy::large_enum_variant)]
pub enum Fetched {
    /// The body of the object that the server sent.
    Body(Body),
    /// A 304 answer: the copy of the caller is current.
    NotModified,
}

/// The method of an upload.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum UploadMethod {
    /// `POST`, which sends the body.
    ///
    /// This is the default.
    #[default]
    Post,
    /// `PUT`, which sends the body.
    ///
    /// The retry and the redirect rules of [`Post`](UploadMethod::Post)
    /// apply.
    Put,
    /// `DELETE`, which sends no body.
    ///
    /// The request takes an empty [`UploadBody::bytes`]. Any other body fails
    /// the upload before admission with [`Error::Fetch`].
    Delete,
}

/// The request body of an upload.
///
/// A body has one of two forms:
///
/// - [`bytes`](UploadBody::bytes) gives the whole body. The request declares
///   its `Content-Length`, and hyper takes the bytes in frames of 64 KiB. A
///   followed redirect sends the bytes again.
///   [`bytes_with_sha256`](UploadBody::bytes_with_sha256) also gives the
///   SHA-256 of the body to the signer.
/// - [`channel`](UploadBody::channel) streams the body. The caller writes the
///   body into the [`UploadWriter`] while the upload runs. Over HTTP/1.1, the
///   body travels chunked.
///
/// If a channel body is dropped before an upload sends it, or after its upload
/// ends, each write of its writer fails with
/// [`io::ErrorKind::BrokenPipe`](std::io::ErrorKind::BrokenPipe). If the body
/// of a `POST` or a `PUT` is at its end when the fetcher hands over the
/// request, the request declares a `Content-Length` of zero.
pub struct UploadBody {
    form: UploadForm,
}

/// The two forms of an [`UploadBody`].
enum UploadForm {
    /// The whole body, which each hop of the upload sends, and the SHA-256
    /// of the body if the caller gave it.
    Bytes {
        bytes: Bytes,
        sha256: Option<[u8; 32]>,
    },
    /// The reading end of a body that an [`UploadWriter`] fills.
    Channel(BodyEnd),
}

impl UploadBody {
    /// Creates a body of `bytes`.
    ///
    /// The request sends the vector in frames cut from it with no copy.
    pub fn bytes(bytes: Vec<u8>) -> UploadBody {
        UploadBody {
            form: UploadForm::Bytes {
                bytes: Bytes::from(bytes),
                sha256: None,
            },
        }
    }

    /// Creates a body of `bytes`, whose SHA-256 is `sha256`.
    ///
    /// The body is a body of [`bytes`](UploadBody::bytes). A signer gets it
    /// as [`SignPayload::Sha256`] with `sha256`, so a signer that signs the
    /// SHA-256 of the body hashes no byte of it on the task of the request.
    /// Each retry and each redirect hop of the upload uses the same digest,
    /// and so does a copy from [`try_clone`](UploadBody::try_clone).
    ///
    /// The fetcher does not check the digest. A wrong digest signs other
    /// bytes than the bytes that the request sends, and the server refuses
    /// the request.
    pub fn bytes_with_sha256(bytes: Vec<u8>, sha256: [u8; 32]) -> UploadBody {
        UploadBody {
            form: UploadForm::Bytes {
                bytes: Bytes::from(bytes),
                sha256: Some(sha256),
            },
        }
    }

    /// Creates a streamed body and the writer that fills it.
    pub fn channel() -> (UploadBody, UploadWriter) {
        let exchange = Arc::new(Exchange::default());
        let body = UploadBody {
            form: UploadForm::Channel(BodyEnd {
                exchange: exchange.clone(),
            }),
        };
        let writer = UploadWriter {
            exchange,
            // The first write allocates the frame. So a body that gets no
            // write holds no frame of memory.
            buffer: Vec::new(),
            stall: None,
            failed: None,
        };
        (body, writer)
    }

    /// Returns the bytes of a body of [`bytes`](UploadBody::bytes), or `None`
    /// for a streamed body.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.form {
            UploadForm::Bytes { bytes, .. } => Some(bytes),
            UploadForm::Channel(_) => None,
        }
    }

    /// Returns the SHA-256 of a body of
    /// [`bytes_with_sha256`](UploadBody::bytes_with_sha256), or `None` for
    /// another body.
    pub fn sha256(&self) -> Option<[u8; 32]> {
        match &self.form {
            UploadForm::Bytes { sha256, .. } => *sha256,
            UploadForm::Channel(_) => None,
        }
    }

    /// Returns a second body with the same bytes, or `None` for a streamed
    /// body.
    ///
    /// The two bodies of [`bytes`](UploadBody::bytes) share the one buffer, so
    /// the call copies no byte. The copy keeps the SHA-256 of a body of
    /// [`bytes_with_sha256`](UploadBody::bytes_with_sha256). A caller sends
    /// the copy in a second request, for example after the first one failed
    /// with [`Error::UploadInterrupted`]. A [`channel`](UploadBody::channel)
    /// body has one writer, so it has no copy.
    pub fn try_clone(&self) -> Option<UploadBody> {
        match &self.form {
            UploadForm::Bytes { bytes, sha256 } => Some(UploadBody {
                form: UploadForm::Bytes {
                    bytes: bytes.clone(),
                    sha256: *sha256,
                },
            }),
            UploadForm::Channel(_) => None,
        }
    }

    /// Returns the bytes of a body of [`bytes`](UploadBody::bytes) as a
    /// vector, or the body unchanged.
    ///
    /// If no other body shares the buffer, the call gives the buffer back
    /// with its capacity, and copies no byte. A caller can then fill the
    /// vector again for a later request. The vector does not keep the
    /// SHA-256 of a body of
    /// [`bytes_with_sha256`](UploadBody::bytes_with_sha256). A copy from
    /// [`try_clone`](UploadBody::try_clone) shares the buffer, and so does an
    /// upload that still holds the body. The call then returns the body as
    /// the error, as it does for a [`channel`](UploadBody::channel) body.
    ///
    /// # Errors
    ///
    /// Returns the body unchanged if it is a streamed body, or if another
    /// body shares its buffer.
    pub fn into_vec(self) -> std::result::Result<Vec<u8>, UploadBody> {
        match self.form {
            UploadForm::Bytes { bytes, sha256 } => match bytes.try_into_mut() {
                Ok(bytes) => Ok(Vec::from(bytes)),
                Err(bytes) => Err(UploadBody {
                    form: UploadForm::Bytes { bytes, sha256 },
                }),
            },
            UploadForm::Channel(end) => Err(UploadBody {
                form: UploadForm::Channel(end),
            }),
        }
    }
}

impl From<Vec<u8>> for UploadBody {
    fn from(bytes: Vec<u8>) -> UploadBody {
        UploadBody::bytes(bytes)
    }
}

impl std::fmt::Debug for UploadBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.form {
            UploadForm::Bytes { bytes, .. } => f.debug_tuple("Bytes").field(&bytes.len()).finish(),
            UploadForm::Channel(_) => f.write_str("Channel"),
        }
    }
}

/// The request of one upload, which sends a body and gets a bounded response.
///
/// The [`Debug`] output shows the name of each header, and `<redacted>` in
/// place of its value. The target shows as the [`Debug`] output of [`Target`]
/// shows it.
pub struct UploadRequest<'a> {
    /// The target, read as [`FetchRequest::target`] is. A
    /// [`Target::PathQuery`] goes to the mirrors with its query, as for a
    /// fetch.
    ///
    /// The fetcher tries the mirrors in order until one of them takes the
    /// request. It never asks a mirror after that one.
    pub target: Target<'a>,
    /// The method.
    ///
    /// The default is `POST`.
    pub method: UploadMethod,
    /// The body that the request sends.
    pub body: UploadBody,
    /// The place of the request in the queue when the fetcher is at its limit.
    pub priority: Priority,
    /// The largest response body, in bytes, for each status.
    ///
    /// A larger `Content-Length` of a 2xx answer fails the upload with
    /// [`Error::UploadInterrupted`]. An answer other than 2xx with a larger
    /// `Content-Length` keeps its status, and its body is
    /// [withheld](Uploaded::body_withheld). If a body grows past the cap
    /// while it streams, the read fails with
    /// [`io::ErrorKind::FileTooLarge`](std::io::ErrorKind::FileTooLarge). The
    /// default is [`UploadRequest::DEFAULT_MAX_RESPONSE`].
    pub max_response: u64,
    /// Headers merged over the headers of the fetcher.
    ///
    /// [`FetchRequest::headers`] states the merge. The fetcher sets no
    /// `Content-Type`, so a `Content-Type` that the server needs goes here.
    pub headers: &'a [(String, String)],
    /// Credentials for `Authorization: Basic`, for this request.
    ///
    /// They replace the credentials of the fetcher.
    ///
    /// Beside [`bearer_token`](UploadRequest::bearer_token), beside an
    /// `Authorization` entry in [`headers`](UploadRequest::headers), or beside
    /// a [`signer`](FetcherOptions::signer) of the fetcher, they fail the
    /// upload before admission with [`Error::Fetch`].
    pub basic_auth: Option<&'a BasicAuth>,
    /// A token for `Authorization: Bearer`, for this request.
    ///
    /// It replaces the credentials of the fetcher.
    ///
    /// Beside [`basic_auth`](UploadRequest::basic_auth), beside an
    /// `Authorization` entry in [`headers`](UploadRequest::headers), or beside
    /// a [`signer`](FetcherOptions::signer) of the fetcher, it fails the
    /// upload before admission with [`Error::Fetch`].
    pub bearer_token: Option<&'a BearerToken>,
    /// The permission for a credential to reach a cleartext origin.
    ///
    /// [`FetchRequest::allow_cleartext_credentials`] states the rule.
    pub allow_cleartext_credentials: bool,
    /// The longest wait for the response head after hyper takes the end of the
    /// body.
    ///
    /// `None` takes [`progress_timeout`](FetcherOptions::progress_timeout).
    pub response_timeout: Option<Duration>,
}

impl std::fmt::Debug for UploadRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let UploadRequest {
            target,
            method,
            body,
            priority,
            max_response,
            headers,
            basic_auth,
            bearer_token,
            allow_cleartext_credentials,
            response_timeout,
        } = self;
        let headers = RedactedHeaders {
            names: || headers.iter().map(|(name, _)| name.as_str()),
        };
        f.debug_struct("UploadRequest")
            .field("target", target)
            .field("method", method)
            .field("body", body)
            .field("priority", priority)
            .field("max_response", max_response)
            .field("headers", &headers)
            .field("basic_auth", basic_auth)
            .field("bearer_token", bearer_token)
            .field("allow_cleartext_credentials", allow_cleartext_credentials)
            .field("response_timeout", response_timeout)
            .finish()
    }
}

impl<'a> UploadRequest<'a> {
    /// The default response cap of a request: 2 MiB.
    pub const DEFAULT_MAX_RESPONSE: u64 = 2 * 1024 * 1024;

    /// Creates a `POST` of `body` to `path` under each mirror.
    ///
    /// The request has normal priority. It carries the headers and the
    /// credentials of the fetcher.
    pub fn path(path: &'a str, body: UploadBody) -> UploadRequest<'a> {
        UploadRequest::for_target(Target::Path(path), body)
    }

    /// Creates a `POST` of `body` to the absolute URL `url`.
    ///
    /// The request has normal priority. It carries the headers and the
    /// credentials of the fetcher.
    pub fn url(url: &'a str, body: UploadBody) -> UploadRequest<'a> {
        UploadRequest::for_target(Target::Url(url), body)
    }

    /// Creates a request for `target` with the default of each other field.
    fn for_target(target: Target<'a>, body: UploadBody) -> UploadRequest<'a> {
        UploadRequest {
            target,
            method: UploadMethod::default(),
            body,
            priority: Priority::default(),
            max_response: UploadRequest::DEFAULT_MAX_RESPONSE,
            headers: &[],
            basic_auth: None,
            bearer_token: None,
            allow_cleartext_credentials: false,
            response_timeout: None,
        }
    }
}

/// The answer to an upload: the status, the headers, and the response body.
///
/// Each final status arrives here, also an unsuccessful one. The caller
/// decides what it means.
///
/// The [`Debug`] output shows the name of each response header, and
/// `<redacted>` in place of its value. A header with several values shows its
/// name once for each value. The URL shows with no userinfo. A query shows as
/// `?<redacted>`, and a fragment shows as `#<redacted>`.
pub struct Uploaded {
    status: StatusCode,
    headers: hyper::HeaderMap,
    url: String,
    body: Body,
    /// `true` if the upload withheld the body of an answer other than 2xx.
    withheld: bool,
}

impl std::fmt::Debug for Uploaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Uploaded {
            status,
            headers,
            url,
            body,
            withheld: _,
        } = self;
        let headers = RedactedHeaders {
            names: || headers.iter().map(|(name, _)| name.as_str()),
        };
        f.debug_struct("Uploaded")
            .field("status", status)
            .field("headers", &headers)
            .field("url", &RedactedUrl::url(url))
            .field("body", body)
            .finish()
    }
}

impl Uploaded {
    /// Returns the status of the response.
    pub fn status(&self) -> u16 {
        self.status.as_u16()
    }

    /// Returns the headers of the response.
    pub fn headers(&self) -> &hyper::HeaderMap {
        &self.headers
    }

    /// Returns the URL that answered.
    ///
    /// After a redirect, this is the URL of the last hop.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns `true` if the upload withheld the body of the response.
    ///
    /// An answer other than 2xx whose head declares a coding, or a
    /// `Content-Length` over [`max_response`](UploadRequest::max_response),
    /// comes with its status and its headers alone. Its body is not read:
    /// [`into_body`](Uploaded::into_body) gives a body that reads as empty,
    /// and the connection closes. [`Fetcher::upload`] states the rule.
    pub fn body_withheld(&self) -> bool {
        self.withheld
    }

    /// Returns the HTTP version of the response.
    pub fn protocol(&self) -> Protocol {
        self.body.protocol()
    }

    /// Returns the response body, capped at
    /// [`max_response`](UploadRequest::max_response).
    ///
    /// The body holds the admission permit until it ends or is dropped. A
    /// [withheld](Uploaded::body_withheld) body reads as empty and holds no
    /// permit.
    pub fn into_body(self) -> Body {
        self.body
    }
}

/// The headers and the capped body of an unsuccessful response to a fetch.
///
/// [`Error::HttpStatus`] carries it if the request set
/// [`max_error_body`](FetchRequest::max_error_body). A caller outside this
/// crate builds one with [`new`](ErrorResponse::new).
///
/// The [`Debug`] output shows the name of each header, and `<redacted>` in
/// place of its value. A header with several values shows its name once for
/// each value. The body shows as its length.
pub struct ErrorResponse {
    headers: hyper::HeaderMap,
    body: Option<Vec<u8>>,
}

impl std::fmt::Debug for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ErrorResponse { headers, body } = self;
        let headers = RedactedHeaders {
            names: || headers.iter().map(|(name, _)| name.as_str()),
        };
        f.debug_struct("ErrorResponse")
            .field("headers", &headers)
            .field("body", &body.as_ref().map(Vec::len))
            .finish()
    }
}

impl ErrorResponse {
    /// Creates a response of `headers` and `body`.
    pub fn new(headers: hyper::HeaderMap, body: Option<Vec<u8>>) -> ErrorResponse {
        ErrorResponse { headers, body }
    }

    /// Returns the headers of the response.
    pub fn headers(&self) -> &hyper::HeaderMap {
        &self.headers
    }

    /// Returns the whole body of the response.
    ///
    /// The body is `None` in these cases:
    ///
    /// - the response declared a `Content-Length` over the cap
    /// - the body grew past the cap while it arrived
    /// - the response declared a coding in `Content-Encoding` or
    ///   `Transfer-Encoding`
    /// - the body failed in transit
    /// - the body did not arrive in full within one
    ///   [`progress_timeout`](FetcherOptions::progress_timeout) from the
    ///   arrival of the response head.
    ///
    /// The fetcher never keeps a part of a body.
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }
}

/// A parsed base URL.
#[derive(Clone, Debug)]
struct Mirror {
    /// The scheme, the host, and the port of the origin.
    origin: Origin,
    /// The `host[:port]` of this mirror, which is the `Host` header of an
    /// HTTP/1.1 request. It holds the authority as the base URL wrote it,
    /// without the default port of the scheme. An IPv6 literal keeps its
    /// brackets.
    authority: HeaderValue,
    /// The `scheme://authority` prefix of each absolute URL for this mirror.
    /// A message names the origin of the mirror with this prefix.
    prefix: String,
    /// The base path, without a trailing slash. It is empty for a mirror at the
    /// root.
    base: String,
}

impl Mirror {
    /// Returns the destination of a request for `path` and `query` under this
    /// mirror. The one string of the destination is the prefix and the base
    /// path of the mirror, then the request path, then `?` and the query if
    /// there is one.
    fn destination(&self, path: &str, query: Option<&str>) -> Destination {
        let path = path.trim_start_matches('/');
        let url = match query {
            None => format!("{}{}/{path}", self.prefix, self.base),
            Some(query) => format!("{}{}/{path}?{query}", self.prefix, self.base),
        };
        Destination {
            origin: self.origin.clone(),
            authority: self.authority.clone(),
            url,
            path_at: self.prefix.len(),
        }
    }
}

/// The place to which one attempt sends its request.
///
/// A URL target resolves its one destination once for each fetch, and each
/// attempt and each retry round uses it. A path target resolves the
/// destination of a mirror at the attempt that uses that mirror.
#[derive(Clone, Debug)]
struct Destination {
    /// The scheme, the host, and the port of the origin. The pool key holds it,
    /// together with the client identity that the connection presents.
    origin: Origin,
    /// The `host[:port]` of the request, which is the `Host` header of an
    /// HTTP/1.1 request. It holds the authority as the caller wrote it, without
    /// the default port of the scheme. An IPv6 literal keeps its brackets.
    authority: HeaderValue,
    /// The absolute URL. It holds the two forms that one request needs: the
    /// whole string, and the tail from `path_at`.
    url: String,
    /// The start of the request path in `url`, which is the length of the
    /// `scheme://authority` prefix.
    path_at: usize,
}

impl Destination {
    /// Returns the absolute URL, which an HTTP/2 request carries and each
    /// message names.
    fn url(&self) -> &str {
        &self.url
    }

    /// Returns the origin-form request target, which an HTTP/1.1 request to an
    /// origin server carries. It is the path, and the query string of a URL
    /// target or of a path target with a query.
    fn target(&self) -> &str {
        &self.url[self.path_at..]
    }

    /// Returns the `scheme://authority` of this destination. A message about
    /// the origin names it with this string.
    fn origin_url(&self) -> &str {
        &self.url[..self.path_at]
    }

    /// Returns the `host[:port]` of this destination as text, which is the
    /// value of the `Host` header in `authority`. An HTTP/2 request carries
    /// the same text in its `:authority`, because it carries the absolute URL.
    fn authority_text(&self) -> &str {
        &self.url[scheme_len(&self.url)..self.path_at]
    }
}

/// The destinations of a fetch, in the order in which it asks them.
///
/// A path target goes to each mirror. So a round walks the mirror list, and
/// builds the destination of a mirror when it asks that mirror. If the first
/// mirror answers, the fetch builds one destination, whatever the length of the
/// list. A URL target names one destination, which the fetch parses once.
#[derive(Debug)]
enum Route<'a> {
    /// Each mirror in order, for this request path and query string. The
    /// path is in the form that the signer of the fetcher gives.
    Mirrors {
        path: Cow<'a, str>,
        query: Option<&'a str>,
    },
    /// The one destination that a URL target names.
    One(Destination),
}

/// A connection endpoint.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Origin {
    tls: bool,
    /// The host that the connect resolves, and the source of the TLS server
    /// name. So an IPv6 literal has no brackets here. An ASCII host is in lower
    /// case, so one origin written in two cases is one pool key and one
    /// connection.
    host: String,
    port: u16,
}

/// The key of the connection pool.
///
/// The key holds an endpoint, the client configuration that opened the
/// connection, and the proxy flag. A connection presents the client
/// certificate for each request that it carries. So the pool never gives a
/// connection with the certificate to a hop that must not present it. It never
/// gives a connection without the certificate to the origin that the route
/// named.
///
/// The identity flag is in this key, and not in [`Origin`]. [`Origin`] states
/// the identity of a network endpoint, and the cleartext and trust-anchor
/// checks read it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PoolKey {
    origin: Origin,
    /// `true` if the connection presents the configured client certificate.
    identity: bool,
    /// `true` if the connection goes to a proxy and carries absolute-form
    /// requests.
    ///
    /// The pool keeps such a connection under the proxy endpoint. A cleartext
    /// origin of the same host and port has the same endpoint, and the two
    /// carry different request forms. This flag keeps the pool from giving one
    /// to a request of the other.
    proxied: bool,
}

/// One proxy that the fetcher connects through, resolved from a proxy URL.
#[derive(Debug)]
struct ProxyEndpoint {
    /// The endpoint of the connection. The fetcher reaches a proxy over
    /// cleartext, so this origin is never TLS.
    endpoint: Origin,
    /// The `Proxy-Authorization` value from the userinfo of the proxy URL, if
    /// the URL holds userinfo.
    credential: Option<HeaderValue>,
    /// The name of this proxy in a message, which is its URL without the
    /// userinfo.
    named: String,
}

/// One `no_proxy` entry: a host text, and the port of the entry if it names
/// one.
#[derive(Debug)]
struct Exemption {
    /// The host that the entry names, in ASCII lower case, without one leading
    /// `.`. It is never empty: an entry that names no host exempts nothing and
    /// gets no place in a list.
    host: String,
    /// The port that the entry matches, if it names a port that the fetcher
    /// can read.
    port: Option<u16>,
}

impl Exemption {
    /// Returns `true` if this entry exempts `origin`.
    ///
    /// The comparison is byte by byte, with ASCII case ignored. So a host that
    /// is not ASCII needs no slice at a character boundary, which can panic.
    fn matches(&self, origin: &Origin) -> bool {
        if self.port.is_some_and(|port| port != origin.port) {
            return false;
        }
        let host = origin.host.as_bytes();
        let entry = self.host.as_bytes();
        if host.eq_ignore_ascii_case(entry) {
            return true;
        }
        // The `.` before the entry states that the host is a name under the
        // entry. `notexample.com` is no part of `example.com`.
        host.len() > entry.len()
            && host[host.len() - entry.len() - 1] == b'.'
            && host[host.len() - entry.len()..].eq_ignore_ascii_case(entry)
    }
}

/// The proxy of each scheme, and the exemptions from both.
#[derive(Debug, Default)]
struct Proxies {
    /// The proxy of a cleartext origin.
    http: Option<Arc<ProxyEndpoint>>,
    /// The proxy of a TLS origin. If one proxy URL serves both schemes, this
    /// field and `http` hold one endpoint.
    https: Option<Arc<ProxyEndpoint>>,
    /// `true` if `no_proxy` lists `*`, which exempts all hosts.
    exempt_all: bool,
    /// The hosts that `no_proxy` lists.
    exempt: Vec<Exemption>,
}

impl Proxies {
    /// Returns the way to reach a hop at `origin`. This reads the resolved
    /// state and allocates nothing, so the decision costs a fetch one walk of
    /// the exemption list.
    fn via(&self, origin: &Origin) -> Via<'_> {
        let proxy = if origin.tls { &self.https } else { &self.http };
        let Some(proxy) = proxy.as_deref() else {
            return Via::Direct;
        };
        if self.exempt_all || self.exempt.iter().any(|entry| entry.matches(origin)) {
            return Via::Direct;
        }
        if origin.tls {
            Via::Tunnel(proxy)
        } else {
            Via::Absolute(proxy)
        }
    }
}

/// The way that one hop reaches its origin.
#[derive(Clone, Copy, Debug)]
enum Via<'a> {
    /// A direct connection to the origin.
    Direct,
    /// A connection to the proxy that carries absolute-form requests. A
    /// cleartext origin behind a proxy uses this way.
    Absolute(&'a ProxyEndpoint),
    /// A `CONNECT` tunnel through the proxy. A TLS origin behind a proxy uses
    /// this way.
    Tunnel(&'a ProxyEndpoint),
}

/// The body of a request: no body for a fetch and for a `CONNECT`, or the
/// reading end of an upload body. One type serves both, so a fetch and an
/// upload share a pooled connection.
enum RequestBody {
    /// No body: a fetch, a `CONNECT`.
    Empty,
    /// The body of an upload.
    Upload(BodyEnd),
}

impl hyper::body::Body for RequestBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Self::Error>>> {
        match self.get_mut() {
            RequestBody::Empty => Poll::Ready(None),
            RequestBody::Upload(end) => end.poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            RequestBody::Empty => true,
            RequestBody::Upload(end) => end.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            RequestBody::Empty => SizeHint::with_exact(0),
            RequestBody::Upload(end) => match end.exchange.exact {
                Some(length) => SizeHint::with_exact(length),
                None => SizeHint::default(),
            },
        }
    }
}

/// The state that one upload body shares between its writer, the reading end
/// that hyper polls, and the upload that waits for the response.
#[derive(Default)]
struct Exchange {
    slot: Mutex<Slot>,
    /// The length of a body given whole, which the request declares. This
    /// field is here, and not in the reading end, so the body of a fetch stays
    /// one pointer wide.
    exact: Option<u64>,
}

/// The one slot through which an upload body passes its frames, and the
/// progress of each party.
#[derive(Default)]
struct Slot {
    /// A frame that the writer handed over and hyper did not take yet. For a
    /// body given whole, this is the remaining part of the body, which hyper
    /// takes in frames of [`UPLOAD_FRAME`].
    frame: Option<Bytes>,
    /// `true` if the writer closed the body, so no frame follows `frame`.
    closed: bool,
    /// The reason for the failure of the body. The writer was dropped before
    /// it closed the body, a frame waited past the stall window, or the
    /// response ended before the body.
    aborted: Option<String>,
    /// `true` if the reading end is dropped, which ends the upload.
    gone: bool,
    /// `true` if the reading end gave hyper the end of the body.
    ended: bool,
    /// `true` if hyper polled the body for a frame.
    polled: bool,
    /// `true` if the body was at its end at the hand-over of the request, so
    /// the request declares a length of zero.
    empty: bool,
    /// The stall window, which runs from the hand-over of the request.
    stall: Option<Stall>,
    /// The writer, which waits for the slot to empty or for the end.
    writer: Option<Waker>,
    /// hyper, which waits for a frame.
    reader: Option<Waker>,
    /// The upload, which waits for the end of the body or for its failure.
    upload: Option<Waker>,
}

/// The stall window of an upload body: the longest time that a frame can wait
/// in the slot for hyper to take it.
#[derive(Clone, Copy)]
struct Stall {
    window: Duration,
    /// The start of the wait of the frame in the slot. This is the latest of
    /// three instants: the frame got its place, hyper took the frame before it
    /// from a body given whole, or the window started.
    since: Instant,
}

impl Slot {
    /// Records that the body is at its end, and gives back the wakers of the
    /// two parties that wait for it.
    fn end(&mut self) -> [Option<Waker>; 2] {
        self.ended = true;
        [self.writer.take(), self.upload.take()]
    }

    /// Fails the body for `reason`, and gives back the wakers of the parties
    /// that read the failure. If the body failed before, the first reason
    /// stays.
    fn abort(&mut self, reason: impl FnOnce() -> String) -> [Option<Waker>; 3] {
        self.aborted.get_or_insert_with(reason);
        [self.reader.take(), self.upload.take(), self.writer.take()]
    }

    /// Returns `true` if the body is at its end: closed, with no frame left to
    /// take and no failure.
    fn at_end(&self) -> bool {
        self.closed && self.frame.is_none() && self.aborted.is_none()
    }

    /// Returns the instant at which the frame in the slot waited the whole
    /// stall window. It is `None` if no frame waits, no window runs, or the
    /// body failed.
    fn stall_end(&self) -> Option<Instant> {
        let stall = self.stall?;
        if self.frame.is_none() || self.aborted.is_some() {
            return None;
        }
        stall.since.checked_add(stall.window)
    }

    /// Starts the wait of the frame in the slot again, from now.
    fn restart_stall(&mut self) {
        if let Some(stall) = &mut self.stall {
            stall.since = Instant::now();
        }
    }
}

/// The state of the body that the upload sees while it waits for the response.
enum Watch {
    /// The body still streams. A body given whole has no writer, so the upload
    /// runs its stall window, which ends at the given instant.
    Streaming(Option<Instant>),
    /// hyper took the end of the body.
    Ended,
    /// The body failed, for the reason given.
    Aborted(String),
}

impl Exchange {
    /// Creates the exchange of a body given whole. The bytes are the frame that
    /// hyper takes in parts, and the body is closed. An empty body holds no
    /// frame, so it is at its end before hyper polls it.
    fn whole(bytes: &Bytes) -> Exchange {
        Exchange {
            slot: Mutex::new(Slot {
                frame: (!bytes.is_empty()).then(|| bytes.clone()),
                closed: true,
                ..Slot::default()
            }),
            exact: Some(bytes.len() as u64),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Slot> {
        self.slot.lock().expect("upload body mutex")
    }

    /// Returns the reason for the failure of the body, if the body failed.
    fn aborted(&self) -> Option<String> {
        self.lock().aborted.clone()
    }

    /// Hands the body to hyper. This starts the stall window of `stall` from
    /// now, and returns `true` if the body is at its end, which the request then
    /// declares. The function does not hand over a failed body, and returns
    /// the reason for the failure as the error.
    fn hand_over(&self, stall: Duration) -> std::result::Result<bool, String> {
        let mut slot = self.lock();
        if let Some(reason) = &slot.aborted {
            return Err(reason.clone());
        }
        slot.stall = Some(Stall {
            window: stall,
            since: Instant::now(),
        });
        slot.empty = slot.at_end();
        let empty = slot.empty;
        let writer = slot.writer.take();
        drop(slot);
        wake(writer);
        Ok(empty)
    }

    /// Returns `true` if hyper took the end of the body, with no failure.
    fn has_ended(&self) -> bool {
        let slot = self.lock();
        slot.ended && slot.aborted.is_none()
    }

    /// Takes the body back from hyper, which gave the request back unwritten.
    /// The stall window stops until the next hand-over.
    fn withdraw(&self) {
        let mut slot = self.lock();
        slot.stall = None;
        slot.empty = false;
    }

    /// Fails the body if the frame in the slot waited the whole stall window,
    /// and returns the reason. If the frame still has time, or no frame waits,
    /// the error holds the instant at which the wait ends.
    fn check_stall(&self) -> std::result::Result<String, Option<Instant>> {
        let mut slot = self.lock();
        let end = slot.stall_end();
        let (Some(end), Some(stall)) = (end, slot.stall) else {
            return Err(None);
        };
        if Instant::now() < end {
            return Err(Some(end));
        }
        let message = format!("the upload body was not taken for {:?}", stall.window);
        let wakers = slot.abort(|| message.clone());
        drop(slot);
        wakers.into_iter().for_each(wake);
        Ok(message)
    }

    /// Fails a body that did not end, because its response ended or was
    /// dropped. hyper stops the body and closes the connection, and the writer
    /// gets a broken pipe.
    fn cut(&self) {
        let mut slot = self.lock();
        if slot.ended {
            return;
        }
        let wakers = slot.abort(|| "the response to the upload ended before its body".into());
        drop(slot);
        wakers.into_iter().for_each(wake);
    }

    /// Returns the state of the body, and registers the upload for a wake when
    /// the state changes.
    fn watch(&self, cx: &mut Context<'_>) -> Watch {
        let mut slot = self.lock();
        if let Some(reason) = &slot.aborted {
            return Watch::Aborted(reason.clone());
        }
        if slot.ended {
            return Watch::Ended;
        }
        park(&mut slot.upload, cx);
        Watch::Streaming(self.exact.and(slot.stall_end()))
    }
}

/// Keeps the waker of `cx` in `waker`, unless the held waker wakes the same
/// task.
fn park(waker: &mut Option<Waker>, cx: &Context<'_>) {
    if !waker
        .as_ref()
        .is_some_and(|held| held.will_wake(cx.waker()))
    {
        *waker = Some(cx.waker().clone());
    }
}

/// Wakes `waker`, if a party left one.
fn wake(waker: Option<Waker>) {
    if let Some(waker) = waker {
        waker.wake();
    }
}

/// Polls a timer toward `end`, and is ready after `end`.
///
/// The function arms the timer once, for the remaining time. If the start of a
/// window moves later, as the stall window does with each frame, `end` moves
/// later and the timer stays. If the timer fires early, the function arms it
/// again for the remaining time.
fn poll_until(timer: &mut Option<rt::Deadline>, cx: &mut Context<'_>, end: Instant) -> Poll<()> {
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            *timer = None;
            return Poll::Ready(());
        }
        let deadline = timer.get_or_insert_with(|| rt::Deadline::new(left));
        if deadline.poll_expired(cx).is_pending() {
            return Poll::Pending;
        }
        *timer = None;
    }
}

/// The reading end of an upload body, which hyper polls for frames.
///
/// The reading end takes a frame out of the slot as it is. So the bytes of a
/// frame get at most one copy, from the buffer of the caller into the buffer of
/// the writer. A body given whole goes in frames of [`UPLOAD_FRAME`] cut from
/// its bytes, with no copy. A drop of the end wakes the writer, and each later
/// write fails.
struct BodyEnd {
    exchange: Arc<Exchange>,
}

impl BodyEnd {
    /// Creates the reading end of a body given whole.
    fn whole(bytes: &Bytes) -> BodyEnd {
        BodyEnd {
            exchange: Arc::new(Exchange::whole(bytes)),
        }
    }

    /// Polls for the next frame. A failed body fails the poll. So hyper ends
    /// the request unfinished, and does not send a truncated body as a whole
    /// body.
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<Option<std::io::Result<Frame<Bytes>>>> {
        let mut slot = self.exchange.lock();
        slot.polled = true;
        if let Some(reason) = &slot.aborted {
            return Poll::Ready(Some(Err(std::io::Error::other(reason.clone()))));
        }
        // hyper takes a body given whole in frames. So the end follows the last
        // frame, and the stall window runs over each frame.
        if let Some(held) = &mut slot.frame
            && held.len() > UPLOAD_FRAME
        {
            let frame = held.split_to(UPLOAD_FRAME);
            slot.restart_stall();
            return Poll::Ready(Some(Ok(Frame::data(frame))));
        }
        if let Some(frame) = slot.frame.take() {
            // The last frame of a closed body is also its end. hyper reads the
            // end from `is_end_stream`, and does not poll for it.
            let wakers = if slot.closed {
                slot.end()
            } else {
                [slot.writer.take(), None]
            };
            drop(slot);
            wakers.into_iter().for_each(wake);
            return Poll::Ready(Some(Ok(Frame::data(frame))));
        }
        if slot.closed {
            let wakers = slot.end();
            drop(slot);
            wakers.into_iter().for_each(wake);
            return Poll::Ready(None);
        }
        park(&mut slot.reader, cx);
        Poll::Pending
    }

    /// Returns `true` if the body has no more frames. hyper asks before it
    /// polls, and never polls a body at its end. So this answer records the
    /// end, as a poll that finds the end does.
    ///
    /// hyper frames the request from the first answer. Over HTTP/1.1, a
    /// request at its end at that time carries no length of its own. So before
    /// the first poll, a body is at its end only if the request declared a
    /// length of zero at the hand-over. If a body reached its end after the
    /// hand-over, hyper frames it as a stream, and the stream ends empty.
    fn is_end_stream(&self) -> bool {
        let mut slot = self.exchange.lock();
        if slot.ended {
            return true;
        }
        if !slot.at_end() || !(slot.polled || slot.empty) {
            return false;
        }
        let wakers = slot.end();
        drop(slot);
        wakers.into_iter().for_each(wake);
        true
    }
}

impl Drop for BodyEnd {
    fn drop(&mut self) {
        let mut slot = self.exchange.lock();
        slot.gone = true;
        let writer = slot.writer.take();
        drop(slot);
        wake(writer);
    }
}

/// The request body of an upload, which its response holds. If the response
/// ends or is dropped before the request body ends, the request body fails. So
/// hyper stops the body and closes the connection.
struct RequestEnd {
    exchange: Arc<Exchange>,
}

impl Drop for RequestEnd {
    fn drop(&mut self) {
        self.exchange.cut();
    }
}

type H1Sender = hyper::client::conn::http1::SendRequest<RequestBody>;
type H2Sender = hyper::client::conn::http2::SendRequest<RequestBody>;

/// A connection ready to carry one request.
enum Sender {
    /// An HTTP/1.1 connection, which carries one request at a time. It goes
    /// back to the pool when its response body ends.
    H1(H1Sender),
    /// A handle on a pooled HTTP/2 connection, which multiplexes requests.
    H2(H2Sender),
}

/// The connections pooled under one [`PoolKey`].
#[derive(Default)]
struct PoolEntry {
    /// The HTTP/2 connection of the origin, if one is open.
    h2: Option<H2Sender>,
    /// The idle HTTP/1.1 connections. The connection that became idle last is
    /// at the end.
    h1: Vec<IdleH1>,
}

/// An idle HTTP/1.1 connection in the pool, and the instant at which it became
/// idle.
struct IdleH1 {
    sender: H1Sender,
    since: Instant,
}

/// The shared state of a fetcher. A [`Fetcher`] is a handle on this state.
struct Inner {
    mirrors: Vec<Mirror>,
    headers: Vec<(HeaderName, HeaderValue)>,
    tls: ClientConfigs,
    /// `true` if a handshake has the anchors to verify the peer.
    ///
    /// A store with no anchor gets here only for a fetcher with all mirrors in
    /// cleartext, which opens no handshake that reads the store. The fetcher
    /// then refuses a TLS destination. A bypass variant of [`TrustRoots`] reads
    /// no store and sets `true`, because its handshake reads no anchor and
    /// completes.
    has_trust_anchors: bool,
    /// `true` if a client certificate is configured, so the two client
    /// configurations differ. If none is configured, each connection opens
    /// over one configuration, and the pool holds one entry for each origin.
    client_identity: bool,
    /// The proxy of each scheme, resolved at construction.
    proxies: Proxies,
    /// `true` if a credential can reach a cleartext destination. A fetch and
    /// an upload then skip the cleartext check.
    allow_cleartext_credentials: bool,
    /// The signer of each attempt at the origin that the route names.
    signer: Option<Arc<dyn RequestSigner>>,
    max_retries: u32,
    max_redirects: u32,
    connect_timeout: Duration,
    progress_timeout: Duration,
    low_speed: Option<LowSpeed>,
    fetch_timeout: Option<Duration>,
    /// The number of requests that the gate admits at one time, at least 1.
    max_outstanding: usize,
    gate: Arc<Gate>,
    h2_connection_window: u32,
    pool: Mutex<HashMap<PoolKey, PoolEntry>>,
}

/// Returns the HTTP/2 flow-control window of the connection for a fetcher that
/// admits `max_outstanding` requests: one stream window for each request.
///
/// A receiver credits a window back when the caller reads the data. So a
/// parked stream, whose body the caller received and did not read yet, holds
/// its own credit. The connection window is the sum of the stream windows, so
/// that credit belongs to the parked stream alone. Each other open stream
/// still has a full window.
///
/// For example, the HTTP pull of `ostrya` parks content bodies while they wait
/// for a write permit. The metadata object that its scan waits for uses the
/// same connection.
///
/// The cost is the received and unread data that one connection can hold,
/// which is this window. At the default limit of 8, it is 16 MiB.
fn h2_connection_window(max_outstanding: usize) -> u32 {
    u32::try_from(max_outstanding)
        .unwrap_or(u32::MAX)
        .saturating_mul(H2_STREAM_WINDOW)
        .min(H2_MAX_WINDOW)
}

/// A failed attempt, and the retry class of the failure.
enum Failure {
    /// A transport failure, or a status that a later attempt can avoid.
    Retry(Error),
    /// A definitive answer, which a retry gets again.
    Fatal(Error),
    /// A failure of the request itself, which no destination and no round
    /// avoids. The request ends with it.
    Final(Error),
}

impl Failure {
    /// Returns the error of the failure, of any kind.
    fn into_error(self) -> Error {
        match self {
            Failure::Retry(e) | Failure::Fatal(e) | Failure::Final(e) => e,
        }
    }

    /// Returns the cap of the error body that `keep` asks for in the class of
    /// this failure, or `None` if the fetch keeps no response of this class.
    fn kept_cap(&self, keep: Option<Keep>) -> Option<u64> {
        let keep = keep?;
        match self {
            Failure::Retry(_) if keep.retryable => Some(keep.cap),
            Failure::Fatal(_) if keep.definitive => Some(keep.cap),
            _ => None,
        }
    }

    /// Puts `kept` into the [`Error::HttpStatus`] of this failure. A failure
    /// of another error stays as it is.
    fn with_response(mut self, kept: ErrorResponse) -> Failure {
        if let Failure::Retry(Error::HttpStatus { response, .. })
        | Failure::Fatal(Error::HttpStatus { response, .. }) = &mut self
        {
            *response = Some(Box::new(kept));
        }
        self
    }
}

/// The unsuccessful responses that one attempt of a fetch keeps.
///
/// A fetch reports one failure. So an attempt reads the body of a failure
/// only if that failure can become the reported one. The flags follow the
/// failure order of [`Fetcher::fetch`].
#[derive(Clone, Copy)]
struct Keep {
    /// The largest body to keep: [`FetchRequest::max_error_body`].
    cap: u64,
    /// `true` if no failure is reported yet, so a retryable failure becomes
    /// the reported one.
    retryable: bool,
    /// `true` if no definitive answer is reported yet, so a definitive answer
    /// becomes the reported one.
    definitive: bool,
}

/// A failed upload attempt, and the send state of the request.
enum UploadFailure {
    /// No part of the request reached hyper, so the round continues as for a
    /// fetch.
    Unsent(Failure),
    /// hyper took the request, so the upload ends with
    /// [`Error::UploadInterrupted`] of this URL and message. A sent request has
    /// no other error, and [`Error::is_unsent`] reads this fact.
    Sent { url: String, message: String },
}

/// The parts that each attempt of one upload sends, set before admission.
struct UploadPlan<'a> {
    method: Method,
    headers: &'a [(HeaderName, HeaderValue)],
    /// The bytes of a body given whole, which a followed redirect sends again.
    /// A streamed body has none, so the upload follows no redirect of it.
    bytes: Option<Bytes>,
    /// The SHA-256 of `bytes` that the caller gave, which the signer of each
    /// attempt and each hop gets.
    sha256: Option<[u8; 32]>,
    max_response: u64,
    response_timeout: Duration,
}

/// The result of a request after hyper took it.
enum Answer<T> {
    /// The send resolved, with the response head or the error of hyper.
    Sent(T),
    /// The writer failed the body before the response head arrived.
    Aborted(String),
    /// The body ended, and no response head followed within the window.
    Silent(Duration),
}

/// The response of one upload hop, its protocol, and the body that the request
/// sent. It also holds the HTTP/1.1 connection, which goes back to the pool
/// when the response body ends.
type UploadResponse = (Response<Incoming>, Protocol, RequestEnd, Option<H1Sender>);

/// An async HTTP client for one remote.
///
/// A fetcher holds the mirrors, the headers, the credentials, and the TLS
/// configuration of one remote. It serves a [`Target::Url`] from the origin of
/// that URL. A clone of a `Fetcher` is another handle on the same connection
/// pool and the same admission limit. The clone has the counters of received
/// body bytes of the handle. [`counted`](Fetcher::counted) gives a handle with
/// more counters.
///
/// # Connections
///
/// The TLS handshake selects the protocol: ALPN offers `h2` and `http/1.1`,
/// and the fetcher uses the choice of the server. Over cleartext, the fetcher
/// uses HTTP/1.1. The pool keeps one HTTP/2 connection for each origin, which
/// carries concurrent requests. The pool also keeps HTTP/1.1 connections, and
/// the fetcher uses one again after the previous body is read to the end.
///
/// The pool key holds three terms:
///
/// - the endpoint of the connection
/// - `true` if the connection presents the configured client certificate
/// - `true` if the connection goes to a proxy and carries absolute-form
///   requests.
///
/// The endpoint is the origin for a direct connection and for a tunnel,
/// because the TLS of a tunnel reaches the origin. For a proxied cleartext
/// connection, the endpoint is the proxy. So a URL target shares a connection
/// with a mirror at the same origin. One proxy connection carries requests for
/// all cleartext origins.
///
/// An unsuccessful status, or a `Content-Length` over the cap of the request,
/// ends an attempt with a response body in flight. If the declared length is
/// 64 KiB or less, the fetcher reads the body to the end. The HTTP/1.1
/// connection then goes back to the pool. If the declared length is larger, or
/// if there is none, the fetcher closes the connection.
///
/// A fetch with [`FetchRequest::max_error_body`] reads the body of the
/// unsuccessful response that it reports, up to that cap, with or without a
/// declared length. If the body ends within the cap, the HTTP/1.1 connection
/// goes back to the pool. If it grows past the cap, the fetcher closes the
/// connection. [`Fetcher::fetch`] states the rule in "Error responses".
///
/// A 404 is the usual answer for an object that the remote does not hold. So
/// this rule saves a connection setup for each absent object.
///
/// All such reads of one attempt share one
/// [`progress_timeout`](FetcherOptions::progress_timeout)
/// window, whatever the number of hops. A peer can declare a short body on
/// each hop and send fewer bytes. Such a peer uses the window once, and the
/// later reads close their connections and do not wait.
#[derive(Clone)]
pub struct Fetcher {
    inner: Arc<Inner>,
    /// The counters that get the bytes of each response body of a request of
    /// this handle.
    received: Arc<[Arc<AtomicU64>]>,
}

impl std::fmt::Debug for Fetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetcher")
            .field("mirrors", &self.inner.mirrors)
            .finish_non_exhaustive()
    }
}

impl Fetcher {
    /// Creates a fetcher from `options`.
    ///
    /// If the mirror list is empty, the fetcher serves [`Target::Url`] requests
    /// alone.
    ///
    /// The fetcher has no counters of received body bytes.
    /// [`counted`](Fetcher::counted) gives a handle that has counters.
    ///
    /// The function is async, because [`TrustRoots::System`], the default,
    /// reads the host trust store on the blocking pool. An encrypted client key
    /// runs a key derivation function, also on the blocking pool. Under
    /// [`TrustRoots::Pem`] with no encrypted client key, all work is in memory,
    /// and the function never yields.
    ///
    /// # Trust store
    ///
    /// The function reads the system store if a fetch can open a handshake.
    /// That is the case if one or more mirrors are `https`. It is also the case
    /// if the mirror list is empty, because a request can then name an `https`
    /// URL. It is also the case if
    /// [`max_redirects`](FetcherOptions::max_redirects) is more than zero,
    /// because a redirect can go to an `https` URL.
    ///
    /// A fetcher with all mirrors `http` that follows no redirect reads no
    /// store and holds no trust anchor. If a request of that fetcher names an
    /// `https` URL of its own, the fetch fails before admission and names the
    /// origin. A host without a CA bundle still reaches a cleartext remote.
    ///
    /// Under either bypass variant of [`TrustRoots`], the function reads no
    /// store, so an empty host store fails no fetcher. With no encrypted client
    /// key, the function then never yields.
    ///
    /// # Errors
    ///
    /// - [`Error::Fetch`] if a [`low_speed`](FetcherOptions::low_speed) rule
    ///   holds a zero.
    /// - [`Error::Fetch`] if a mirror URL is not a valid absolute URL, has no
    ///   usable host, or holds a query string or userinfo.
    /// - [`Error::Fetch`] if a mirror URL names a port that is not a number
    ///   from 0 to 65535.
    /// - [`Error::Unsupported`] if the scheme of a mirror URL is neither `http`
    ///   nor `https`.
    /// - [`Error::Fetch`] if a header name or value is invalid, or if a header
    ///   is `Host` or a header that the connection layer sets.
    /// - [`Error::Fetch`] if a mirror is cleartext `http`, the options hold a
    ///   credential, and
    ///   [`allow_cleartext_credentials`](FetcherOptions::allow_cleartext_credentials)
    ///   is `false`. The credentials are
    ///   [`basic_auth`](FetcherOptions::basic_auth),
    ///   [`bearer_token`](FetcherOptions::bearer_token),
    ///   [`signer`](FetcherOptions::signer), and an `Authorization`,
    ///   `Proxy-Authorization`, or `Cookie` header.
    /// - [`Error::Fetch`] if two of these are set:
    ///   [`basic_auth`](FetcherOptions::basic_auth),
    ///   [`bearer_token`](FetcherOptions::bearer_token),
    ///   [`signer`](FetcherOptions::signer), and an `Authorization` header.
    /// - [`Error::Fetch`] if [`basic_auth`](FetcherOptions::basic_auth) does
    ///   not give a valid header value, or if
    ///   [`bearer_token`](FetcherOptions::bearer_token) does not have the
    ///   token68 syntax.
    /// - [`Error::Unsupported`] if a proxy URL is not `http://host[:port]`,
    ///   from the options or from the environment.
    /// - [`Error::Unsupported`] if a proxy variable has
    ///   [white space](Proxy#white-space) around its value.
    /// - [`Error::Fetch`] if the TLS material does not parse or the TLS setup
    ///   fails: a trust anchor, the client certificate, or the client key.
    ///   [`ClientIdentity::key_passphrase`] states the refusals of a client
    ///   key.
    /// - [`Error::Fetch`] if the system trust store holds no certificate, and
    ///   one or more mirrors are `https` or the mirror list is empty.
    pub async fn new(options: FetcherOptions) -> Result<Fetcher> {
        // A limit of zero or a time of zero measures nothing. No rate is under
        // a zero limit, and each transfer fails a zero time immediately.
        if let Some(low) = options.low_speed
            && (low.limit == 0 || low.time.is_zero())
        {
            return Err(Error::Fetch(format!(
                "low-speed limit {} bytes per second over {:?}: neither may be zero",
                low.limit, low.time
            )));
        }
        let mirrors = options
            .mirrors
            .iter()
            .map(|url| parse_mirror(url))
            .collect::<Result<Vec<_>>>()?;
        // The fetcher sends a credential with each request to each mirror. So
        // one cleartext entry in the list puts the credential on the wire in
        // the clear, and the fetcher refuses such a configuration, unless the
        // caller permits it. A fetch that withholds the credential gets a 401
        // that does not state why.
        let cleartext = if options.allow_cleartext_credentials {
            None
        } else {
            options
                .mirrors
                .iter()
                .zip(&mirrors)
                .find(|(_, mirror)| !mirror.origin.tls)
                .map(|(url, _)| url.as_str())
        };
        let credential = match (&options.basic_auth, &options.bearer_token) {
            (Some(_), Some(_)) => return Err(Error::Fetch(BASIC_AND_BEARER.into())),
            (Some(_), None) => Some("basic-auth credentials"),
            (None, Some(_)) => Some("the bearer token"),
            (None, None) if options.signer.is_some() => Some("the signature of the request signer"),
            (None, None) => None,
        };
        if options.signer.is_some() {
            refuse_beside_signer(
                &options.headers,
                options.basic_auth.is_some(),
                options.bearer_token.is_some(),
            )?;
        }
        if let Some(credential) = credential
            && let Some(url) = cleartext
        {
            return Err(Error::Fetch(format!(
                "{credential} would reach the http mirror {url} in the clear: \
                 use https mirrors, drop the credentials, or set \
                 FetcherOptions::allow_cleartext_credentials"
            )));
        }
        let mut headers = vec![
            (
                hyper::header::USER_AGENT,
                HeaderValue::from_static(USER_AGENT),
            ),
            (
                hyper::header::ACCEPT_ENCODING,
                HeaderValue::from_static(IDENTITY),
            ),
        ];
        // The length of the part of the list that the fetcher sets. A
        // configured header of one of those names replaces that entry, as a
        // request header replaces a fetcher header of the same name. Without
        // this rule, both go on the wire and give one question two answers.
        // After this part, the list holds configured headers, and two entries
        // of one name both go on the wire.
        let mut base = headers.len();
        for (name, value) in &options.headers {
            let name = HeaderName::try_from(name.as_str())
                .map_err(|_| Error::Fetch(format!("invalid header name: {name}")))?;
            if name == hyper::header::HOST {
                return Err(Error::Fetch(HOST_COMES_FROM_THE_URL.into()));
            }
            if is_connection_header(&name) {
                return Err(connection_header_refused(&name));
            }
            if name == hyper::header::AUTHORIZATION && options.basic_auth.is_some() {
                return Err(Error::Fetch(AMBIGUOUS_AUTHORIZATION.into()));
            }
            if name == hyper::header::AUTHORIZATION && options.bearer_token.is_some() {
                return Err(Error::Fetch(AMBIGUOUS_BEARER.into()));
            }
            if is_credential(&name)
                && let Some(url) = cleartext
            {
                return Err(Error::Fetch(format!(
                    "the {name} header carries credentials, which the http mirror {url} \
                     would receive in the clear: use https mirrors, drop the header, or set \
                     FetcherOptions::allow_cleartext_credentials"
                )));
            }
            let mut value = HeaderValue::try_from(value.as_str())
                .map_err(|_| Error::Fetch(format!("invalid value for header {name}")))?;
            value.set_sensitive(is_credential(&name));
            if let Some(at) = headers[..base].iter().position(|(held, _)| *held == name) {
                headers.remove(at);
                base -= 1;
            }
            headers.push((name, value));
        }
        if let Some(auth) = &options.basic_auth {
            headers.push((hyper::header::AUTHORIZATION, basic_auth_value(auth)?));
        }
        if let Some(token) = &options.bearer_token {
            headers.push((hyper::header::AUTHORIZATION, bearer_value(token)?));
        }
        let proxies = resolve_proxy(&options.proxy)?;
        let max_outstanding = options.max_outstanding.max(1);
        // A fetcher with no mirror serves the URLs of its requests, and each
        // of them can be `https`. So it must hold trust anchors, and an empty
        // system store fails it as for an `https` mirror.
        let https = mirrors.is_empty() || mirrors.iter().any(|mirror| mirror.origin.tls);
        // A redirect can go from a cleartext mirror to a TLS origin. So the
        // fetcher also reads the system store if it follows redirects. If not,
        // a fetch reaches a TLS origin only through a URL target of its own. A
        // fetcher with no anchor refuses that target before admission.
        let reaches_tls = https || options.max_redirects > 0;
        let tls = client_config(&options.tls, options.http2, https, reaches_tls).await?;
        Ok(Fetcher {
            inner: Arc::new(Inner {
                mirrors,
                headers,
                has_trust_anchors: tls.has_trust_anchors,
                client_identity: options.tls.client_identity.is_some(),
                proxies,
                tls,
                allow_cleartext_credentials: options.allow_cleartext_credentials,
                signer: options.signer,
                max_retries: options.max_retries,
                max_redirects: options.max_redirects,
                connect_timeout: options.connect_timeout,
                progress_timeout: options.progress_timeout,
                low_speed: options.low_speed,
                fetch_timeout: options.fetch_timeout,
                max_outstanding,
                gate: Arc::new(Gate::new(max_outstanding)),
                h2_connection_window: h2_connection_window(max_outstanding),
                pool: Mutex::new(HashMap::new()),
            }),
            received: Arc::new([]),
        })
    }

    /// Returns a handle on this fetcher that adds counters of received body
    /// bytes.
    ///
    /// The new handle shares the configuration, the connection pool, and the
    /// admission limit of this handle. It has the counters of this handle and
    /// the counters of `received`. A clone of the new handle has the same
    /// counters.
    ///
    /// Each response body of a request of the new handle adds the bytes that it
    /// takes from the connection to each of these counters. This includes the
    /// bytes of a body before it fails, the body of a [`Refetch`], a body that
    /// the caller drops before its end, and the response body of an upload. A
    /// request does not count a response that it does not give to the caller:
    /// a redirect, an unsuccessful status of a fetch, or a refused response.
    ///
    /// The counters of this handle do not change. A request of this handle adds
    /// to the counters of this handle alone. Each data frame costs one relaxed
    /// atomic add for each counter. A counter that the new handle has two times
    /// gets the bytes two times.
    pub fn counted(&self, received: Vec<Arc<AtomicU64>>) -> Fetcher {
        Fetcher {
            inner: Arc::clone(&self.inner),
            received: self.received.iter().cloned().chain(received).collect(),
        }
    }

    /// Returns the number of requests that the fetcher admits at one time.
    ///
    /// The number is [`max_outstanding`](FetcherOptions::max_outstanding) of
    /// the options, and at least 1. All handles on one fetcher share this
    /// limit.
    pub fn max_outstanding(&self) -> usize {
        self.inner.max_outstanding
    }

    /// Sends `request` to each destination in turn and returns the response.
    ///
    /// # Retries
    ///
    /// A path target goes to each mirror, in the mirror order. The fetch
    /// resolves the destination of a mirror at the attempt that uses it. A URL
    /// target has the one destination that the URL names.
    ///
    /// - The fetch tries each destination in order before it retries.
    /// - Transport failures and the statuses 408, 429, and 5xx are retryable.
    ///   If one or more destinations of a round fail that way, the fetch
    ///   repeats the round, up to [`max_retries`](FetcherOptions::max_retries)
    ///   times. The delay before a repeat starts at 250ms, doubles each time,
    ///   and stops at two seconds. A repeated round asks only the destinations
    ///   with a retryable failure.
    /// - Each other unsuccessful status is definitive. The fetch does not ask
    ///   that destination again, because its answer is the same in each round.
    /// - The expiry of [`connect_timeout`](FetcherOptions::connect_timeout),
    ///   [`progress_timeout`](FetcherOptions::progress_timeout), or
    ///   [`low_speed`](FetcherOptions::low_speed) is a transport failure. The
    ///   fetch reports the deadline that expires first.
    ///
    /// The hop count belongs to one attempt. So a retryable status on a hop
    /// makes the whole attempt retryable, and the repeated round starts again
    /// from the destination that the route names.
    ///
    /// The retries end at the response head. So if a body fails in transit,
    /// the caller gets a failed read. [`refetching`](Fetcher::refetching)
    /// fetches such a body again.
    ///
    /// # Failure order
    ///
    /// A fetch ends if it has no more destinations to ask or no more rounds to
    /// repeat. In both cases, it reports a definitive answer if it got one, and
    /// the first retryable failure if not.
    ///
    /// A caller can act on a definitive answer, for example a 404 that states
    /// that the object is absent. So the fetch reports such an answer from any
    /// round, and an earlier retryable failure does not hide it. Of two
    /// definitive answers, the fetch reports the answer that it got first. In
    /// one round, this is the mirror order.
    ///
    /// # Redirects
    ///
    /// A 301, 302, 303, 307, or 308 sends the attempt to the URL of its
    /// `Location` header, up to [`max_redirects`](FetcherOptions::max_redirects)
    /// times. A fetch is a GET, so none of the five statuses changes the method
    /// of the next hop.
    ///
    /// The fetch resolves `Location` against the URL of the response that
    /// carries it. So `Location` can be an absolute URL, a relative URL
    /// (`/other/path`, `sibling`), or a scheme-relative URL (`//host/path`). The
    /// resolution normalizes the result, as the HTTP specification prescribes
    /// for a redirect:
    ///
    /// - it resolves dot segments
    /// - it reads a backslash as a path separator
    /// - it removes tabs and newlines
    /// - it percent-encodes a character that a path or a query cannot carry
    /// - it puts an IPv4 or an IPv6 host in canonical form
    /// - it removes the fragment.
    ///
    /// A [`Target::Url`] goes on the wire as the caller wrote it. So one string
    /// as a URL target and as a `Location` can reach the server as two
    /// different request targets.
    ///
    /// The fetch refuses two hops definitively: a scheme other than `http` or
    /// `https`, and a hop from `https` to `http`. The [`Error::Fetch`] names the
    /// URL that redirected and the URL that it named. On a fetcher with no trust
    /// anchors, the fetch also refuses a hop to a TLS origin in the same way.
    /// The fetch follows a hop from `http` to `https`.
    ///
    /// If a response with one of the five statuses has no readable `Location`,
    /// the fetch reports the status, whatever the hop count. This applies to a
    /// missing header, an empty value, a value that is not text, and a value
    /// that the resolution cannot read.
    ///
    /// `Authorization`, `Proxy-Authorization`, and `Cookie` from either layer
    /// go to the origin that the route names. They also go to a hop at that
    /// origin: the same scheme, host, and port.
    ///
    /// The fetch removes them for a hop at another origin. A removed credential
    /// stays removed for the rest of the attempt, also on a redirect back to the
    /// named origin. At that time, the operator of the other origin has the
    /// request.
    ///
    /// The [`signer`](FetcherOptions::signer) follows the same rule. It signs
    /// each hop at the named origin again, with the path and the query of that
    /// hop. It signs no hop at another origin, and no hop after it.
    ///
    /// All other headers go to each hop, also the `User-Agent` and the
    /// `Accept-Encoding` of the fetcher. The fetcher presents a configured
    /// client certificate to the origin that the route names and to no other
    /// origin. So the pool keeps the connections with the certificate apart
    /// from the connections without it.
    ///
    /// The fetch discards the body of an intermediate response as it discards
    /// the body of an unsuccessful response. So if the declared length is
    /// 64 KiB or less, the HTTP/1.1 connection goes back to the pool. A chain
    /// on one origin then uses one connection. If the intermediate responses
    /// declare more, or declare no length, the chain opens a connection for
    /// each hop.
    ///
    /// The validators go to each hop, because they describe the resource. A 304
    /// from any hop is the answer of the fetch. Each message names the URL of
    /// the response that answered, which after a redirect is the URL of the
    /// last hop.
    ///
    /// A fetch with [`max_error_body`](FetchRequest::max_error_body) and a
    /// redirect limit of zero gets each redirect as an unsuccessful response.
    /// So the caller reads its headers, for example `Location`, and its body.
    /// A redirect with no usable `Location` is also such a response, at any
    /// limit.
    ///
    /// # Content coding
    ///
    /// A fetch gives the bytes that the remote stores. So each request carries
    /// `Accept-Encoding: identity`, and asks for no content coding. Without
    /// that header, a server can compress a response and stay within the HTTP
    /// specification. The body then holds bytes other than the bytes that the
    /// checksum of the object names.
    ///
    /// A 200 response fails the attempt definitively with
    /// [`Error::ContentEncoded`] in two cases: a `Content-Encoding` other than
    /// `identity`, or a `Transfer-Encoding` other than `chunked` and
    /// `identity`. This applies whichever layer asked for the coding. A caller
    /// that wants a coded body decodes it outside the fetcher.
    ///
    /// `chunked` frames a message, and the connection removes the framing. So a
    /// response with `chunked` alone gives the body as the remote wrote it.
    ///
    /// # Error responses
    ///
    /// A request with [`max_error_body`](FetchRequest::max_error_body) set
    /// keeps the unsuccessful response that the fetch reports. The
    /// [`Error::HttpStatus`] then carries an [`ErrorResponse`] with the
    /// headers of that response, and its body if the whole body is within the
    /// cap.
    ///
    /// - The fetch reads the body of a failure only if the failure order can
    ///   make it the reported failure. So it reads at most two bodies: one
    ///   retryable failure and one definitive answer. It keeps the body of the
    ///   failure that it reports. If each round gets a 503, the error holds
    ///   the body of the first 503. A 503 and then a 404 give the body of the
    ///   404.
    /// - The read takes place within one
    ///   [`progress_timeout`](FetcherOptions::progress_timeout) from the
    ///   arrival of the response head, and within
    ///   [`fetch_timeout`](FetcherOptions::fetch_timeout). The
    ///   [`low_speed`](FetcherOptions::low_speed) rule does not apply to it.
    /// - The fetch does not read a body that declares a coding or a
    ///   `Content-Length` over the cap. It discards such a body, and the error
    ///   holds the headers alone.
    /// - A body that grows past the cap, fails in transit, or does not end
    ///   within the window gives the headers alone. The fetch keeps no part of
    ///   such a body.
    /// - The read never changes the retry class of the status.
    /// - The bytes of a kept body do not count in the received counters of
    ///   [`counted`](Fetcher::counted).
    ///
    /// Before a body arrives, the read reserves at most 64 KiB, whatever
    /// length the response declares. The capacity of a kept body never passes
    /// the cap. So the fetch holds at most two kept bodies of at most the cap
    /// each, one retryable and one definitive, and one frame of the body that
    /// it reads.
    ///
    /// # Errors
    ///
    /// If more than one destination fails, the failure order rules state which
    /// error the fetch reports.
    ///
    /// - [`Error::Fetch`] before admission, if a path holds a `?` or a `#`, if
    ///   the query of a [`Target::PathQuery`] holds a `#`, or if the fetcher
    ///   has no mirror for a path target.
    /// - [`Error::Fetch`] before admission, if a URL target is not a valid
    ///   absolute URL, or holds a fragment or userinfo.
    /// - [`Error::Unsupported`] if the scheme of a URL target is neither `http`
    ///   nor `https`.
    /// - [`Error::Fetch`] before admission, if a request header is invalid, is
    ///   `Host`, or is a header that the connection layer sets.
    /// - [`Error::Fetch`] before admission, if an `Authorization` header is
    ///   beside [`basic_auth`](FetchRequest::basic_auth).
    /// - [`Error::Fetch`] before admission, if the fetcher has a
    ///   [`signer`](FetcherOptions::signer) and the request carries
    ///   [`basic_auth`](FetchRequest::basic_auth) or an `Authorization`
    ///   header.
    /// - [`Error::Fetch`] before admission, if a credential can reach a
    ///   cleartext destination, and neither
    ///   [`allow_cleartext_credentials`](FetchRequest::allow_cleartext_credentials)
    ///   nor [`FetcherOptions::allow_cleartext_credentials`] is `true`.
    /// - [`Error::Fetch`] before admission, if the route names a TLS
    ///   destination and the fetcher holds no trust anchors.
    /// - [`Error::Fetch`] if a transport failure ends the rounds: a failed
    ///   connect, handshake, or proxy `CONNECT`, or an expired deadline.
    /// - [`Error::Fetch`] if the fetch refuses a redirect hop, as the redirect
    ///   rules state.
    /// - [`Error::Fetch`] if hyper cannot build a request, for example from an
    ///   invalid validator value.
    /// - The error of the [`signer`](FetcherOptions::signer), unchanged, if it
    ///   fails. An [`Error::Fetch`] if it returns a header that a request
    ///   cannot carry. The fetch asks no other destination and repeats no
    ///   round.
    /// - [`Error::Fetch`] if [`fetch_timeout`](FetcherOptions::fetch_timeout)
    ///   expires.
    /// - [`Error::HttpStatus`] if a destination answers with a status other
    ///   than 200 and 304. This includes a redirect that the fetch does not
    ///   follow: no usable `Location`, or a redirect limit of zero. With
    ///   [`max_error_body`](FetchRequest::max_error_body), the error carries
    ///   the response, as the rules of the error responses state.
    /// - [`Error::RedirectLimit`] if an attempt follows
    ///   [`max_redirects`](FetcherOptions::max_redirects) redirects, and the
    ///   next response names a URL to follow.
    /// - [`Error::FetchTooLarge`] if the `Content-Length` of the response is
    ///   more than [`max_size`](FetchRequest::max_size).
    /// - [`Error::ContentEncoded`] if the response declares a coding, as the
    ///   content coding rules state.
    pub async fn fetch(&self, request: FetchRequest<'_>) -> Result<Fetched> {
        let (fetched, _) = self
            .fetch_budgeted(&request, self.inner.max_retries)
            .await?;
        Ok(fetched)
    }

    /// Returns a [`Refetch`] of `request`, which fetches a failed body again.
    ///
    /// [`Refetch`] states the budget that it spends.
    pub fn refetching<'r>(&self, request: FetchRequest<'r>) -> Refetch<'_, 'r> {
        Refetch {
            fetcher: self,
            request,
            left: self.inner.max_retries,
            round: 0,
            interrupted: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Fetches `request`, and repeats a round at most `max_retries` times.
    /// Returns the response and the number of repeated rounds.
    async fn fetch_budgeted(
        &self,
        request: &FetchRequest<'_>,
        max_retries: u32,
    ) -> Result<(Fetched, u32)> {
        // The target, the headers, their credentials, and the anchors of a TLS
        // destination are the same for each destination. So the fetch settles
        // all of them before admission, and reports a failure of them one
        // time. The fetch takes no permit and opens no socket for it.
        let route = self.route(request.target)?;
        if self.inner.signer.is_some() {
            refuse_beside_signer(request.headers, request.basic_auth.is_some(), false)?;
        }
        let headers = merge_headers(
            &self.inner.headers,
            request.headers,
            request.basic_auth,
            None,
        )?;
        if !request.allow_cleartext_credentials && !self.inner.allow_cleartext_credentials {
            self.check_cleartext(&route, &headers)?;
        }
        self.check_trust_anchors(&route)?;
        let permit = self.inner.gate.acquire(request.priority).await;
        let rounds = self.rounds(request, &route, &headers, permit, max_retries);
        let Some(limit) = self.inner.fetch_timeout else {
            return rounds.await;
        };
        // The expiry drops the rounds, the attempt in flight, and the permit.
        // So the slot is free before the fetch reports the failure.
        match within(limit, rounds).await {
            Some(result) => result,
            None => Err(Error::Fetch(format!(
                "fetch of {} timed out after {limit:?}",
                request.target.describe()
            ))),
        }
    }

    /// Returns the destinations of a fetch of `target`, in the order in which
    /// the fetch asks them.
    ///
    /// A URL target names its one destination, which this function parses. A
    /// path target, with or without a query, goes to the mirrors, so a
    /// fetcher with no mirror has no destination for it. The signer of the
    /// fetcher, if there is one, gives the form of the path.
    fn route<'a>(&self, target: Target<'a>) -> Result<Route<'a>> {
        let (path, query) = match target {
            Target::Url(url) => return Ok(Route::One(parse_url(url)?)),
            Target::Path(path) => (path, None),
            Target::PathQuery { path, query } => (path, Some(query)),
        };
        check_path(path)?;
        if let Some(query) = query {
            check_query(path, query)?;
        }
        if self.inner.mirrors.is_empty() {
            return Err(Error::Fetch(format!(
                "fetch of the path {} has nowhere to go: no mirror is configured",
                target.describe()
            )));
        }
        let path = match &self.inner.signer {
            Some(signer) => signer.request_path(path)?,
            None => Cow::Borrowed(path),
        };
        Ok(Route::Mirrors { path, query })
    }

    /// Refuses a fetch if its headers carry a credential that a cleartext
    /// destination gets in the clear.
    ///
    /// The fetch withholds a credential from no destination. So one cleartext
    /// destination that the fetch can reach is enough for a refusal. The other
    /// choice is to send the request without the credential, which gets a 401
    /// that names nothing.
    fn check_cleartext(
        &self,
        route: &Route<'_>,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<()> {
        // A signer is a credential, as an `Authorization` header is.
        if self.inner.signer.is_none() && !headers.iter().any(|(name, _)| is_credential(name)) {
            return Ok(());
        }
        let Some(origin) = self.matching_origin(route, |origin| !origin.tls) else {
            return Ok(());
        };
        Err(Error::Fetch(format!(
            "the request carries credentials, which the cleartext origin {origin} would receive \
             in the clear: fetch over https, drop the credentials, or set \
             allow_cleartext_credentials on the request or on the fetcher"
        )))
    }

    /// Refuses a fetch if its route names a TLS destination and the fetcher
    /// holds no trust anchors.
    ///
    /// A handshake verifies the server certificate against an anchor, so a
    /// fetcher with no anchor reaches no TLS origin. Only one case gets here: a
    /// request with an `https` URL of its own, on a fetcher with all mirrors in
    /// cleartext. Each other combination of route and anchors fails
    /// [`Fetcher::new`].
    ///
    /// The handshake reports this case as an unknown issuer. That is a
    /// retryable failure, which uses all rounds and all backoffs before it
    /// names the cause. So the refusal occurs here, before admission.
    ///
    /// This function reads the destinations of the route. A redirect hop names
    /// an origin that the server chooses. If that origin is TLS, the attempt
    /// refuses the hop with the same message, from [`no_trust_anchors`].
    fn check_trust_anchors(&self, route: &Route<'_>) -> Result<()> {
        if self.inner.has_trust_anchors {
            return Ok(());
        }
        let Some(origin) = self.matching_origin(route, |origin| origin.tls) else {
            return Ok(());
        };
        Err(no_trust_anchors(origin))
    }

    /// Returns the `scheme://authority` of the first destination on `route`
    /// whose origin `wanted` accepts.
    fn matching_origin<'a>(
        &'a self,
        route: &'a Route<'_>,
        wanted: fn(&Origin) -> bool,
    ) -> Option<&'a str> {
        match route {
            Route::Mirrors { .. } => self
                .inner
                .mirrors
                .iter()
                .find(|mirror| wanted(&mirror.origin))
                .map(|mirror| mirror.prefix.as_str()),
            Route::One(destination) => {
                wanted(&destination.origin).then(|| destination.origin_url())
            }
        }
    }

    /// Tries each destination in turn, and repeats the round at most
    /// `max_retries` times while a destination has a retryable failure.
    ///
    /// The permit moves into the body of a successful round. If no round
    /// succeeds, the permit drops with this future. A success returns the
    /// number of repeated rounds.
    async fn rounds(
        &self,
        request: &FetchRequest<'_>,
        route: &Route<'_>,
        headers: &[(HeaderName, HeaderValue)],
        permit: Permit,
        max_retries: u32,
    ) -> Result<(Fetched, u32)> {
        let destination_count = match route {
            Route::Mirrors { .. } => self.inner.mirrors.len(),
            Route::One(_) => 1,
        };
        // A destination with a definitive answer gives the same answer in each
        // round, so the fetch asks it once. A repeated round asks only the
        // destinations with a retryable failure.
        let mut settled = vec![false; destination_count];
        // The failure that both end paths report. A caller can act on a
        // definitive answer, so it has priority over a retryable failure from
        // any round. A destination that fails transiently and then answers 404
        // reports the 404. Of two failures of one kind, the fetch keeps the
        // first.
        let mut reported: Option<Error> = None;
        let mut definitive = false;
        let mut round = 0;
        loop {
            let mut retryable = false;
            for (position, settled) in settled.iter_mut().enumerate() {
                if *settled {
                    continue;
                }
                // The fetch builds the destination of a mirror for the attempt
                // that uses it. So if the first mirror answers, the fetch builds
                // one destination, whatever the length of the list.
                let destination = match route {
                    Route::Mirrors { path, query } => {
                        Cow::Owned(self.inner.mirrors[position].destination(path, *query))
                    }
                    Route::One(destination) => Cow::Borrowed(destination),
                };
                // A fetch reads at most one body of each class, and keeps the
                // body of the failure that it reports.
                let keep = request.max_error_body.map(|cap| Keep {
                    cap,
                    retryable: reported.is_none(),
                    definitive: !definitive,
                });
                let failure = match self.attempt(&destination, request, headers, keep).await {
                    Ok(Attempted::Body(mut body)) => {
                        body.permit = Some(permit);
                        return Ok((Fetched::Body(body), round));
                    }
                    Ok(Attempted::NotModified) => return Ok((Fetched::NotModified, round)),
                    Err(failure) => failure,
                };
                match failure {
                    Failure::Retry(e) => {
                        retryable = true;
                        if reported.is_none() {
                            reported = Some(e);
                        }
                    }
                    Failure::Fatal(e) => {
                        *settled = true;
                        if !definitive {
                            reported = Some(e);
                            definitive = true;
                        }
                    }
                    Failure::Final(e) => return Err(e),
                }
            }
            // If `retryable` is `true`, one or more destinations had a
            // retryable failure. If not, each destination gave a definitive
            // answer.
            if !retryable || round >= max_retries {
                return Err(reported.expect("a failed round holds a failure"));
            }
            round += 1;
            rt::Timer::after(backoff(round)).await;
        }
    }

    /// Sends one request to one destination, and follows the redirects of the
    /// responses.
    ///
    /// The hop state of an attempt is three locals:
    ///
    /// - the destination, borrowed from the route until a redirect names
    ///   another destination
    /// - the header list, which is the slice of the caller until a hop goes to
    ///   another origin and a credential must come out
    /// - the count of followed redirects.
    ///
    /// If the first response answers the request, all three stay as they
    /// start. So the attempt builds no URL, copies no header list, and
    /// allocates no bookkeeping.
    ///
    /// `keep` names the unsuccessful responses whose headers and body the
    /// attempt keeps in the failure. The attempt discards each other one.
    async fn attempt(
        &self,
        destination: &Destination,
        request: &FetchRequest<'_>,
        headers: &[(HeaderName, HeaderValue)],
        keep: Option<Keep>,
    ) -> std::result::Result<Attempted, Failure> {
        // The origin that the route names. A credential and the client
        // certificate go to this origin alone.
        let named = &destination.origin;
        let mut hop = Cow::Borrowed(destination);
        let mut headers = Cow::Borrowed(headers);
        // The signer signs each hop at the named origin. It stays out of the
        // attempt after a hop at another origin, as a credential does.
        let mut signer = self.inner.signer.as_deref();
        let mut followed = 0u32;
        let progress_timeout = self.inner.progress_timeout;
        // One progress window applies to all drains of this attempt, whatever
        // the number of hops. A peer can answer each hop with a short declared
        // body and then stop. Such a peer uses the window on the first drain,
        // and each later drain drops its connection and does not wait. An
        // attempt that follows no redirect drains once, with the whole window.
        let drain_until = Instant::now() + progress_timeout;
        // The response head must arrive within the time of the rule, in whole
        // seconds, from the start of the attempt, whatever the number of hops.
        // A head carries no bytes for the rate. So the rate stays under the
        // limit from the start until the head arrives.
        let head_until = self
            .inner
            .low_speed
            .and_then(|low| Some((Instant::now().checked_add(low.whole_seconds())?, low)));
        loop {
            // Each hop makes its own proxy decision. The pool keeps a cleartext
            // hop behind a proxy under the proxy endpoint. So one such
            // connection carries requests for all cleartext origins.
            let via = self.inner.proxies.via(&hop.origin);
            let key = PoolKey {
                origin: match via {
                    Via::Absolute(proxy) => proxy.endpoint.clone(),
                    Via::Direct | Via::Tunnel(_) => hop.origin.clone(),
                },
                identity: self.presents_identity(&hop.origin, named),
                proxied: matches!(via, Via::Absolute(_)),
            };
            let url = hop.url();
            let (response, protocol, reuse) = match head_until {
                None => {
                    self.send(&hop, &key, via, request, &headers, signer)
                        .await?
                }
                Some((until, low)) => {
                    // The send is in a box under the window. So the attempt
                    // holds one inline copy of its state.
                    let sent = Box::pin(self.send(&hop, &key, via, request, &headers, signer));
                    match within(until.saturating_duration_since(Instant::now()), sent).await {
                        Some(result) => result?,
                        None => return Err(Failure::Retry(too_slow(url, low))),
                    }
                }
            };
            let status = response.status();
            if status == StatusCode::NOT_MODIFIED {
                // A 304 carries no body, so the connection is ready for the
                // next request immediately. The validators describe the
                // resource. So a 304 from a hop is the answer for the caller,
                // as a 304 from the named destination is.
                if let Some(sender) = reuse {
                    self.inner.put_h1(&key, sender);
                }
                return Ok(Attempted::NotModified);
            }
            // A limit of zero follows nothing. Each redirect status is then a
            // definitive answer.
            if is_redirect(status) && self.inner.max_redirects > 0 {
                let location = response
                    .headers()
                    .get(hyper::header::LOCATION)
                    .and_then(|value| resolve_location(url, value));
                let Some(location) = location else {
                    // There is no URL to follow. So the attempt reports the
                    // status of the hop, whatever the hop count is.
                    let failure = classify(status, url);
                    return Err(self
                        .conclude(&key, response, reuse, drain_until, failure, keep)
                        .await);
                };
                // The limit stops the attempt at a URL that it can follow. So
                // the attempt reads the limit after the `Location` names a URL.
                if followed >= self.inner.max_redirects {
                    self.discard(&key, response, reuse, drain_until).await;
                    return Err(Failure::Fatal(Error::RedirectLimit {
                        url: url.to_string(),
                        hops: followed,
                    }));
                }
                let next = redirect_destination(&hop, &location);
                // The attempt discards the intermediate body as it discards an
                // unsuccessful body. So a short body returns its HTTP/1.1
                // connection to the pool, and the next hop at this origin
                // uses it.
                self.discard(&key, response, reuse, drain_until).await;
                let next = next.map_err(Failure::Fatal)?;
                // A handshake verifies the server certificate against an
                // anchor. So the attempt refuses a hop to a TLS origin if the
                // fetcher holds no anchor. Without this check, the handshake
                // fails retryably, and uses all rounds and all backoffs on a
                // message about the peer.
                if next.origin.tls && !self.inner.has_trust_anchors {
                    return Err(Failure::Fatal(no_trust_anchors(next.origin_url())));
                }
                // The operator of the origin that a request reaches gets its
                // credentials. So the attempt removes them for a hop at an
                // origin other than the named origin. They stay removed for the
                // rest of the attempt, also on a redirect back to the named
                // origin. At that time, the other operator controls the request.
                // The same applies to the signer.
                if next.origin != *named {
                    signer = None;
                }
                if next.origin != *named && headers.iter().any(|(name, _)| is_credential(name)) {
                    let scoped = headers
                        .iter()
                        .filter(|(name, _)| !is_credential(name))
                        .cloned()
                        .collect::<Vec<_>>();
                    headers = Cow::Owned(scoped);
                }
                hop = Cow::Owned(next);
                followed += 1;
                continue;
            }
            if status != StatusCode::OK {
                let failure = classify(status, url);
                return Err(self
                    .conclude(&key, response, reuse, drain_until, failure, keep)
                    .await);
            }
            // A coded body holds bytes other than the bytes that the remote
            // stores. So the declared length tells nothing about the object,
            // and the attempt refuses the coding before it compares the cap.
            // The refusal names the coding, and a checksum mismatch cannot. The
            // refusal is definitive, because another attempt against the same
            // destination gets the same answer.
            if let Some(encoding) = declared_coding(response.headers()) {
                let url = url.to_string();
                self.discard(&key, response, reuse, drain_until).await;
                return Err(Failure::Fatal(Error::ContentEncoded { url, encoding }));
            }
            let validators = read_validators(response.headers());
            let content_length = content_length(response.headers());
            // The cap is the limit of the caller on the object. So the attempt
            // compares it with the response that carries the object, and with
            // no redirect before it.
            if let (Some(limit), Some(length)) = (request.max_size, content_length)
                && length > limit
            {
                self.discard(&key, response, reuse, drain_until).await;
                return Err(Failure::Fatal(Error::FetchTooLarge { limit }));
            }
            let protocol = match response.version() {
                Version::HTTP_2 => Protocol::Http2,
                _ => protocol,
            };
            return Ok(Attempted::Body(Body {
                incoming: response.into_body(),
                chunk: Bytes::new(),
                received: 0,
                max_size: request.max_size,
                validators,
                content_length,
                protocol,
                inner: self.inner.clone(),
                counters: self.received.clone(),
                key,
                reuse,
                permit: None,
                done: false,
                failed: None,
                deadline: rt::Deadline::new(progress_timeout),
                waiting: false,
                low_speed: self.inner.low_speed.map(Monitor::new),
                interrupted: None,
                request_body: None,
            }));
        }
    }

    /// Takes or opens a connection for one hop, and sends the request over it.
    ///
    /// The function returns the response, its protocol, and the HTTP/1.1
    /// connection of the response. That connection goes back to the pool after
    /// the response is read to its end.
    ///
    /// A `signer` signs the request after the connection is taken. So the
    /// wait for a connect is not part of the age of the signature. If the
    /// signer fails, an HTTP/1.1 connection goes back to the pool unused.
    async fn send(
        &self,
        hop: &Destination,
        key: &PoolKey,
        via: Via<'_>,
        request: &FetchRequest<'_>,
        headers: &[(HeaderName, HeaderValue)],
        signer: Option<&dyn RequestSigner>,
    ) -> std::result::Result<(Response<Incoming>, Protocol, Option<H1Sender>), Failure> {
        let url = hop.url();
        let origin = &key.origin;
        let connect_timeout = self.inner.connect_timeout;
        let progress_timeout = self.inner.progress_timeout;
        let (sender, idle_since) = match self.inner.take_conn(key) {
            Some(taken) => taken,
            None => {
                // The open of a connection is the largest state of a fetch: the
                // TLS handshake and the state of hyper. It is also the rarest,
                // because it occurs only if the pool has no connection for this
                // origin. A box keeps that state out of the fetch future, which
                // each caller nests in its own future.
                //
                // A fetch measures 5064 bytes with the box and 36136 bytes
                // without it. A caller that wraps several helpers around one
                // fetch multiplies the saving.
                let opened = within(connect_timeout, Box::pin(self.connect(key, via))).await;
                match opened {
                    Some(result) => (result?, None),
                    None => {
                        return Err(Failure::Retry(connect_timed_out(
                            origin,
                            via,
                            connect_timeout,
                        )));
                    }
                }
            }
        };
        let headers = match signer {
            None => Cow::Borrowed(headers),
            Some(signer) => match signed(signer, &Method::GET, hop, SignPayload::Empty, headers) {
                Ok(signed) => signed,
                Err(failure) => {
                    // The connection carried no request, so it goes back to
                    // the pool as it came.
                    if let Sender::H1(sender) = sender {
                        let since = idle_since.unwrap_or_else(Instant::now);
                        self.inner.put_idle_h1(key, sender, since);
                    }
                    return Err(failure);
                }
            },
        };
        match sender {
            Sender::H1(mut sender) => {
                let http_request = self
                    .build_request(hop, request, &headers, Protocol::Http11, via)
                    .map_err(Failure::Fatal)?;
                // The request and the wait for the response head share the
                // progress window, because the head is the first bytes of the
                // response.
                let sent = within(progress_timeout, async {
                    sender.ready().await?;
                    sender.send_request(http_request).await
                })
                .await;
                let response = match sent {
                    Some(result) => result.map_err(|e| Failure::Retry(transport(url, e)))?,
                    None => return Err(Failure::Retry(stalled(url, progress_timeout))),
                };
                Ok((response, Protocol::Http11, Some(sender)))
            }
            Sender::H2(mut sender) => {
                let http_request = self
                    .build_request(hop, request, &headers, Protocol::Http2, via)
                    .map_err(Failure::Fatal)?;
                let sent = within(progress_timeout, async {
                    sender.ready().await?;
                    sender.send_request(http_request).await
                })
                .await;
                let response = match sent {
                    Some(result) => result.map_err(|e| Failure::Retry(transport(url, e)))?,
                    None => return Err(Failure::Retry(stalled(url, progress_timeout))),
                };
                Ok((response, Protocol::Http2, None))
            }
        }
    }

    /// Returns `true` if a connection to `hop` presents the configured client
    /// certificate.
    ///
    /// This is the case if a certificate is configured, the hop is the origin
    /// that the route names, and that origin is TLS. A cleartext connection
    /// presents no certificate. If no certificate is configured, the result is
    /// always `false`, so the pool holds one entry for each origin.
    fn presents_identity(&self, hop: &Origin, named: &Origin) -> bool {
        self.inner.client_identity && hop.tls && hop == named
    }

    /// Ends an attempt with a response that the caller did not ask for.
    ///
    /// If the response declares a body of at most [`DRAIN_LIMIT`] bytes, the
    /// function reads it to the end. This frees its HTTP/1.1 connection for the
    /// next request. The function drops a larger declared body, or a body with
    /// no declared length. The connection then closes, because the rest of the
    /// response is still in flight.
    ///
    /// An HTTP/2 stream has no such cost, because its connection stays in the
    /// pool, whatever the stream did. So it needs no drain.
    ///
    /// `drain_until` is the limit for all reads of one attempt here. It is one
    /// progress window from the start of the attempt, and the reads share it. A
    /// read that reaches the end of the window drops the remaining response. A
    /// read that finds no time left drops the connection and reads nothing.
    async fn discard(
        &self,
        key: &PoolKey,
        response: Response<Incoming>,
        reuse: Option<H1Sender>,
        drain_until: Instant,
    ) {
        let length = content_length(response.headers());
        self.drain(key, length, response.into_body(), reuse, drain_until)
            .await;
    }

    /// Ends an attempt with the unsuccessful response that `failure`
    /// classifies, and returns the failure.
    ///
    /// If `keep` asks for a response of the class of the failure, the
    /// function reads the response with [`capture`](Fetcher::capture) and
    /// puts it into the failure. Else it discards the response.
    async fn conclude(
        &self,
        key: &PoolKey,
        response: Response<Incoming>,
        reuse: Option<H1Sender>,
        drain_until: Instant,
        failure: Failure,
        keep: Option<Keep>,
    ) -> Failure {
        match failure.kept_cap(keep) {
            None => {
                self.discard(key, response, reuse, drain_until).await;
                failure
            }
            Some(cap) => {
                let kept = self.capture(key, response, reuse, cap).await;
                failure.with_response(kept)
            }
        }
    }

    /// Reads the headers and the body of an unsuccessful response, for the
    /// error of the fetch.
    ///
    /// The function keeps the whole body if it is `cap` bytes or less, and
    /// keeps no part of a larger body. It reads no body that declares a
    /// coding or a length over the cap, and discards it as
    /// [`discard`](Fetcher::discard) does. A body that grows past the cap, or
    /// fails, closes its connection.
    ///
    /// Before the first byte, the function reserves at most
    /// [`CAPTURE_RESERVE`] bytes, whatever length the response declares. The
    /// capacity of the kept body never passes `cap`.
    ///
    /// All reads take place within one progress window from the call. The
    /// read stops at the end of the window, and the body is then absent. The
    /// bytes do not count in the received counters, because they are not part
    /// of an object. A clean end of the body returns an HTTP/1.1 connection to
    /// the pool.
    async fn capture(
        &self,
        key: &PoolKey,
        response: Response<Incoming>,
        reuse: Option<H1Sender>,
        cap: u64,
    ) -> ErrorResponse {
        let until = Instant::now() + self.inner.progress_timeout;
        let (parts, mut body) = response.into_parts();
        let headers = parts.headers;
        let length = content_length(&headers);
        if declared_coding(&headers).is_some() || length.is_some_and(|length| length > cap) {
            self.drain(key, length, body, reuse, until).await;
            return ErrorResponse::new(headers, None);
        }
        // The declared length is a claim of the server, so the reserve before
        // the first byte stays small. The vector grows as the bytes arrive.
        let reserve = length.unwrap_or(0).min(cap).min(CAPTURE_RESERVE);
        let mut bytes = Vec::with_capacity(usize::try_from(reserve).unwrap_or(0));
        let budget = until.saturating_duration_since(Instant::now());
        let read = within(budget, async {
            loop {
                let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
                match frame {
                    Some(Ok(frame)) => {
                        // A trailer carries no bytes of the body.
                        let Ok(data) = frame.into_data() else {
                            continue;
                        };
                        if !extend_capped(&mut bytes, &data, cap) {
                            return false;
                        }
                    }
                    Some(Err(_)) => return false,
                    None => return true,
                }
            }
        })
        .await;
        if read != Some(true) {
            // The rest of the response is still in flight, so the connection
            // closes when `reuse` drops.
            return ErrorResponse::new(headers, None);
        }
        if let Some(sender) = reuse {
            self.inner.put_h1(key, sender);
        }
        ErrorResponse::new(headers, Some(bytes))
    }

    /// Reads a response body of the declared `length` to its end within
    /// `drain_until`, and returns its HTTP/1.1 connection to the pool.
    ///
    /// [`discard`](Fetcher::discard) states the rule.
    async fn drain(
        &self,
        key: &PoolKey,
        length: Option<u64>,
        mut body: Incoming,
        reuse: Option<H1Sender>,
        drain_until: Instant,
    ) {
        let Some(sender) = reuse else { return };
        if length.is_none_or(|length| length > DRAIN_LIMIT) {
            return;
        }
        let budget = drain_until.saturating_duration_since(Instant::now());
        if budget.is_zero() {
            return;
        }
        // The drain runs in the remaining window of the attempt. So a peer that
        // declares a short body and then stops costs the attempt no more than a
        // stalled body, whatever the hop count.
        let drained = within(budget, async {
            loop {
                let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
                match frame {
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => return false,
                    None => return true,
                }
            }
        })
        .await;
        if drained == Some(true) {
            self.inner.put_h1(key, sender);
        }
    }

    /// Sends `request` and tries each destination until one takes it.
    ///
    /// Each final status returns an [`Uploaded`], also 408, 429, and 5xx. The
    /// mirrors, the proxy, TLS, the client certificate, the headers, the
    /// credentials, the signer, and the cleartext rule apply to an upload as
    /// they apply to [`fetch`](Fetcher::fetch). An upload can also carry a
    /// [`BearerToken`] of its own as its credential. The fetcher sets no
    /// `Content-Type` header and no `Expect` header.
    ///
    /// The hand-over gives the request to hyper. A failure before the
    /// hand-over returns the error that a fetch returns. A failure after the
    /// hand-over returns [`Error::UploadInterrupted`].
    ///
    /// # Retries
    ///
    /// The fetcher tries an upload again only while no part of the request is
    /// sent. The request is unsent if the attempt fails before hyper accepts
    /// it, in one of these steps:
    ///
    /// - the connect
    /// - the `CONNECT` tunnel
    /// - the TLS handshake
    /// - the HTTP handshake
    /// - the wait for a ready connection.
    ///
    /// The request is also unsent if hyper gives it back unwritten. The bytes
    /// of a `CONNECT` go to the proxy alone and are no part of the request.
    ///
    /// An unsent attempt spends a round as a retryable failure of a fetch
    /// does. The upload asks the next mirror, then repeats the round after the
    /// backoff, up to [`max_retries`](FetcherOptions::max_retries) times. A 407
    /// to the `CONNECT` is definitive. If the rounds run out before the request
    /// is sent, the upload returns the [`Error::Fetch`] that a fetch returns.
    ///
    /// If the writer of a streamed body is dropped before it closes the body,
    /// the upload fails before the hand-over. It fails with [`Error::Fetch`]
    /// and sends nothing.
    ///
    /// All other outcomes count as sent. The upload then ends on the
    /// destination that took it, and asks no other mirror and no other round.
    /// A failure after the hand-over fails the upload with
    /// [`Error::UploadInterrupted`], because the server can have received the
    /// whole request and acted on it. An HTTP/2 stream that the server refuses
    /// or resets after the hand-over is such a failure.
    ///
    /// # Redirects
    ///
    /// For a body given whole, the upload follows a 307 or a 308. It keeps the
    /// method and sends the bytes again. The redirect rules of
    /// [`fetch`](Fetcher::fetch) apply: the redirect limit, the refusal of a
    /// hop from `https` to `http`, and the scope of the credentials and of the
    /// signer.
    ///
    /// The first hop sends the request. So a failure on a later hop, a refused
    /// hop, and a redirect past the limit each fail the upload with
    /// [`Error::UploadInterrupted`].
    ///
    /// The upload returns these redirects as their status in an [`Uploaded`]:
    ///
    /// - a redirect status other than 307 and 308
    /// - each redirect of a streamed body
    /// - a 307 or a 308 with no `Location` that the upload can read
    /// - each redirect if [`max_redirects`](FetcherOptions::max_redirects) is
    ///   0.
    ///
    /// # Unsuccessful answers
    ///
    /// An answer other than 2xx returns an [`Uploaded`] with its status and
    /// its headers, also when the upload cannot deliver its body. The upload
    /// does not deliver a body that declares a coding in `Content-Encoding` or
    /// `Transfer-Encoding`, or a `Content-Length` over
    /// [`max_response`](UploadRequest::max_response). It withholds such a
    /// body: [`Uploaded::body_withheld`] returns `true`, the body reads as
    /// empty, and the connection closes. So a definitive refusal, for example
    /// a 403 behind a proxy that compresses it, keeps its status, and the
    /// caller does not take it for an interrupted upload.
    ///
    /// A 2xx answer with such a body fails the upload with
    /// [`Error::UploadInterrupted`].
    ///
    /// # Connections
    ///
    /// An upload uses the pooled HTTP/2 connection of its origin. It takes an
    /// idle HTTP/1.1 connection from the pool only if the connection became
    /// idle less than 2 seconds ago. Otherwise, it opens a connection of its
    /// own.
    ///
    /// A server can close an idle connection at any time. If hyper began to
    /// write an upload over a connection that the server closed, the upload
    /// counts as sent. A server closes an idle connection at the end of its
    /// idle timeout, so it keeps a connection that became idle a short time
    /// ago.
    ///
    /// If a pooled HTTP/1.1 connection fails before hyper writes the request,
    /// the fetcher drops the connection. The upload then continues over a new
    /// connection and spends no round.
    ///
    /// The HTTP/1.1 connection of an upload goes back to the pool if both
    /// bodies end cleanly. That is, hyper takes the end of the request body
    /// before the response head arrives. Then the caller reads the response
    /// body to its end with no failure. Each of these closes the connection:
    ///
    /// - a response that closes the connection
    /// - an HTTP/1.0 response
    /// - an answer that arrives before the end of the request body
    /// - a response body that fails
    /// - a response that is dropped before its end.
    ///
    /// # The response ends the request body
    ///
    /// A server can answer before it reads the whole request body. If the
    /// response body ends or is dropped before the request body ends, the
    /// fetcher fails the request body. The writer then gets
    /// [`io::ErrorKind::BrokenPipe`](std::io::ErrorKind::BrokenPipe), and hyper
    /// stops the body.
    ///
    /// The stop of the body closes an HTTP/1.1 connection and resets an HTTP/2
    /// stream. The same applies to a response that the upload does not
    /// deliver: a followed redirect, a refused coding, a declared length over
    /// the cap, and a withheld body.
    ///
    /// # Deadlines
    ///
    /// - [`connect_timeout`](FetcherOptions::connect_timeout) bounds the open
    ///   of a connection.
    /// - [`fetch_timeout`](FetcherOptions::fetch_timeout) bounds the upload
    ///   from admission to the hand-over alone.
    /// - While a streamed body streams, the one bound is the stall window of
    ///   [`UploadWriter`], which starts at the hand-over.
    /// - For a body given whole, a frame that the connection does not take for
    ///   [`progress_timeout`](FetcherOptions::progress_timeout) ends the upload
    ///   with [`Error::UploadInterrupted`].
    /// - The wait for the response head lasts
    ///   [`response_timeout`](UploadRequest::response_timeout).
    /// - The response body has the progress window of a fetch.
    ///
    /// Before the hand-over, a wait of the writer has no bound of its own. This
    /// applies at the gate, during the connect, and during the backoff between
    /// rounds.
    /// The low-speed rule does not apply to an upload.
    ///
    /// # Errors
    ///
    /// If more than one destination fails before the hand-over, the failure
    /// order of [`fetch`](Fetcher::fetch) states which error the upload
    /// returns.
    ///
    /// - [`Error::Fetch`] before admission, if a path holds a `?` or a `#`, if
    ///   the query of a [`Target::PathQuery`] holds a `#`, or if the fetcher
    ///   has no mirror for a path target.
    /// - [`Error::Fetch`] before admission, if a URL target is not a valid
    ///   absolute URL, or holds a fragment or userinfo.
    /// - [`Error::Unsupported`] if the scheme of a URL target is neither `http`
    ///   nor `https`.
    /// - [`Error::Fetch`] before admission, if a request header is invalid, is
    ///   `Host`, or is a header that the connection layer sets.
    /// - [`Error::Fetch`] before admission, if two credentials of the request
    ///   meet: [`basic_auth`](UploadRequest::basic_auth),
    ///   [`bearer_token`](UploadRequest::bearer_token), and an `Authorization`
    ///   header. A bearer token that is not token68 also fails.
    /// - [`Error::Fetch`] before admission, if the fetcher has a
    ///   [`signer`](FetcherOptions::signer) and the request carries one of
    ///   these credentials: [`basic_auth`](UploadRequest::basic_auth),
    ///   [`bearer_token`](UploadRequest::bearer_token), or an `Authorization`
    ///   header.
    /// - [`Error::Fetch`] before admission, if a credential can reach a
    ///   cleartext destination, and neither
    ///   [`allow_cleartext_credentials`](UploadRequest::allow_cleartext_credentials)
    ///   nor [`FetcherOptions::allow_cleartext_credentials`] is `true`.
    /// - [`Error::Fetch`] before admission, if the route names a TLS
    ///   destination and the fetcher holds no trust anchors.
    /// - [`Error::Fetch`] before admission, if the method is `DELETE` and the
    ///   body is not an empty [`UploadBody::bytes`].
    /// - [`Error::Fetch`] if a transport failure ends the rounds before the
    ///   hand-over: a failed connect, handshake, or proxy `CONNECT`, or an
    ///   expired deadline.
    /// - [`Error::Fetch`] if hyper cannot build the request.
    /// - The error of the [`signer`](FetcherOptions::signer), unchanged, if it
    ///   fails before the hand-over. An [`Error::Fetch`] if it returns a
    ///   header that a request cannot carry. The upload asks no other
    ///   destination and repeats no round. A failure of the signer on a
    ///   redirect hop is a failure after the hand-over.
    /// - [`Error::Fetch`] if the writer of a streamed body is dropped before
    ///   the hand-over.
    /// - [`Error::Fetch`] if [`fetch_timeout`](FetcherOptions::fetch_timeout)
    ///   expires before the hand-over.
    /// - [`Error::UploadInterrupted`] if a failure occurs after the hand-over.
    ///   This includes a refused redirect hop, a redirect past the limit, and
    ///   a 2xx response that declares a coding or a `Content-Length` over
    ///   [`max_response`](UploadRequest::max_response). The message names the
    ///   cause.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ostrya_fetch::{Fetcher, FetcherOptions, UploadBody, UploadRequest};
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let fetcher = Fetcher::new(FetcherOptions::new("https://example.com/repo")).await?;
    /// let body = UploadBody::bytes(b"report".to_vec());
    /// let uploaded = fetcher.upload(UploadRequest::path("inbox/report", body)).await?;
    /// println!("the server answered {}", uploaded.status());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn upload(&self, request: UploadRequest<'_>) -> Result<Uploaded> {
        let UploadRequest {
            target,
            method,
            body,
            priority,
            max_response,
            headers,
            basic_auth,
            bearer_token,
            allow_cleartext_credentials,
            response_timeout,
        } = request;
        // As for a fetch, the checks of the request run before admission.
        // The check of the body that a DELETE does not send runs there too.
        let route = self.route(target)?;
        if self.inner.signer.is_some() {
            refuse_beside_signer(headers, basic_auth.is_some(), bearer_token.is_some())?;
        }
        let headers = merge_headers(&self.inner.headers, headers, basic_auth, bearer_token)?;
        if !allow_cleartext_credentials && !self.inner.allow_cleartext_credentials {
            self.check_cleartext(&route, &headers)?;
        }
        self.check_trust_anchors(&route)?;
        let method = match method {
            UploadMethod::Post => Method::POST,
            UploadMethod::Put => Method::PUT,
            UploadMethod::Delete => Method::DELETE,
        };
        let (end, bytes, sha256) = match body.form {
            UploadForm::Bytes { bytes, sha256 } => (BodyEnd::whole(&bytes), Some(bytes), sha256),
            UploadForm::Channel(end) => (end, None, None),
        };
        if method == Method::DELETE && !bytes.as_ref().is_some_and(Bytes::is_empty) {
            return Err(Error::Fetch(format!(
                "the delete of {} carries a body, which a delete does not send: pass an empty \
                 UploadBody::bytes",
                target.describe()
            )));
        }
        let plan = UploadPlan {
            method,
            headers: &headers,
            bytes,
            sha256,
            max_response,
            response_timeout: response_timeout.unwrap_or(self.inner.progress_timeout),
        };
        let permit = self.inner.gate.acquire(priority).await;
        // This flag is set while hyper holds the request. The admission
        // deadline stops then, because the steps after the hand-over have
        // deadlines of their own.
        let handed = AtomicBool::new(false);
        let rounds = self.upload_rounds(&plan, &route, end, &handed);
        let mut uploaded = match self.inner.fetch_timeout {
            None => rounds.await?,
            Some(limit) => match before_hand_over(limit, &handed, rounds).await {
                Some(result) => result?,
                None => {
                    return Err(Error::Fetch(format!(
                        "upload of {} was not sent within {limit:?}",
                        target.describe()
                    )));
                }
            },
        };
        if !uploaded.withheld {
            uploaded.body.permit = Some(permit);
        }
        Ok(uploaded)
    }

    /// Tries each destination in turn, as [`rounds`](Fetcher::rounds) does for
    /// a fetch.
    ///
    /// The function repeats the round while the request is unsent and a
    /// destination failed retryably. A request that is sent ends the rounds,
    /// whatever its outcome.
    async fn upload_rounds(
        &self,
        plan: &UploadPlan<'_>,
        route: &Route<'_>,
        end: BodyEnd,
        handed: &AtomicBool,
    ) -> Result<Uploaded> {
        let destination_count = match route {
            Route::Mirrors { .. } => self.inner.mirrors.len(),
            Route::One(_) => 1,
        };
        let mut settled = vec![false; destination_count];
        let mut reported: Option<Error> = None;
        let mut definitive = false;
        let mut round = 0;
        // An attempt takes the body when it hands the request over. If the
        // request comes back unsent, the attempt puts the body back here.
        let mut body = Some(end);
        loop {
            let mut retryable = false;
            for (position, settled) in settled.iter_mut().enumerate() {
                if *settled {
                    continue;
                }
                let destination = match route {
                    Route::Mirrors { path, query } => {
                        Cow::Owned(self.inner.mirrors[position].destination(path, *query))
                    }
                    Route::One(destination) => Cow::Borrowed(destination),
                };
                match self
                    .upload_attempt(&destination, plan, &mut body, handed)
                    .await
                {
                    Ok(uploaded) => return Ok(uploaded),
                    Err(UploadFailure::Sent { url, message }) => {
                        return Err(Error::UploadInterrupted { url, message });
                    }
                    Err(UploadFailure::Unsent(Failure::Retry(e))) => {
                        retryable = true;
                        if reported.is_none() {
                            reported = Some(e);
                        }
                    }
                    Err(UploadFailure::Unsent(Failure::Fatal(e))) => {
                        *settled = true;
                        if !definitive {
                            reported = Some(e);
                            definitive = true;
                        }
                    }
                    Err(UploadFailure::Unsent(Failure::Final(e))) => return Err(e),
                }
            }
            if !retryable || round >= self.inner.max_retries {
                return Err(reported.expect("a failed round holds a failure"));
            }
            round += 1;
            rt::Timer::after(backoff(round)).await;
        }
    }

    /// Runs one upload against one destination, and follows the redirects of a
    /// body given whole.
    ///
    /// The first hop that hyper takes sends the request. So a failure on a
    /// later hop is final: the function reports an interrupted upload, and the
    /// rounds stop. The function drops a response that the upload does not
    /// deliver. This also drops a request body that did not end, and closes
    /// the connection of an HTTP/1.1 hop.
    async fn upload_attempt(
        &self,
        destination: &Destination,
        plan: &UploadPlan<'_>,
        body: &mut Option<BodyEnd>,
        handed: &AtomicBool,
    ) -> std::result::Result<Uploaded, UploadFailure> {
        let named = &destination.origin;
        let mut hop = Cow::Borrowed(destination);
        let mut headers = Cow::Borrowed(plan.headers);
        let mut signer = self.inner.signer.as_deref();
        let mut followed = 0u32;
        loop {
            let via = self.inner.proxies.via(&hop.origin);
            let key = PoolKey {
                origin: match via {
                    Via::Absolute(proxy) => proxy.endpoint.clone(),
                    Via::Direct | Via::Tunnel(_) => hop.origin.clone(),
                },
                identity: self.presents_identity(&hop.origin, named),
                proxied: matches!(via, Via::Absolute(_)),
            };
            let url = hop.url();
            let sent = self
                .upload_send(&hop, &key, via, plan, &headers, signer, body, handed)
                .await;
            let (response, protocol, request_end, reuse) = match sent {
                Ok(sent) => sent,
                Err(UploadFailure::Unsent(failure)) if followed > 0 => {
                    return Err(interrupted(url, failure.into_error().to_string()));
                }
                Err(failure) => return Err(failure),
            };
            let status = response.status();
            if let Some(bytes) = &plan.bytes
                && UPLOAD_REDIRECTS.contains(&status)
                && self.inner.max_redirects > 0
                && let Some(location) = response
                    .headers()
                    .get(hyper::header::LOCATION)
                    .and_then(|value| resolve_location(url, value))
            {
                if followed >= self.inner.max_redirects {
                    return Err(undelivered(
                        url,
                        Error::RedirectLimit {
                            url: url.to_string(),
                            hops: followed,
                        },
                    ));
                }
                let next =
                    redirect_destination(&hop, &location).map_err(|e| undelivered(url, e))?;
                if next.origin.tls && !self.inner.has_trust_anchors {
                    return Err(undelivered(url, no_trust_anchors(next.origin_url())));
                }
                // As for a fetch, a credential and the signer stay with the
                // origin that the route names.
                if next.origin != *named {
                    signer = None;
                }
                if next.origin != *named && headers.iter().any(|(name, _)| is_credential(name)) {
                    let scoped = headers
                        .iter()
                        .filter(|(name, _)| !is_credential(name))
                        .cloned()
                        .collect::<Vec<_>>();
                    headers = Cow::Owned(scoped);
                }
                hop = Cow::Owned(next);
                followed += 1;
                *body = Some(BodyEnd::whole(bytes));
                continue;
            }
            let coding = declared_coding(response.headers());
            let content_length = content_length(response.headers());
            let over = content_length.is_some_and(|length| length > plan.max_response);
            // An answer other than 2xx keeps its status and its headers, so a
            // refusal of the server reaches the caller as a refusal. Its body
            // is withheld, and the connection closes.
            let withheld = !status.is_success() && (coding.is_some() || over);
            if !withheld {
                if let Some(encoding) = coding {
                    return Err(undelivered(
                        url,
                        Error::ContentEncoded {
                            url: url.to_string(),
                            encoding,
                        },
                    ));
                }
                if over {
                    return Err(undelivered(
                        url,
                        Error::FetchTooLarge {
                            limit: plan.max_response,
                        },
                    ));
                }
            }
            let protocol = match response.version() {
                Version::HTTP_2 => Protocol::Http2,
                _ => protocol,
            };
            let (parts, incoming) = response.into_parts();
            // A withheld body ends at once. Its request body stops, and its
            // HTTP/1.1 connection does not go back to the pool, because the
            // rest of the response is still in flight.
            let (reuse, request_body) = if withheld {
                (None, None)
            } else {
                (reuse, Some(request_end))
            };
            return Ok(Uploaded {
                status: parts.status,
                headers: parts.headers,
                url: url.to_string(),
                withheld,
                body: Body {
                    incoming,
                    chunk: Bytes::new(),
                    received: 0,
                    max_size: Some(plan.max_response),
                    validators: Validators::default(),
                    content_length: if withheld { None } else { content_length },
                    protocol,
                    inner: self.inner.clone(),
                    counters: self.received.clone(),
                    key,
                    reuse,
                    permit: None,
                    done: withheld,
                    failed: None,
                    deadline: rt::Deadline::new(self.inner.progress_timeout),
                    waiting: false,
                    low_speed: None,
                    interrupted: None,
                    request_body,
                },
            });
        }
    }

    /// Takes or opens a connection for one upload hop, and hands the request
    /// to hyper.
    ///
    /// An upload takes the pooled HTTP/2 connection, or an idle HTTP/1.1
    /// connection from [`Inner::take_upload`]. If a pooled HTTP/1.1 connection
    /// fails before hyper writes the request, the function drops it. The hop
    /// then continues over a new connection and spends no round.
    ///
    /// A failure before the hand-over leaves the body in `body`. A request
    /// that hyper gives back unwritten also leaves it there. A body that failed
    /// before the hand-over is never sent. The stall window of the body starts
    /// at the hand-over, and [`answer`] then bounds the wait for the response
    /// head.
    ///
    /// The HTTP/1.1 connection comes back with the response if it can carry
    /// the next request after the response body ends. That is, hyper took the
    /// end of the request body before the response head arrived, and the
    /// response does not close the connection. In each other case, the
    /// connection closes at the end of the exchange.
    ///
    /// A `signer` signs the request over each connection that the function
    /// takes or opens, when the connection is ready and before the function
    /// starts the request. So a request that goes again over a new connection
    /// carries a new signature. If the signer fails, an HTTP/1.1 connection
    /// goes back to the pool unused.
    #[allow(clippy::too_many_arguments)]
    async fn upload_send(
        &self,
        hop: &Destination,
        key: &PoolKey,
        via: Via<'_>,
        plan: &UploadPlan<'_>,
        headers: &[(HeaderName, HeaderValue)],
        signer: Option<&dyn RequestSigner>,
        body: &mut Option<BodyEnd>,
        handed: &AtomicBool,
    ) -> std::result::Result<UploadResponse, UploadFailure> {
        let url = hop.url();
        let unsent = |failure: Failure| -> std::result::Result<UploadResponse, UploadFailure> {
            Err(UploadFailure::Unsent(failure))
        };
        let exchange = body
            .as_ref()
            .expect("an upload attempt holds its body until it sends it")
            .exchange
            .clone();
        if let Some(reason) = exchange.aborted() {
            return unsent(Failure::Fatal(not_sent(url, reason)));
        }
        let progress_timeout = self.inner.progress_timeout;
        let mut pooled = self.inner.take_upload(key);
        loop {
            // If a pooled HTTP/1.1 connection fails before hyper writes the
            // request, the server closed it while it was idle.
            let stale_h1 = matches!(pooled, Some((Sender::H1(_), _)));
            let (mut sender, idle_since) = match pooled.take() {
                Some(taken) => taken,
                None => {
                    let connect_timeout = self.inner.connect_timeout;
                    match within(connect_timeout, Box::pin(self.connect(key, via))).await {
                        Some(Ok(sender)) => (sender, None),
                        Some(Err(failure)) => return unsent(failure),
                        None => {
                            return unsent(Failure::Retry(connect_timed_out(
                                &key.origin,
                                via,
                                connect_timeout,
                            )));
                        }
                    }
                }
            };
            let protocol = match sender {
                Sender::H1(_) => Protocol::Http11,
                Sender::H2(_) => Protocol::Http2,
            };
            let ready = match &mut sender {
                Sender::H1(sender) => within(progress_timeout, sender.ready()).await,
                Sender::H2(sender) => within(progress_timeout, sender.ready()).await,
            };
            match ready {
                Some(Ok(())) => {}
                Some(Err(_)) if stale_h1 => continue,
                Some(Err(e)) => return unsent(Failure::Retry(transport(url, e))),
                None => return unsent(Failure::Retry(stalled(url, progress_timeout))),
            }
            // The signature is made when the connection is ready to carry the
            // request. So a connection that fails here costs no signature, and
            // the wait for a stream slot is not part of the age of the
            // signature.
            let signed_headers = match signer {
                None => Cow::Borrowed(headers),
                Some(signer) => {
                    // The signer reads a body given whole as the slice that
                    // the request sends, with no copy, and with the digest
                    // of the caller if it gave one. A streamed body is not
                    // known yet.
                    let payload = match (&plan.bytes, plan.sha256) {
                        _ if plan.method == Method::DELETE => SignPayload::Empty,
                        (Some(bytes), Some(sha256)) => SignPayload::Sha256 { bytes, sha256 },
                        (Some(bytes), None) => SignPayload::Bytes(bytes),
                        (None, _) => SignPayload::Streamed,
                    };
                    match signed(signer, &plan.method, hop, payload, headers) {
                        Ok(signed) => signed,
                        Err(failure) => {
                            // The connection carried no request, so it goes
                            // back to the pool as it came.
                            if let Sender::H1(sender) = sender {
                                let since = idle_since.unwrap_or_else(Instant::now);
                                self.inner.put_idle_h1(key, sender, since);
                            }
                            return unsent(failure);
                        }
                    }
                }
            };
            let mut head = match self.upload_head(hop, plan, &signed_headers, protocol, via) {
                Ok(head) => head,
                Err(e) => return unsent(Failure::Fatal(e)),
            };
            let empty = match exchange.hand_over(progress_timeout) {
                Ok(empty) => empty,
                Err(reason) => return unsent(Failure::Fatal(not_sent(url, reason))),
            };
            // A `POST` or a `PUT` whose body is at its end states its length.
            // hyper writes no length for an HTTP/1.1 request at the end of its
            // body. Each of the two methods defines content, so a server that
            // waits for the framing reads `0`. A `DELETE` sends no body.
            if empty && plan.method != Method::DELETE {
                head.headers_mut()
                    .insert(hyper::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
            }
            let end = body
                .take()
                .expect("an upload attempt holds its body until it sends it");
            let request = head.map(|()| RequestBody::Upload(end));
            handed.store(true, Ordering::Relaxed);
            let window = plan.response_timeout;
            let (answered, h1) = match sender {
                Sender::H1(mut sender) => {
                    let answered =
                        answer(sender.try_send_request(request), &exchange, window).await;
                    (answered, Some(sender))
                }
                Sender::H2(mut sender) => {
                    let answered =
                        answer(sender.try_send_request(request), &exchange, window).await;
                    (answered, None)
                }
            };
            let response = match answered {
                Answer::Sent(Ok(response)) => response,
                Answer::Sent(Err(mut e)) => {
                    let Some(request) = e.take_message() else {
                        exchange.cut();
                        return Err(interrupted(url, with_cause(&e.into_error())));
                    };
                    // hyper gives the request back if the connection failed
                    // before hyper wrote a part of it. So the body is whole,
                    // and the request is unsent.
                    exchange.withdraw();
                    if let RequestBody::Upload(end) = request.into_body() {
                        *body = Some(end);
                    }
                    handed.store(false, Ordering::Relaxed);
                    if stale_h1 {
                        continue;
                    }
                    return unsent(Failure::Retry(transport(url, e.into_error())));
                }
                Answer::Aborted(reason) => return Err(interrupted(url, reason)),
                Answer::Silent(window) => {
                    return Err(interrupted(
                        url,
                        format!("no response within {window:?} of the end of the request body"),
                    ));
                }
            };
            // A head that arrived before hyper took the end of the body is an
            // early answer. The body is cut when the response ends, and the
            // cut closes the connection.
            let reuse = h1.filter(|_| exchange.has_ended() && !closes(&response));
            return Ok((response, protocol, RequestEnd { exchange }, reuse));
        }
    }

    /// Starts the upload request against `destination`, in the form that
    /// `protocol` and `via` give it.
    ///
    /// [`request_head`](Fetcher::request_head) does the same for a fetch.
    fn upload_head(
        &self,
        destination: &Destination,
        plan: &UploadPlan<'_>,
        headers: &[(HeaderName, HeaderValue)],
        protocol: Protocol,
        via: Via<'_>,
    ) -> Result<Request<()>> {
        self.request_head(plan.method.clone(), destination, headers, protocol, via)?
            .body(())
            .map_err(|e| Error::Fetch(format!("invalid request for {}: {e}", destination.url())))
    }

    /// Builds the GET for `request` against `destination`, with `headers` and
    /// the validators of the request.
    fn build_request(
        &self,
        destination: &Destination,
        request: &FetchRequest<'_>,
        headers: &[(HeaderName, HeaderValue)],
        protocol: Protocol,
        via: Via<'_>,
    ) -> Result<Request<RequestBody>> {
        let mut builder = self.request_head(Method::GET, destination, headers, protocol, via)?;
        if let Some(validators) = request.validators {
            if let Some(etag) = &validators.etag {
                builder = builder.header(hyper::header::IF_NONE_MATCH, etag);
            }
            if let Some(last_modified) = &validators.last_modified {
                builder = builder.header(hyper::header::IF_MODIFIED_SINCE, last_modified);
            }
        }
        builder
            .body(RequestBody::Empty)
            .map_err(|e| Error::Fetch(format!("invalid request for {}: {e}", destination.url())))
    }

    /// Starts the request of `method` against `destination`, with `headers`.
    ///
    /// An HTTP/1.1 request carries the origin-form target and a `Host` header,
    /// as an origin server expects. The absolute form is for proxy requests,
    /// and a plain static-file server answers 404 to it. An HTTP/2 request
    /// carries the absolute URL, and hyper fills the `:scheme` and
    /// `:authority` pseudo-headers from it.
    ///
    /// A request to a cleartext origin over a proxy connection carries the
    /// absolute form, which tells the proxy where to send it. Its `Host`
    /// header names the origin.
    ///
    /// The request also carries the credential of the proxy, if the merged
    /// headers hold no `Proxy-Authorization`. A `Proxy-Authorization` header
    /// that the caller set states the value for the proxy. Two values of one
    /// name give the proxy two answers to one question.
    ///
    /// A `CONNECT` tunnel carries the proxy credential of the fetcher on the
    /// `CONNECT` alone. So the request over the tunnel is the request that a
    /// direct connection sends.
    fn request_head(
        &self,
        method: Method,
        destination: &Destination,
        headers: &[(HeaderName, HeaderValue)],
        protocol: Protocol,
        via: Via<'_>,
    ) -> Result<hyper::http::request::Builder> {
        let absolute = protocol == Protocol::Http2 || matches!(via, Via::Absolute(_));
        let url = if absolute {
            destination.url()
        } else {
            destination.target()
        };
        let uri =
            Uri::try_from(url).map_err(|e| Error::Fetch(format!("invalid url {url}: {e}")))?;
        let mut builder = Request::builder().method(method).uri(uri);
        if protocol == Protocol::Http11 {
            builder = builder.header(hyper::header::HOST, &destination.authority);
        }
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        if let Via::Absolute(proxy) = via
            && let Some(credential) = &proxy.credential
            && !headers
                .iter()
                .any(|(name, _)| *name == hyper::header::PROXY_AUTHORIZATION)
        {
            builder = builder.header(hyper::header::PROXY_AUTHORIZATION, credential);
        }
        Ok(builder)
    }

    /// Opens a connection for `key`, and selects the protocol over ALPN if the
    /// origin is TLS.
    ///
    /// The key states the client configuration of the handshake. So a
    /// connection that presents the client certificate and a connection that
    /// presents none are two pool entries. The pool gives neither to the hop
    /// of the other.
    ///
    /// `via` states what the connection reaches. The key of a proxied
    /// cleartext origin is the proxy endpoint. So the socket goes where the key
    /// names, and the requests over it carry the absolute form.
    ///
    /// The key of a tunneled TLS origin is the origin. So the socket goes to
    /// the proxy, and the handshake runs over the `CONNECT` exchange.
    ///
    /// A failure states if another attempt can get a different result. A proxy
    /// that refuses the tunnel with 407 refuses the credential of the fetcher,
    /// and no round of retries changes it. Each other failure is retryable.
    async fn connect(&self, key: &PoolKey, via: Via<'_>) -> std::result::Result<Sender, Failure> {
        let origin = &key.origin;
        let endpoint = match via {
            Via::Tunnel(proxy) => &proxy.endpoint,
            Via::Direct | Via::Absolute(_) => origin,
        };
        let tcp = rt::TcpStream::connect(&endpoint.host, endpoint.port)
            .await
            .map_err(|e| {
                Failure::Retry(Error::Fetch(match via {
                    Via::Direct => {
                        format!("connect to {}:{} failed: {e}", endpoint.host, endpoint.port)
                    }
                    Via::Absolute(proxy) | Via::Tunnel(proxy) => {
                        format!("connect to the proxy {} failed: {e}", proxy.named)
                    }
                }))
            })?;
        if !origin.tls {
            // Cleartext HTTP/2 needs prior knowledge or an upgrade. The
            // fetcher uses neither. So a cleartext origin speaks HTTP/1.1,
            // over a proxy and over a direct connection.
            return self
                .handshake_h1(key, FuturesIo::new(tcp))
                .await
                .map_err(Failure::Retry);
        }
        let tcp = match via {
            Via::Tunnel(proxy) => self.tunnel(proxy, origin, tcp).await?,
            Via::Direct | Via::Absolute(_) => tcp,
        };
        let server_name =
            rustls::pki_types::ServerName::try_from(origin.host.clone()).map_err(|e| {
                Failure::Retry(Error::Fetch(format!(
                    "invalid server name {}: {e}",
                    origin.host
                )))
            })?;
        let config = if key.identity {
            &self.inner.tls.with_identity
        } else {
            &self.inner.tls.without_identity
        };
        let stream = futures_rustls::TlsConnector::from(config.clone())
            .connect(server_name, tcp)
            .await
            .map_err(|e| {
                Failure::Retry(Error::Fetch(format!(
                    "tls handshake with {} failed: {e}",
                    origin.host
                )))
            })?;
        let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
        let io = FuturesIo::new(stream);
        if h2 {
            self.handshake_h2(key, io).await.map_err(Failure::Retry)
        } else {
            self.handshake_h1(key, io).await.map_err(Failure::Retry)
        }
    }

    /// Asks `proxy` for a tunnel to `origin`, and returns the socket of the
    /// tunnel.
    ///
    /// The `CONNECT` goes over the HTTP/1.1 client of hyper, which reads the
    /// answer and gives the socket back. A 2xx to a `CONNECT` is an upgrade,
    /// and the upgraded I/O is the stream of the handshake. The connection
    /// future delivers it, so the future runs in its own task and ends with the
    /// upgrade.
    ///
    /// Bytes in the buffer after the response fail the connect. Nothing comes
    /// after a `CONNECT` response before the client speaks. So a proxy that
    /// sent bytes does not speak the protocol of the tunnel. A TLS handshake
    /// over that stream starts to read after those bytes.
    async fn tunnel(
        &self,
        proxy: &ProxyEndpoint,
        origin: &Origin,
        tcp: rt::TcpStream,
    ) -> std::result::Result<rt::TcpStream, Failure> {
        let refused = |what: String| Failure::Retry(Error::Fetch(what));
        let authority = connect_authority(origin);
        let host = HeaderValue::try_from(&authority).map_err(|_| {
            Failure::Fatal(Error::Fetch(format!(
                "the proxy {} cannot be asked to reach {authority}, which is not a usable host",
                proxy.named
            )))
        })?;
        let mut builder = Request::builder()
            .method(Method::CONNECT)
            .uri(&authority)
            .header(hyper::header::HOST, host);
        if let Some(credential) = &proxy.credential {
            builder = builder.header(hyper::header::PROXY_AUTHORIZATION, credential);
        }
        let request = builder.body(RequestBody::Empty).map_err(|e| {
            refused(format!(
                "the connect request to the proxy {} for {authority} is invalid: {e}",
                proxy.named
            ))
        })?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(FuturesIo::new(tcp))
            .await
            .map_err(|e| {
                refused(format!(
                    "http/1.1 handshake with the proxy {} failed: {e}",
                    proxy.named
                ))
            })?;
        // The connection future delivers the upgrade, so it runs beside the
        // request. The future and its task end with the upgrade.
        drop(rt::spawn(async move {
            let _ = connection.with_upgrades().await;
        }));
        let response = async {
            sender.ready().await?;
            sender.send_request(request).await
        }
        .await
        .map_err(|e| {
            refused(format!(
                "connect to {authority} through the proxy {} failed: {e}",
                proxy.named
            ))
        })?;
        let status = response.status();
        if !status.is_success() {
            let message = format!(
                "the proxy {} answered the connect to {authority} with {}",
                proxy.named,
                status.as_u16()
            );
            // A 407 refuses the credential of the fetcher, or the absence of
            // one. Each round of retries offers the same again.
            return Err(match status {
                StatusCode::PROXY_AUTHENTICATION_REQUIRED => Failure::Fatal(Error::Fetch(message)),
                _ => Failure::Retry(Error::Fetch(message)),
            });
        }
        let upgraded = hyper::upgrade::on(response).await.map_err(|e| {
            refused(format!(
                "the proxy {} accepted the connect to {authority} without tunneling it: {e}",
                proxy.named
            ))
        })?;
        let parts = upgraded
            .downcast::<FuturesIo<rt::TcpStream>>()
            .map_err(|_| {
                refused(format!(
                    "the tunnel through the proxy {} to {authority} is not the socket it was \
                     opened over",
                    proxy.named
                ))
            })?;
        if !parts.read_buf.is_empty() {
            return Err(refused(format!(
                "the proxy {} sent {} bytes after the connect to {authority}, which nothing may \
                 follow",
                proxy.named,
                parts.read_buf.len()
            )));
        }
        Ok(parts.io.into_inner())
    }

    /// Completes an HTTP/1.1 handshake, and runs the connection in its own
    /// task.
    async fn handshake_h1<S>(&self, key: &PoolKey, io: FuturesIo<S>) -> Result<Sender>
    where
        S: AsyncRead + AsyncWrite + WriteVectored + Send + Unpin + 'static,
    {
        let (sender, connection) =
            hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| {
                    Error::Fetch(format!(
                        "http/1.1 handshake with {} failed: {e}",
                        key.origin.host
                    ))
                })?;
        drop(rt::spawn(async move {
            // The connection ends when the last sender drops or the peer closes
            // it. An error here shows on the next request over it.
            let _ = connection.await;
        }));
        Ok(Sender::H1(sender))
    }

    /// Completes an HTTP/2 handshake, runs the connection in its own task, and
    /// puts it in the pool.
    ///
    /// The next requests to this origin multiplex over the connection. The
    /// function opens the connection through the builder of hyper. Only the
    /// builder sets the flow-control windows and the keep-alive ping.
    async fn handshake_h2<S>(&self, key: &PoolKey, io: FuturesIo<S>) -> Result<Sender>
    where
        S: AsyncRead + AsyncWrite + WriteVectored + Send + Unpin + 'static,
    {
        let (sender, connection) = hyper::client::conn::http2::Builder::new(RtExecutor)
            .timer(RtTimer)
            .initial_stream_window_size(H2_STREAM_WINDOW)
            .initial_connection_window_size(self.inner.h2_connection_window)
            .keep_alive_interval(H2_KEEP_ALIVE_INTERVAL)
            .keep_alive_timeout(H2_KEEP_ALIVE_TIMEOUT)
            .handshake(io)
            .await
            .map_err(|e| {
                Error::Fetch(format!(
                    "http/2 handshake with {} failed: {e}",
                    key.origin.host
                ))
            })?;
        drop(rt::spawn(async move {
            let _ = connection.await;
        }));
        self.inner.put_h2(key, sender.clone());
        Ok(Sender::H2(sender))
    }
}

impl Inner {
    /// Returns a pooled connection for `key`, if one is still usable.
    ///
    /// An HTTP/1.1 connection comes with the instant at which it became idle.
    /// [`Inner::put_idle_h1`] takes that instant back if the connection
    /// carried no request.
    fn take_conn(&self, key: &PoolKey) -> Option<(Sender, Option<Instant>)> {
        let mut pool = self.pool.lock().expect("fetcher pool mutex");
        let entry = pool.get_mut(key)?;
        if let Some(h2) = &entry.h2 {
            if h2.is_closed() {
                entry.h2 = None;
            } else {
                return Some((Sender::H2(h2.clone()), None));
            }
        }
        while let Some(h1) = entry.h1.pop() {
            if !h1.sender.is_closed() {
                return Some((Sender::H1(h1.sender), Some(h1.since)));
            }
        }
        None
    }

    /// Returns a pooled connection that an upload can take for `key`.
    ///
    /// This is the HTTP/2 connection. If there is none, it is the HTTP/1.1
    /// connection that became idle last, if it became idle less than
    /// [`UPLOAD_IDLE`] ago.
    ///
    /// A server can close an idle connection at any time. If hyper began to
    /// write a request over a connection that the server closed, the request
    /// counts as sent. A server closes an idle connection at the end of its
    /// idle timeout, which is seconds or more. So the server keeps a connection
    /// that became idle a short time ago.
    ///
    /// An older idle connection stays in the pool for a fetch. If a fetch over
    /// it fails, the fetcher sends the fetch again.
    ///
    /// An HTTP/1.1 connection comes with the instant at which it became idle,
    /// as [`Inner::take_conn`] gives it.
    fn take_upload(&self, key: &PoolKey) -> Option<(Sender, Option<Instant>)> {
        let mut pool = self.pool.lock().expect("fetcher pool mutex");
        let entry = pool.get_mut(key)?;
        match &entry.h2 {
            Some(h2) if h2.is_closed() => entry.h2 = None,
            Some(h2) => return Some((Sender::H2(h2.clone()), None)),
            None => {}
        }
        while let Some(h1) = entry.h1.last() {
            if h1.sender.is_closed() {
                entry.h1.pop();
                continue;
            }
            if h1.since.elapsed() >= UPLOAD_IDLE {
                return None;
            }
            return entry
                .h1
                .pop()
                .map(|h1| (Sender::H1(h1.sender), Some(h1.since)));
        }
        None
    }

    /// Returns an idle HTTP/1.1 connection to the pool.
    ///
    /// The function finds the existing entry of an origin by reference. A new
    /// entry needs a key of its own, and the host string of that key is an
    /// allocation. The lookup by reference keeps that allocation off the warm
    /// path of each object fetch.
    fn put_h1(&self, key: &PoolKey, sender: H1Sender) {
        self.put_idle_h1(key, sender, Instant::now());
    }

    /// Returns an HTTP/1.1 connection to the pool that has been idle since
    /// `since`.
    ///
    /// A connection that the fetcher took and did not use goes back with the
    /// instant at which it became idle. So [`Inner::take_upload`] reads its
    /// true idle time.
    fn put_idle_h1(&self, key: &PoolKey, sender: H1Sender, since: Instant) {
        if sender.is_closed() {
            return;
        }
        let idle = IdleH1 { sender, since };
        let mut pool = self.pool.lock().expect("fetcher pool mutex");
        if let Some(entry) = pool.get_mut(key) {
            entry.h1.push(idle);
            return;
        }
        pool.entry(key.clone()).or_default().h1.push(idle);
    }

    /// Records the HTTP/2 connection of the origin, and keeps a usable
    /// connection that is already in the pool.
    ///
    /// Two concurrent connects to one origin each complete a handshake. The
    /// connection that loses the race serves only the request that opened it,
    /// and closes with that request. So it does not replace a pooled entry
    /// that other requests multiplex over. A replaced entry stays open, with
    /// no pool reference, until its own senders drop.
    ///
    /// The function finds the existing entry of an origin by reference, as
    /// [`Inner::put_h1`] does.
    fn put_h2(&self, key: &PoolKey, sender: H2Sender) {
        let mut pool = self.pool.lock().expect("fetcher pool mutex");
        if let Some(entry) = pool.get_mut(key) {
            match &entry.h2 {
                Some(pooled) if !pooled.is_closed() => {}
                _ => entry.h2 = Some(sender),
            }
            return;
        }
        pool.entry(key.clone()).or_default().h2 = Some(sender);
    }
}

/// A fetch that starts again if its body fails in transit.
///
/// A body fails in transit in these cases:
///
/// - the connection reports an error
/// - the peer stays silent past the
///   [`progress_timeout`](FetcherOptions::progress_timeout) window
/// - the transfer is slower than the
///   [`low_speed`](FetcherOptions::low_speed) rule allows.
///
/// Each refetch spends one repeat of
/// [`max_retries`](FetcherOptions::max_retries), the count that also limits
/// the rounds of the fetch. So the rounds of each fetch and the refetches
/// between them share one budget. A refetch asks for the whole body again,
/// from the first destination, and sends no `Range` request.
///
/// A body that fails in another way is not fetched again, because another
/// fetch fails in the same way. Examples are the size cap and a failure of
/// the consumer, such as a checksum mismatch.
pub struct Refetch<'f, 'r> {
    fetcher: &'f Fetcher,
    request: FetchRequest<'r>,
    /// The repeats left in the budget.
    left: u32,
    /// The repeats spent. The next delay doubles from this count.
    round: u32,
    /// The flag that the body of the latest fetch sets if it fails in transit.
    interrupted: Arc<AtomicBool>,
}

impl Refetch<'_, '_> {
    /// Fetches the request, with the rest of the budget for its rounds.
    ///
    /// # Errors
    ///
    /// This method returns the errors that [`Fetcher::fetch`] returns.
    pub async fn fetch(&mut self) -> Result<Fetched> {
        self.interrupted.store(false, Ordering::Relaxed);
        let (mut fetched, used) = self
            .fetcher
            .fetch_budgeted(&self.request, self.left)
            .await?;
        self.left -= used;
        self.round += used;
        if let Fetched::Body(body) = &mut fetched {
            body.interrupted = Some(self.interrupted.clone());
        }
        Ok(fetched)
    }

    /// Prepares the next refetch, or returns `error` if no refetch applies.
    ///
    /// `error` is the error that ended the consumer of the latest body, in the
    /// error type of the caller. If that body failed in transit and a repeat
    /// is left, the method spends the repeat. It then waits for the backoff
    /// delay before the next [`fetch`](Refetch::fetch).
    ///
    /// The consumer drops the body before it calls this method. So the delay
    /// holds no connection and no admission permit.
    ///
    /// # Errors
    ///
    /// Returns `error` as it is if the latest body did not fail in transit, or
    /// if no repeat is left.
    pub async fn retry<E>(&mut self, error: E) -> std::result::Result<(), E> {
        if !self.interrupted.load(Ordering::Relaxed) || self.left == 0 {
            return Err(error);
        }
        self.left -= 1;
        self.round += 1;
        rt::Timer::after(backoff(self.round)).await;
        Ok(())
    }
}

/// The result of one attempt.
#[allow(clippy::large_enum_variant)]
enum Attempted {
    Body(Body),
    NotModified,
}

/// A failure that ends a body. Each later read gives it again.
struct Failed {
    kind: std::io::ErrorKind,
    message: String,
}

impl Failed {
    fn error(&self) -> std::io::Error {
        std::io::Error::new(self.kind, self.message.clone())
    }
}

/// The response body of a fetch or of an upload.
///
/// A read gives the bytes of the response in bounded chunks. The body releases
/// its connection and the admission permit when it reaches its end or is
/// dropped. A body dropped before its end closes an HTTP/1.1 connection and
/// resets an HTTP/2 stream, because the rest of the response is still in
/// flight.
///
/// # Failures
///
/// A failure ends the body. The failed read and each later read fail with the
/// same error. So a consumer that reads past a failure never gets a clean end
/// of stream, and cannot take a truncated object for a complete one. The
/// failures and their error kinds are:
///
/// - the size cap: [`FileTooLarge`](std::io::ErrorKind::FileTooLarge)
/// - the progress window and the low-speed rule:
///   [`TimedOut`](std::io::ErrorKind::TimedOut)
/// - a transport failure: [`Other`](std::io::ErrorKind::Other).
///
/// A failure releases neither the connection nor the permit. The drop of the
/// body releases both.
pub struct Body {
    incoming: Incoming,
    /// Bytes received from the connection and not yet copied to the caller.
    chunk: Bytes,
    /// The bytes taken from the connection. The caller is behind this count by
    /// the bytes still in `chunk`. The size cap applies to this count.
    received: u64,
    max_size: Option<u64>,
    validators: Validators,
    content_length: Option<u64>,
    protocol: Protocol,
    inner: Arc<Inner>,
    /// The counters of the fetcher handle that made the request. Each data
    /// frame adds its bytes to each of them.
    counters: Arc<[Arc<AtomicU64>]>,
    /// The pool entry of the connection of this body. The connection goes back
    /// to this entry.
    key: PoolKey,
    /// The HTTP/1.1 connection to return to the pool at the end of the body.
    reuse: Option<H1Sender>,
    /// The admission permit, which the body holds while it is in flight.
    permit: Option<Permit>,
    done: bool,
    /// The failure that ended the body, if one did.
    failed: Option<Failed>,
    /// The time that the peer can stay silent while a read waits for it.
    deadline: rt::Deadline,
    /// `true` while the window runs, from the read that finds nothing until
    /// the next frame arrives.
    ///
    /// The window measures the silence since a read wanted bytes. It keeps
    /// running also when no read is outstanding. A body that no read found
    /// empty is not on the clock.
    waiting: bool,
    /// The low-speed rule of the body, if the fetcher has one.
    low_speed: Option<Monitor>,
    /// The flag that reports a failure in transit to a [`Refetch`], which
    /// fetches the body again. The size cap is not a failure in transit,
    /// because another fetch of the body grows past the cap in the same way.
    interrupted: Option<Arc<AtomicBool>>,
    /// The request body of an upload. It fails when this body ends, or when
    /// this body is dropped before the request body ends.
    request_body: Option<RequestEnd>,
}

/// The low-speed state of one body: the delivered bytes, the last samples of
/// that count, and the time below the limit.
struct Monitor {
    rule: LowSpeed,
    /// The bytes that the body delivered since its first read.
    counted: u64,
    /// `counted` at the last [`RATE_SPAN`] samples. The slot of the next
    /// sample holds the oldest sample. A slot that no sample filled holds the
    /// count at the first read, which is zero.
    samples: [u64; RATE_SPAN],
    /// The samples taken since the first read.
    taken: u64,
    /// The whole seconds for which the rate stayed at or below the limit, or
    /// `None` while the rate is above it. A body starts below the limit, at
    /// zero.
    below: Option<u64>,
    /// The time to the next sample.
    deadline: rt::Deadline,
    /// `true` after the measurement starts, which is at the first read.
    started: bool,
}

impl Monitor {
    /// Creates the monitor for `rule`. The measurement starts at the first
    /// read.
    fn new(rule: LowSpeed) -> Monitor {
        Monitor {
            rule,
            counted: 0,
            samples: [0; RATE_SPAN],
            taken: 0,
            below: Some(0),
            deadline: rt::Deadline::new(SAMPLE_PERIOD),
            started: false,
        }
    }

    /// Returns `true` if the rate stayed below the limit for the time of the
    /// rule.
    ///
    /// Each expiry of the timer takes one sample. If the next sample is not
    /// due, the poll leaves the timer to wake the task at the due time.
    fn below_rate(&mut self, cx: &mut Context<'_>) -> bool {
        while self.deadline.poll_expired(cx).is_ready() {
            if self.sample() {
                return true;
            }
            self.deadline.restart();
        }
        false
    }

    /// Takes one sample, and returns `true` if the rate now stayed below the
    /// limit for the time of the rule.
    fn sample(&mut self) -> bool {
        self.taken += 1;
        let slot = (self.taken % RATE_SPAN as u64) as usize;
        let span = self.taken.min(RATE_SPAN as u64);
        let carried = self.counted - self.samples[slot];
        self.samples[slot] = self.counted;
        // A sample of exactly the limit counts as below it, as in the `ostree`
        // command. The samples of that command span a little more than their
        // whole seconds.
        if carried > u64::from(self.rule.limit) * span {
            self.below = None;
            return false;
        }
        let below = self.below.map_or(0, |seconds| seconds + 1);
        self.below = Some(below);
        Duration::from_secs(below) >= self.rule.time
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Body")
            .field("protocol", &self.protocol)
            .field("content_length", &self.content_length)
            .field("received", &self.received)
            .finish_non_exhaustive()
    }
}

impl Body {
    /// Returns the validators to send on the next fetch of this target.
    pub fn validators(&self) -> &Validators {
        &self.validators
    }

    /// Returns the `Content-Length` that the response declared, if it declared
    /// one.
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// Returns the HTTP version that carried the response.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns the number of bytes that the body took from the connection.
    ///
    /// The body takes a frame whole and gives it out in as many reads as the
    /// buffers of the caller need. So this count can be up to one frame ahead
    /// of the bytes that the caller read. The size cap applies to this count.
    /// A caller that needs the count of delivered bytes counts them in its own
    /// read loop.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// Latches a failure that ends the body, and returns it.
    ///
    /// The body keeps the connection and the permit, so the drop releases
    /// them. The drop closes the connection, because a response still in
    /// flight does not go back to the pool.
    fn fail(&mut self, kind: std::io::ErrorKind, message: String) -> std::io::Error {
        let failed = Failed { kind, message };
        let error = failed.error();
        self.failed = Some(failed);
        error
    }

    /// Latches a failure in transit, and returns it. A [`Refetch`] can repeat
    /// the fetch for such a failure.
    fn interrupt(&mut self, kind: std::io::ErrorKind, message: String) -> std::io::Error {
        if let Some(interrupted) = &self.interrupted {
            interrupted.store(true, Ordering::Relaxed);
        }
        self.fail(kind, message)
    }

    /// Returns the failure of the low-speed rule, if the rate stayed at or
    /// below the limit for the time of the rule.
    ///
    /// Returns `None` while the rate holds, or if no rule applies.
    fn poll_low_speed(&mut self, cx: &mut Context<'_>) -> Option<std::io::Error> {
        let monitor = self.low_speed.as_mut()?;
        if !monitor.below_rate(cx) {
            return None;
        }
        let LowSpeed { limit, time } = monitor.rule;
        Some(self.interrupt(
            std::io::ErrorKind::TimedOut,
            format!("fetched body averaged below {limit} bytes per second for {time:?}"),
        ))
    }
}

/// The read trait of `futures-io`.
impl AsyncRead for Body {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let me = self.get_mut();
        if let Some(failed) = &me.failed {
            return Poll::Ready(Err(failed.error()));
        }
        // The low-speed measurement starts at the first read. So the time for
        // which a body waits for its consumer before that read is not counted.
        if let Some(monitor) = &mut me.low_speed
            && !monitor.started
        {
            monitor.deadline.restart();
            monitor.started = true;
        }
        loop {
            if !me.chunk.is_empty() {
                let n = me.chunk.len().min(buf.len());
                buf[..n].copy_from_slice(&me.chunk[..n]);
                me.chunk = me.chunk.slice(n..);
                return Poll::Ready(Ok(n));
            }
            if me.done {
                return Poll::Ready(Ok(0));
            }
            let frame = match Pin::new(&mut me.incoming).poll_frame(cx) {
                Poll::Ready(frame) => frame,
                Poll::Pending => {
                    // Nothing arrived since the last frame. So the read fails
                    // when the progress window runs out, or when the rate
                    // stayed below the low-speed limit for the time of the rule.
                    if let Some(error) = me.poll_low_speed(cx) {
                        return Poll::Ready(Err(error));
                    }
                    if !me.waiting {
                        me.deadline.restart();
                        me.waiting = true;
                    }
                    return match me.deadline.poll_expired(cx) {
                        Poll::Ready(()) => {
                            let window = me.deadline.window();
                            Poll::Ready(Err(me.interrupt(
                                std::io::ErrorKind::TimedOut,
                                format!("fetched body delivered nothing for {window:?}"),
                            )))
                        }
                        Poll::Pending => Poll::Pending,
                    };
                }
            };
            match frame {
                Some(Ok(frame)) => {
                    // The peer delivered. The window stops until the next read
                    // finds nothing.
                    me.waiting = false;
                    // Trailers carry no payload, so the loop polls again for
                    // data.
                    if let Ok(data) = frame.into_data() {
                        me.received += data.len() as u64;
                        for counter in me.counters.iter() {
                            counter.fetch_add(data.len() as u64, Ordering::Relaxed);
                        }
                        if let Some(limit) = me.max_size
                            && me.received > limit
                        {
                            return Poll::Ready(Err(me.fail(
                                std::io::ErrorKind::FileTooLarge,
                                format!("fetched body exceeds the {limit}-byte cap"),
                            )));
                        }
                        if let Some(monitor) = &mut me.low_speed {
                            monitor.counted += data.len() as u64;
                        }
                        me.chunk = data;
                        if let Some(error) = me.poll_low_speed(cx) {
                            return Poll::Ready(Err(error));
                        }
                    }
                }
                Some(Err(e)) => {
                    // hyper reports a body error once, and then reports the end
                    // of the body. Without the latch, the next read returns a
                    // clean end of stream for a truncated object.
                    let message = with_cause(&e);
                    return Poll::Ready(Err(me.interrupt(std::io::ErrorKind::Other, message)));
                }
                None => {
                    me.done = true;
                    // The whole response arrived, so the connection can serve
                    // the next request. The response to an upload ends its
                    // request body, and hyper then stops the send of that body.
                    if let Some(sender) = me.reuse.take() {
                        me.inner.put_h1(&me.key, sender);
                    }
                    me.request_body = None;
                    me.permit = None;
                    return Poll::Ready(Ok(0));
                }
            }
        }
    }
}

/// The read trait of tokio.
#[cfg(feature = "tokio")]
impl rt::tokio_io::AsyncRead for Body {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut rt::tokio_io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        let n = ready!(AsyncRead::poll_read(self, cx, unfilled))?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

/// The writing end of a streamed [`UploadBody`], from
/// [`UploadBody::channel`].
///
/// The writer and the upload run together. So a caller writes from a task
/// other than the task that awaits [`Fetcher::upload`], or joins the two
/// futures.
///
/// # Frames
///
/// Writes fill a frame of 64 KiB. The writer gives a full frame to the
/// connection through a slot of one frame. If the slot is still full, a write
/// waits until hyper takes the frame in it.
///
/// - [`flush`](AsyncWrite::poll_flush) hands over a part-filled frame, and
///   waits until hyper takes it.
/// - [`close`](AsyncWrite::poll_close) hands over the rest, ends the body,
///   and waits until hyper takes the end.
///
/// A flush of less than 4 KiB hands over a copy of the bytes and keeps the
/// frame buffer. A larger frame moves to the connection as it is, and the next
/// write allocates the next buffer.
///
/// # Memory
///
/// The writer holds at most two frames: the frame that it fills and the frame
/// in the slot. The connection holds more for each upload in flight.
///
/// Over HTTP/1.1, hyper takes another frame while it holds fewer than 16
/// frames and less than 408 KiB. So it holds up to 472 KiB. Over HTTP/2, it
/// holds up to two frames.
///
/// # Stalls
///
/// After the upload hands its request to the connection, a frame can wait in
/// the slot for the [`progress_timeout`](FetcherOptions::progress_timeout) of
/// its fetcher. If it does, the wait fails with
/// [`io::ErrorKind::TimedOut`](std::io::ErrorKind::TimedOut), and the body
/// fails. Before the hand-over, a wait has no bound of its own.
///
/// # Failures
///
/// If the writer is dropped before close, the body fails. So hyper ends the
/// request unfinished, and the server never receives a truncated body as a
/// whole body. A writer dropped before the hand-over leaves the request
/// unsent.
///
/// A write fails with
/// [`io::ErrorKind::BrokenPipe`](std::io::ErrorKind::BrokenPipe) in these
/// cases:
///
/// - after close
/// - after the upload is done with the body
/// - after the response ended before the body.
///
/// A failure is latched: each later call fails in the same way.
pub struct UploadWriter {
    exchange: Arc<Exchange>,
    /// The frame that the writer fills. If a frame is handed over whole, the
    /// buffer has no capacity, and the next write allocates the next frame.
    buffer: Vec<u8>,
    /// The timer of the stall window. The first wait on a full slot after the
    /// hand-over arms it. If the timer fires before the frame in the slot
    /// waited the whole window, the writer arms it again for the rest.
    stall: Option<rt::Deadline>,
    /// The failure that ended the writer, if one did.
    failed: Option<Failed>,
}

impl std::fmt::Debug for UploadWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadWriter")
            .field("buffered", &self.buffer.len())
            .finish_non_exhaustive()
    }
}

/// The message of a write after the upload is done with the body.
const UPLOAD_ENDED: &str = "the upload of this body has ended";

impl UploadWriter {
    /// Returns `true` if the request of this body is handed over to a
    /// connection.
    ///
    /// The value becomes `true` at the hand-over. It becomes `false` again if
    /// the connection gives the request back unwritten, until the next round
    /// hands it over. A caller that counts the bytes that a request sent counts
    /// the bytes that it wrote after the hand-over.
    pub fn is_handed_over(&self) -> bool {
        self.exchange.lock().stall.is_some()
    }

    /// Latches a failure that ends the writer, and returns it.
    fn fail(&mut self, kind: std::io::ErrorKind, message: String) -> std::io::Error {
        let failed = Failed { kind, message };
        let error = failed.error();
        self.failed = Some(failed);
        error
    }

    /// Moves the buffer into the slot as the next frame, when the slot is
    /// free.
    ///
    /// The function copies a frame of less than [`SMALL_FRAME`] bytes, and
    /// keeps the buffer for the next frames. So a small frame that waits in the
    /// connection holds no more memory than its bytes. A larger frame moves as
    /// it is, and the next write allocates the next buffer.
    fn poll_hand_over(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut slot = self.exchange.lock();
        if slot.gone || slot.aborted.is_some() {
            drop(slot);
            return Poll::Ready(Err(
                self.fail(std::io::ErrorKind::BrokenPipe, UPLOAD_ENDED.into())
            ));
        }
        if slot.frame.is_some() {
            park(&mut slot.writer, cx);
            let end = slot.stall_end();
            drop(slot);
            return self.poll_stall(cx, end);
        }
        let frame = if self.buffer.len() < SMALL_FRAME {
            let frame = Bytes::copy_from_slice(&self.buffer);
            self.buffer.clear();
            frame
        } else {
            Bytes::from(std::mem::take(&mut self.buffer))
        };
        slot.frame = Some(frame);
        slot.restart_stall();
        let reader = slot.reader.take();
        drop(slot);
        wake(reader);
        Poll::Ready(Ok(()))
    }

    /// Waits until hyper takes the frame in the slot.
    fn poll_taken(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut slot = self.exchange.lock();
        if slot.gone || slot.aborted.is_some() {
            drop(slot);
            return Poll::Ready(Err(
                self.fail(std::io::ErrorKind::BrokenPipe, UPLOAD_ENDED.into())
            ));
        }
        if slot.frame.is_none() {
            return Poll::Ready(Ok(()));
        }
        park(&mut slot.writer, cx);
        let end = slot.stall_end();
        drop(slot);
        self.poll_stall(cx, end)
    }

    /// Polls the stall window of the frame in the slot. At `end`, the frame
    /// waited the whole window.
    ///
    /// The poll is pending while the window runs. It gives the failure of the
    /// body when the window runs out. Before the hand-over, `end` is `None`.
    /// The poll is then pending alone, and the take of the frame wakes the
    /// writer.
    fn poll_stall(
        &mut self,
        cx: &mut Context<'_>,
        mut end: Option<Instant>,
    ) -> Poll<std::io::Result<()>> {
        while let Some(at) = end {
            ready!(poll_until(&mut self.stall, cx, at));
            match self.exchange.check_stall() {
                Ok(message) => {
                    return Poll::Ready(Err(self.fail(std::io::ErrorKind::TimedOut, message)));
                }
                Err(later) => end = later,
            }
        }
        Poll::Pending
    }
}

/// The write trait of `futures-io`.
impl AsyncWrite for UploadWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        if let Some(failed) = &me.failed {
            return Poll::Ready(Err(failed.error()));
        }
        let slot = me.exchange.lock();
        let refused = if slot.gone || slot.aborted.is_some() {
            Some(UPLOAD_ENDED)
        } else if slot.closed {
            Some("the upload body is closed")
        } else {
            None
        };
        drop(slot);
        if let Some(message) = refused {
            return Poll::Ready(Err(me.fail(std::io::ErrorKind::BrokenPipe, message.into())));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if me.buffer.len() == UPLOAD_FRAME {
            ready!(me.poll_hand_over(cx))?;
        }
        if me.buffer.capacity() == 0 {
            me.buffer.reserve_exact(UPLOAD_FRAME);
        }
        let n = (UPLOAD_FRAME - me.buffer.len()).min(buf.len());
        me.buffer.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        if let Some(failed) = &me.failed {
            return Poll::Ready(Err(failed.error()));
        }
        if !me.buffer.is_empty() {
            ready!(me.poll_hand_over(cx))?;
        }
        me.poll_taken(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        if let Some(failed) = &me.failed {
            return Poll::Ready(Err(failed.error()));
        }
        if !me.buffer.is_empty() {
            ready!(me.poll_hand_over(cx))?;
        }
        let mut slot = me.exchange.lock();
        let reader = if slot.closed {
            None
        } else {
            slot.closed = true;
            slot.reader.take()
        };
        if slot.ended {
            drop(slot);
            wake(reader);
            return Poll::Ready(Ok(()));
        }
        if slot.gone || slot.aborted.is_some() {
            drop(slot);
            return Poll::Ready(Err(
                me.fail(std::io::ErrorKind::BrokenPipe, UPLOAD_ENDED.into())
            ));
        }
        park(&mut slot.writer, cx);
        // The stall window runs over a frame that waits in the slot. An empty
        // slot waits for hyper to poll the end, and that wait is no stall of
        // the body.
        let end = slot.stall_end();
        drop(slot);
        wake(reader);
        me.poll_stall(cx, end)
    }
}

/// The write trait of tokio.
#[cfg(feature = "tokio")]
impl rt::tokio_io::AsyncWrite for UploadWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_close(self, cx)
    }
}

impl Drop for UploadWriter {
    fn drop(&mut self) {
        let mut slot = self.exchange.lock();
        if slot.closed {
            return;
        }
        let wakers =
            slot.abort(|| "the upload writer was dropped before it closed the body".into());
        drop(slot);
        wakers.into_iter().for_each(wake);
    }
}

/// Returns `true` if a header name carries credentials, which no cleartext
/// destination gets.
///
/// The value of these three header names is a secret, whatever it holds. The
/// fetcher sends each other header as the caller wrote it, except `Host` and
/// the connection-layer names, which both layers refuse. A caller can put a
/// secret into such a header, and the fetcher cannot tell.
fn is_credential(name: &HeaderName) -> bool {
    *name == hyper::header::AUTHORIZATION
        || *name == hyper::header::PROXY_AUTHORIZATION
        || *name == hyper::header::COOKIE
}

/// Returns `true` if the connection layer sets a header of this name, so that
/// no caller can set it.
///
/// A `HeaderName` holds its name in lower case, and [`CONNECTION_HEADERS`] is
/// in lower case too.
fn is_connection_header(name: &HeaderName) -> bool {
    CONNECTION_HEADERS.contains(&name.as_str())
}

/// Returns the error for a layer that sets a header of the connection layer.
fn connection_header_refused(name: &HeaderName) -> Error {
    Error::Fetch(format!(
        "the {name} header is set by the connection layer, which frames the request and \
         holds its connection: drop the header"
    ))
}

/// Checks that a request path can go after the base path of a mirror.
///
/// A target is the base path with the request path added as written. So a `?`
/// or a `#` in that path is a delimiter. A `?` sends its tail as a query string
/// that the server matches on. A `#` and its tail drop out when the URL is
/// built, and the request asks for a different resource.
fn check_path(path: &str) -> Result<()> {
    if let Some(at) = path.find(['?', '#']) {
        let found = &path[at..=at];
        return Err(Error::Fetch(format!(
            "fetch path {path} carries {found}: a path holds no query and no fragment"
        )));
    }
    Ok(())
}

/// Checks that the query string `query` of a request for `path` can go after
/// the path.
///
/// The target is the path with `?` and the query added as written. So a `#`
/// in the query is a delimiter. The `#` and its tail drop out when the URL is
/// built, and the server gets a query other than the query of the caller.
fn check_query(path: &str, query: &str) -> Result<()> {
    if query.contains('#') {
        return Err(Error::Fetch(format!(
            "fetch query of {path}?{query} carries #: a query holds no fragment"
        )));
    }
    Ok(())
}

/// Returns the headers of one request: the headers of the fetcher, with the
/// headers of the request merged over them.
///
/// A request header replaces the fetcher header of the same name. The
/// credentials of the request replace the `Authorization` of the fetcher,
/// whichever of the two layers set it. These credentials are basic-auth
/// credentials or a bearer token, never both.
///
/// Two request headers of one name both reach the wire, as two fetcher headers
/// do. A request that adds no header and no credentials sends the list of the
/// fetcher as it is. Each object fetch takes this path.
///
/// A credential value is marked sensitive. So an HTTP/2 connection never adds
/// it to its header compression table.
fn merge_headers<'a>(
    fetcher: &'a [(HeaderName, HeaderValue)],
    extra: &[(String, String)],
    basic_auth: Option<&BasicAuth>,
    bearer_token: Option<&BearerToken>,
) -> Result<Cow<'a, [(HeaderName, HeaderValue)]>> {
    if extra.is_empty() && basic_auth.is_none() && bearer_token.is_none() {
        return Ok(Cow::Borrowed(fetcher));
    }
    if basic_auth.is_some() && bearer_token.is_some() {
        return Err(Error::Fetch(BASIC_AND_BEARER.into()));
    }
    let credential = usize::from(basic_auth.is_some() || bearer_token.is_some());
    let mut added = Vec::with_capacity(extra.len() + credential);
    for (name, value) in extra {
        let name = HeaderName::try_from(name.as_str())
            .map_err(|_| Error::Fetch(format!("invalid header name: {name}")))?;
        if name == hyper::header::HOST {
            return Err(Error::Fetch(HOST_COMES_FROM_THE_URL.into()));
        }
        if is_connection_header(&name) {
            return Err(connection_header_refused(&name));
        }
        if name == hyper::header::AUTHORIZATION && basic_auth.is_some() {
            return Err(Error::Fetch(AMBIGUOUS_AUTHORIZATION.into()));
        }
        if name == hyper::header::AUTHORIZATION && bearer_token.is_some() {
            return Err(Error::Fetch(AMBIGUOUS_BEARER.into()));
        }
        let mut value = HeaderValue::try_from(value.as_str())
            .map_err(|_| Error::Fetch(format!("invalid value for header {name}")))?;
        value.set_sensitive(is_credential(&name));
        added.push((name, value));
    }
    if let Some(auth) = basic_auth {
        added.push((hyper::header::AUTHORIZATION, basic_auth_value(auth)?));
    }
    if let Some(token) = bearer_token {
        added.push((hyper::header::AUTHORIZATION, bearer_value(token)?));
    }
    let mut headers = Vec::with_capacity(fetcher.len() + added.len());
    headers.extend(
        fetcher
            .iter()
            .filter(|(name, _)| !added.iter().any(|(replaced, _)| replaced == name))
            .cloned(),
    );
    headers.extend(added);
    Ok(Cow::Owned(headers))
}

/// Refuses a credential beside a request signer: basic-auth credentials if
/// `basic_auth` is `true`, a bearer token if `bearer_token` is `true`, or an
/// `Authorization` entry in `headers`.
///
/// A signature can set `Authorization`, as each of these can. So the signer
/// goes alone, and a choice of one sends a credential that the caller did not
/// choose. [`Fetcher::new`] refuses these on the fetcher, and a fetch and an
/// upload refuse them on a request.
fn refuse_beside_signer(
    headers: &[(String, String)],
    basic_auth: bool,
    bearer_token: bool,
) -> Result<()> {
    if basic_auth {
        return Err(Error::Fetch(SIGNER_AND_BASIC.into()));
    }
    if bearer_token {
        return Err(Error::Fetch(SIGNER_AND_BEARER.into()));
    }
    if headers.iter().any(|(name, _)| {
        HeaderName::try_from(name.as_str()).is_ok_and(|name| name == hyper::header::AUTHORIZATION)
    }) {
        return Err(Error::Fetch(SIGNER_AND_AUTHORIZATION.into()));
    }
    Ok(())
}

/// Returns the [`SignRequest`] of one request of `method` to `hop`, with
/// `payload`.
///
/// The path and the query come from the origin-form target of the hop, which
/// splits at its first `?`. The authority is the text of the `Host` header.
fn sign_request<'a>(
    method: &'a Method,
    hop: &'a Destination,
    payload: SignPayload<'a>,
) -> SignRequest<'a> {
    let target = hop.target();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    SignRequest {
        method: method.as_str(),
        authority: hop.authority_text(),
        path,
        query,
        payload,
    }
}

/// Returns `headers` with the headers that `signer` gives for one request of
/// `method` to `hop`, with `payload`.
///
/// [`merge_headers`] merges the headers of the signer as headers of a
/// request. So each one replaces a header of the same name, and a `Host`
/// header or a header of the connection layer is refused. Each value of the
/// signer is marked sensitive, because a signature header such as a session
/// token is a credential whatever its name is. An error of the signer, or a
/// refused header, is a [`Failure::Final`].
fn signed<'a>(
    signer: &dyn RequestSigner,
    method: &Method,
    hop: &Destination,
    payload: SignPayload<'_>,
    headers: &'a [(HeaderName, HeaderValue)],
) -> std::result::Result<Cow<'a, [(HeaderName, HeaderValue)]>, Failure> {
    let added = signer
        .sign(&sign_request(method, hop, payload))
        .map_err(Failure::Final)?;
    let merged = merge_headers(headers, &added, None, None).map_err(Failure::Final)?;
    if added.is_empty() {
        return Ok(merged);
    }
    // A name of the signer replaces each header of that name, so each entry
    // of such a name holds a value of the signer.
    let mut merged = merged.into_owned();
    for (name, value) in &mut merged {
        if added
            .iter()
            .any(|(added, _)| name.as_str().eq_ignore_ascii_case(added))
        {
            value.set_sensitive(true);
        }
    }
    Ok(Cow::Owned(merged))
}

/// Resolves the proxy configuration into the state that a fetch reads.
///
/// The function resolves each form once. So a fetch reads no environment and
/// parses no URL. A proxy URL that the fetcher cannot connect through fails
/// the constructor, from the options and from the environment. A value read
/// under a meaning of this crate sends the request to a place that the caller
/// did not name.
fn resolve_proxy(proxy: &Proxy) -> Result<Proxies> {
    match proxy {
        Proxy::None => Ok(Proxies::default()),
        Proxy::Environment => resolve_variables(&environment()),
        Proxy::Variables(variables) => resolve_variables(variables),
        Proxy::Url(url) => {
            let endpoint = Arc::new(parse_proxy(url)?);
            Ok(Proxies {
                http: Some(endpoint.clone()),
                https: Some(endpoint),
                exempt_all: false,
                exempt: Vec::new(),
            })
        }
    }
}

/// Returns the proxy variables of the process environment.
///
/// An empty value counts as unset. So the function leaves it out, and
/// [`variable`] has one rule to apply.
fn environment() -> Vec<(String, String)> {
    PROXY_VARIABLES
        .iter()
        .filter_map(|name| {
            let value = std::env::var(name).ok()?;
            (!value.is_empty()).then(|| ((*name).to_owned(), value))
        })
        .collect()
}

/// Resolves the variable forms of [`Proxy`] into the state that a fetch reads.
fn resolve_variables(variables: &[(String, String)]) -> Result<Proxies> {
    let all = variable(variables, "all_proxy", Some("ALL_PROXY"));
    let http = variable(variables, "http_proxy", None);
    let https = variable(variables, "https_proxy", Some("HTTPS_PROXY"));
    // The loop parses each variable that holds a value. The choice of the
    // proxy for each scheme comes after the loop, from the parsed values. So
    // the fetcher refuses a proxy URL that it cannot connect through, also if
    // no fetch reads it. An example is `all_proxy` beside both
    // scheme-specific variables.
    //
    // The loop parses one URL for both schemes once, and holds it as one
    // endpoint. So the pool key of a proxy connection is the same, whichever
    // variable named it.
    //
    // The loop refuses a value with white space at its start or end before
    // the parse, because the parse trims it. The rule is the same: the loop
    // checks each variable that it reads, also if no fetch uses it.
    // The message names the variable, and leaves out the value, which can hold
    // a password.
    let mut endpoints: Vec<(&str, Arc<ProxyEndpoint>)> = Vec::new();
    for (name, url) in [all, http, https].into_iter().flatten() {
        if url.trim() != url {
            return Err(Error::Unsupported(format!(
                "the proxy variable {name} has white space at the start or the end of \
                 its value"
            )));
        }
        if !endpoints.iter().any(|(named, _)| *named == url) {
            endpoints.push((url, Arc::new(parse_proxy(url)?)));
        }
    }
    let parsed = |held: Option<(&str, &str)>| {
        held.and_then(|(_, url)| endpoints.iter().find(|(named, _)| *named == url))
            .map(|(_, endpoint)| endpoint.clone())
    };
    let (http, https) = (parsed(http.or(all)), parsed(https.or(all)));
    let mut exempt_all = false;
    let mut exempt = Vec::new();
    for entry in variable(variables, "no_proxy", Some("NO_PROXY"))
        .map(|(_, value)| value)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        if entry == "*" {
            exempt_all = true;
            continue;
        }
        exempt.extend(parse_exemption(entry));
    }
    Ok(Proxies {
        http,
        https,
        exempt_all,
        exempt,
    })
}

/// Returns the name and the value of one proxy variable.
///
/// The function reads the lower-case name first, then the upper-case name if
/// there is one. An empty value counts as unset. Of two entries of one name,
/// the function reads the first entry with a value.
fn variable<'a>(
    variables: &'a [(String, String)],
    lower: &str,
    upper: Option<&str>,
) -> Option<(&'a str, &'a str)> {
    let held = |name: &str| {
        variables
            .iter()
            .find(|(held, value)| held == name && !value.is_empty())
            .map(|(held, value)| (held.as_str(), value.as_str()))
    };
    held(lower).or_else(|| upper.and_then(held))
}

/// Reads one `no_proxy` entry, or returns `None` if it names no host.
///
/// An IPv6 literal holds colons of its own. So the function reads a port from
/// the bracketed form and from an entry with one colon. An unbracketed entry
/// with more colons is an address, with no port.
///
/// A port text that is not a number from 0 to 65535 leaves the whole entry as
/// one host text. No origin host holds that text, so the entry exempts
/// nothing.
///
/// The function drops an entry with no host after it removes the leading `.`
/// and the port. `.` and `:8080` are the two forms of such an entry. An empty
/// host text is the suffix of each host, so it exempts every origin if it
/// stays.
fn parse_exemption(entry: &str) -> Option<Exemption> {
    let (host, port) = match entry
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
    {
        Some((inside, rest)) => (inside, rest.strip_prefix(':')),
        None => match entry.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, Some(port)),
            _ => (entry, None),
        },
    };
    // One leading `.` states the suffix match that the comparison makes in
    // all cases. So the code removes it, and the two forms of one entry are
    // one entry. A second `.` is part of the host text of the entry, which no
    // origin host holds.
    let named = |host: &str| host.strip_prefix('.').unwrap_or(host).to_ascii_lowercase();
    let (host, port) = match port.map(str::parse::<u16>) {
        Some(Ok(port)) => (named(host), Some(port)),
        Some(Err(_)) => (named(entry), None),
        None => (named(host), None),
    };
    (!host.is_empty()).then_some(Exemption { host, port })
}

/// Reads a proxy URL into the endpoint of a connection.
///
/// The request to a proxy names the origin. So the URL names an endpoint and
/// nothing else. A path other than `/`, a query, or a fragment states a value
/// that the request has no place for, and the function refuses it. The
/// scheme is `http`, the one scheme of a proxy connection in this crate.
///
/// Userinfo is the credential of the proxy. The function percent-decodes it
/// and sends it as `Proxy-Authorization: Basic`, as a proxy that works with
/// other clients expects. A userinfo holds a password, so each refusal names
/// the URL with the userinfo left out.
fn parse_proxy(url: &str) -> Result<ProxyEndpoint> {
    let refused = |what: &str| {
        Error::Unsupported(format!(
            "proxy url {}: {what}",
            without_userinfo(url.trim())
        ))
    };
    let url = url.trim();
    if !url
        .get(..PROXY_SCHEME.len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case(PROXY_SCHEME))
    {
        return Err(refused("a proxy is reached over http://host[:port] alone"));
    }
    if url.contains('#') {
        return Err(refused("a proxy url carries no fragment"));
    }
    let uri = Uri::try_from(url).map_err(|e| refused(&format!("invalid url: {e}")))?;
    // A `/` or a `?` in the userinfo moves a part of the password into the
    // path or the query. So these refusals do not show the path or the query.
    if uri.query().is_some() {
        return Err(refused("a proxy url carries no query string"));
    }
    if !matches!(uri.path(), "" | "/") {
        return Err(refused("a proxy url carries no path"));
    }
    // `Uri::host` holds an IPv6 literal in brackets. The brackets belong to
    // the authority. A connect resolves the bracketed form to nothing.
    let literal = uri.host().ok_or_else(|| refused("the url has no host"))?;
    let authority = uri
        .authority()
        .expect("a url holding a host holds an authority")
        .as_str();
    let credential = match authority.rsplit_once('@') {
        Some((userinfo, _)) => Some(proxy_credential(userinfo).ok_or_else(|| {
            refused(
                "the userinfo is not a percent-encoded user name and password the proxy can be \
                 sent",
            )
        })?),
        None => None,
    };
    let host = literal
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(literal)
        .to_ascii_lowercase();
    // `Uri` accepts an authority whose port it cannot read, and reports no
    // port for it. So the code reads the port text from the authority and
    // refuses it. The default port does not replace it.
    let port_text = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
        .strip_prefix(literal)
        .and_then(|rest| rest.strip_prefix(':'));
    let port = match (uri.port_u16(), port_text) {
        (Some(port), _) => port,
        (None, None) => 80,
        (None, Some(text)) => {
            return Err(refused(&format!(
                "the port {text:?} is not a number from 0 to 65535"
            )));
        }
    };
    let named = if port == 80 {
        format!("{PROXY_SCHEME}{literal}")
    } else {
        format!("{PROXY_SCHEME}{literal}:{port}")
    };
    Ok(ProxyEndpoint {
        endpoint: Origin {
            tls: false,
            host,
            port,
        },
        credential,
        named,
    })
}

/// Returns the `Proxy-Authorization` value of the userinfo of one proxy URL.
///
/// The function percent-decodes the two fields, because a URL states a `:` or
/// an `@` of a credential in that encoding. `None` states that the userinfo
/// holds something else: an escape that is not two hexadecimal digits, or a
/// field whose bytes are not text.
fn proxy_credential(userinfo: &str) -> Option<HeaderValue> {
    let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let field = |text: &str| String::from_utf8(percent_decode(text)?).ok();
    basic_auth_value(&BasicAuth {
        user: field(user)?,
        password: field(password)?,
    })
    .ok()
}

/// Percent-decodes one field of the userinfo of a proxy URL.
///
/// `%` starts an escape of exactly two hexadecimal digits. `None` states that
/// the field holds a different escape, which the fetcher refuses. The bytes as
/// written can give the proxy a credential other than the one that the caller
/// meant. The 407 answer to that credential names nothing.
fn percent_decode(field: &str) -> Option<Vec<u8>> {
    let bytes = field.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'%' {
            decoded.push(bytes[at]);
            at += 1;
            continue;
        }
        let escape = bytes.get(at + 1..at + 3)?;
        if !escape.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let text = std::str::from_utf8(escape).ok()?;
        decoded.push(u8::from_str_radix(text, 16).ok()?);
        at += 3;
    }
    Some(decoded)
}

/// Returns the `host:port` that names the target of a `CONNECT`.
///
/// The port is always written, whatever the default of the scheme. The proxy
/// opens a TCP connection, which names a port and reads no scheme. An IPv6
/// literal keeps the brackets that separate the address from the port.
fn connect_authority(origin: &Origin) -> String {
    if origin.host.contains(':') {
        format!("[{}]:{}", origin.host, origin.port)
    } else {
        format!("{}:{}", origin.host, origin.port)
    }
}

/// Returns the `Authorization` value of basic credentials, marked sensitive.
fn basic_auth_value(auth: &BasicAuth) -> Result<HeaderValue> {
    let encoded =
        ostrya_core::base64::encode(format!("{}:{}", auth.user, auth.password).as_bytes());
    let mut value = HeaderValue::try_from(format!("Basic {encoded}"))
        .map_err(|_| Error::Fetch("invalid basic-auth credentials".into()))?;
    value.set_sensitive(true);
    Ok(value)
}

/// Returns the `Authorization` value of a bearer token, marked sensitive.
///
/// The fetcher sends the token as written, so it must hold the token68 syntax
/// of the header. The token is a secret, so a refusal names no part of it.
fn bearer_value(token: &BearerToken) -> Result<HeaderValue> {
    let refused = || {
        Error::Fetch(
            "the bearer token is not token68: it holds letters, digits, -, ., _, ~, +, or /, \
             then any number of ="
                .into(),
        )
    };
    if !is_token68(&token.token) {
        return Err(refused());
    }
    let mut value =
        HeaderValue::try_from(format!("Bearer {}", token.token)).map_err(|_| refused())?;
    value.set_sensitive(true);
    Ok(value)
}

/// Returns `true` if `token` holds the token68 syntax.
///
/// The syntax is one or more ASCII letters, digits, `-`, `.`, `_`, `~`, `+`,
/// or `/`, then any number of `=`.
fn is_token68(token: &str) -> bool {
    let body = token.trim_end_matches('=');
    !body.is_empty()
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
}

/// Returns the origin of one absolute URL, and the authority of that origin.
///
/// The function checks the scheme before it parses the URL. So a URL that the
/// fetcher cannot serve gets a message that names the scheme. An example is a
/// `file://` URL, which is not a well-formed HTTP URL.
///
/// The function refuses userinfo. Credentials that never reach the wire get a
/// 401 answer, which points at nothing. `credentials` names the field that
/// carries them.
///
/// A userinfo holds a password. So the refusal names the scheme and the host.
/// A message about a URL before the parse reaches its authority names the URL
/// with the userinfo left out.
fn parse_authority(url: &str, credentials: &str) -> Result<(Uri, Origin, String)> {
    let scheme = url
        .split_once("://")
        .map(|(scheme, _)| scheme)
        .ok_or_else(|| {
            Error::Fetch(format!(
                "url {} is not an absolute http or https url",
                without_userinfo(url)
            ))
        })?;
    let tls = match scheme {
        _ if scheme.eq_ignore_ascii_case(Scheme::HTTPS.as_str()) => true,
        _ if scheme.eq_ignore_ascii_case(Scheme::HTTP.as_str()) => false,
        other => {
            return Err(Error::Unsupported(format!(
                "fetch url scheme {other}: only http and https are fetched"
            )));
        }
    };
    let scheme = if tls { "https" } else { "http" };
    let uri = Uri::try_from(url)
        .map_err(|e| Error::Fetch(format!("invalid url {}: {e}", without_userinfo(url))))?;
    // `Uri::host` puts an IPv6 literal in brackets. The brackets belong to the
    // authority, and the `Host` header and the absolute URL carry them. A
    // connect resolves the bracketed form to nothing, and a TLS server name
    // cannot come from it.
    let literal = uri
        .host()
        .ok_or_else(|| Error::Fetch(format!("url {} has no host", without_userinfo(url))))?;
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(Error::Fetch(format!(
            "the {scheme} url for {literal} carries userinfo, which the fetcher does not send: \
             pass credentials as {credentials}"
        )));
    }
    // A host is one origin in each case of its letters. So the pool key holds
    // it in lower case. A `Location` header repeats the case that the origin
    // server wrote. With two cases of one host in the pool, the fetcher opens
    // two connections and two HTTP/2 sessions to it.
    let host = literal
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(literal)
        .to_ascii_lowercase();
    // `Uri` accepts an authority whose port it cannot read, and reports no
    // port for it. Examples are `h:99999`, `h:`, and `h:abc`. A fallback to the
    // default of the scheme serves the request from a port that the caller did
    // not name. The rebuilt authority also drops the port. So the code reads
    // the port text from the authority and refuses it.
    //
    // `Uri` also reads the port with the integer parse of `std`, which takes a
    // leading `+`. A port is ASCII digits alone, so the code refuses a port
    // text with any other byte. Leading zeros are digits, and `080` names the
    // port 80.
    let port_text = uri
        .authority()
        .and_then(|authority| authority.as_str().strip_prefix(literal))
        .and_then(|rest| rest.strip_prefix(':'));
    let default_port = if tls { 443 } else { 80 };
    let digits = port_text.is_none_or(|text| text.bytes().all(|b| b.is_ascii_digit()));
    let port = match (uri.port_u16().filter(|_| digits), port_text) {
        (Some(port), _) => port,
        (None, None) => default_port,
        (None, Some(text)) => {
            // A password with a `?` or a `#` ends the authority before the
            // `@`. So the userinfo check passes, and a URL with userinfo can
            // get this message.
            return Err(Error::Fetch(format!(
                "url {} names the port {text:?}, which is not a number from 0 to 65535",
                without_userinfo(url)
            )));
        }
    };
    let authority = if port == default_port {
        literal.to_string()
    } else {
        format!("{literal}:{port}")
    };
    Ok((uri, Origin { tls, host, port }, authority))
}

/// Returns the form of a URL for a message, before the parse reaches the
/// authority and refuses the userinfo.
///
/// Userinfo holds a password, so the function leaves out the part of the
/// authority before the `@`. The password arrives as the caller wrote it. It
/// can hold a `/`, a `?`, or a `#`, which are the characters that end an
/// authority. So the end of the authority is known only after the userinfo is
/// found.
///
/// The function reads an `@` at any position after the scheme as the end of a
/// userinfo. It leaves out all text up to the last `@`, so no password of any
/// form reaches the message. When the text has no valid scheme before the
/// first `://`, the userinfo starts at the start of the text.
///
/// If a URL has an `@` in its path and no userinfo, the message loses its
/// host. A redaction that reads no well-formed authority has this cost.
fn without_userinfo(url: &str) -> Cow<'_, str> {
    let start = scheme_len(url);
    match url[start..].rfind('@') {
        Some(at) => Cow::Owned(format!("{}{}", &url[..start], &url[start + at + 1..])),
        None => Cow::Borrowed(url),
    }
}

/// Returns the length of the `<scheme>://` prefix of `url`, or 0.
///
/// The prefix counts only when the text before the first `://` is a valid
/// scheme: an ASCII letter, then ASCII letters, digits, `+`, `-`, or `.`.
fn scheme_len(url: &str) -> usize {
    let Some(end) = url.find("://") else {
        return 0;
    };
    let mut chars = url[..end].chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if valid { end + 3 } else { 0 }
}

/// Returns the `Host` header value of one authority.
fn host_header(url: &str, authority: &str) -> Result<HeaderValue> {
    HeaderValue::try_from(authority).map_err(|_| {
        Error::Fetch(format!(
            "url {} has an unusable host",
            without_userinfo(url)
        ))
    })
}

/// Checks that `url` is a base URL that a fetcher takes as a mirror.
///
/// The check opens no connection and reads no file. It refuses these parts:
///
/// - a scheme other than `http` and `https`
/// - userinfo
/// - a query string
/// - a fragment
/// - an empty host
/// - a port that is not a number from 0 to 65535 in ASCII digits.
///
/// A port with leading zeros is the number that its digits give.
///
/// The check refuses an `@` at any position, also in the path and in the
/// query. The authority of a URL ends at the first `/`, `?`, or `#`. So a
/// password with one of those ends the authority before the `@`. The rest of
/// the userinfo then reads as a path or a query.
///
/// No refusal names the part of the URL before the last `@`.
///
/// # Errors
///
/// - [`Error::Fetch`] if `url` holds a `#` or an `@`.
/// - [`Error::Unsupported`] if the scheme is neither `http` nor `https`.
/// - [`Error::Fetch`] if `url` is not a valid absolute URL, or has no host.
/// - [`Error::Fetch`] if `url` holds a query string, or names a port that is
///   not valid.
/// - [`Error::Fetch`] if a `Host` header cannot hold the authority.
pub fn check_base_url(url: &str) -> Result<()> {
    if url.contains('#') {
        return Err(Error::Fetch(format!(
            "url {} carries a fragment, which no request sends",
            without_userinfo(url)
        )));
    }
    if url.contains('@') {
        return Err(Error::Fetch(format!(
            "url {} holds an '@', which can mark userinfo: a base url carries no userinfo, so \
             pass the credential in the options and not in the url",
            without_userinfo(url)
        )));
    }
    let mirror = parse_mirror(url)?;
    if mirror.origin.host.is_empty() {
        return Err(Error::Fetch(format!(
            "url {} has no host",
            without_userinfo(url)
        )));
    }
    Ok(())
}

/// Parses one base URL into a [`Mirror`].
fn parse_mirror(url: &str) -> Result<Mirror> {
    let (uri, origin, authority) = parse_authority(url, "FetcherOptions::basic_auth")?;
    // A request target is the base path of the mirror with the object path
    // added. So a query string of the base URL drops out with no message. The
    // code refuses it. A presigned URL that lost its signature gets a 403
    // answer, which does not point at the URL that caused it.
    //
    // A password with a `?` ends the authority there, and the rest of the
    // userinfo reads as the query. So the message names the URL with the
    // userinfo left out, and does not quote the query.
    if uri.query().is_some() {
        return Err(Error::Fetch(format!(
            "mirror url {} carries a query string, which the fetcher does not send",
            without_userinfo(url)
        )));
    }
    let scheme = if origin.tls { "https" } else { "http" };
    Ok(Mirror {
        authority: host_header(url, &authority)?,
        prefix: format!("{scheme}://{authority}"),
        base: uri.path().trim_end_matches('/').to_string(),
        origin,
    })
}

/// Parses the absolute URL of a request into its [`Destination`].
///
/// The query string is part of the name of the request, so it reaches the
/// wire as written. The function refuses a fragment. A fragment is never sent,
/// so a URL with one asks for a resource other than the resource that the
/// caller named.
fn parse_url(url: &str) -> Result<Destination> {
    if url.contains('#') {
        return Err(Error::Fetch(format!(
            "fetch url {} carries a fragment, which no request sends",
            without_userinfo(url)
        )));
    }
    let (uri, origin, authority) = parse_authority(url, "FetchRequest::basic_auth")?;
    let scheme = if origin.tls { "https" } else { "http" };
    let path_and_query = uri.path_and_query().map_or("/", |pq| pq.as_str());
    // The code builds the one string of the destination from the parts of the
    // parse. The whole string is the absolute URL. Its tail from the prefix
    // length is the origin-form target.
    let mut text =
        String::with_capacity(scheme.len() + 3 + authority.len() + 1 + path_and_query.len());
    text.push_str(scheme);
    text.push_str("://");
    text.push_str(&authority);
    let path_at = text.len();
    if !path_and_query.starts_with('/') {
        text.push('/');
    }
    text.push_str(path_and_query);
    Ok(Destination {
        authority: host_header(url, &authority)?,
        url: text,
        path_at,
        origin,
    })
}

/// Returns `true` if `response` closes its HTTP/1.1 connection when it ends.
///
/// This is an HTTP/1.0 response, or a response whose `Connection` header holds
/// `close`.
fn closes(response: &Response<Incoming>) -> bool {
    response.version() != Version::HTTP_11
        || response
            .headers()
            .get_all(hyper::header::CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("close"))
}

/// Returns the `Content-Length` that a response declared, if it is usable.
fn content_length(headers: &hyper::HeaderMap) -> Option<u64> {
    headers
        .get(hyper::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Returns the coding that a response declared, if the body needs a decode.
///
/// `Content-Encoding` codes the content, and `Transfer-Encoding` codes the
/// message that carries the content. A body under either holds bytes other
/// than the bytes that the remote stores, so the function reads both headers.
/// If a response declares both, the function returns its content coding.
fn declared_coding(headers: &hyper::HeaderMap) -> Option<String> {
    coding(headers, hyper::header::CONTENT_ENCODING, &[IDENTITY]).or_else(|| {
        coding(
            headers,
            hyper::header::TRANSFER_ENCODING,
            &[IDENTITY, CHUNKED],
        )
    })
}

/// Returns the coding that a response declared under `name`, if it is not in
/// `undone`.
///
/// `undone` holds the codings that leave the body as the remote wrote it. A
/// value is a comma-separated list of codings, and several headers of one name
/// state one list together. So the function reads each token of each value.
///
/// A value whose tokens are all empty names no coding. The function adds it
/// to no result, so a stray separator reaches no message. The result is the
/// text of the response, in its order, so the refusal names the value of the
/// server. A response with nothing to refuse builds no string.
fn coding(headers: &hyper::HeaderMap, name: HeaderName, undone: &[&str]) -> Option<String> {
    let declared = || {
        headers
            .get_all(&name)
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()))
            .filter(|value| value.split(',').any(|token| !token.trim().is_empty()))
    };
    if !declared().any(|value| value.split(',').any(|token| names_a_coding(token, undone))) {
        return None;
    }
    Some(declared().collect::<Vec<_>>().join(", "))
}

/// Returns `true` if one token of a coding list names a coding that is not in
/// `undone`.
///
/// The comparison ignores case and the space around the token. An empty token
/// names nothing.
fn names_a_coding(token: &str, undone: &[&str]) -> bool {
    let token = token.trim();
    !token.is_empty() && !undone.iter().any(|name| token.eq_ignore_ascii_case(name))
}

/// Reads the cache validators of a response.
fn read_validators(headers: &hyper::HeaderMap) -> Validators {
    let text = |name: HeaderName| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    Validators {
        etag: text(hyper::header::ETAG),
        last_modified: text(hyper::header::LAST_MODIFIED),
    }
}

/// Returns `true` if a response with this status sends the attempt to another
/// URL.
fn is_redirect(status: StatusCode) -> bool {
    REDIRECTS.contains(&status)
}

/// Returns the URL of a `Location` header, resolved against `from`, the URL of
/// the response that carried it.
///
/// A `Location` can be an absolute URL, a URL relative to the URL of the
/// response, or a scheme-relative URL. The resolution is the one that the URL
/// specification states. The function drops a fragment of the result. A
/// fragment names a part of a representation and reaches no request, and the
/// HTTP specification tells a redirect to drop it.
///
/// The resolution normalizes its result. A [`Target::Url`] reaches the wire as
/// the caller wrote it. The changes are:
///
/// - it resolves dot segments: `/deep/../root` becomes `/root`, and `/./p`
///   becomes `/p`
/// - it reads a backslash as a path separator: `/a\b` becomes `/a/b`
/// - it removes tabs and newlines
/// - it percent-encodes a character that a path or a query cannot carry:
///   `?q='x'` becomes `?q=%27x%27`
/// - it puts an IPv4 or an IPv6 host in canonical form: `2130706433` and
///   `0177.0.0.1` both become `127.0.0.1`.
///
/// If the signature of a signed request target covers one of those
/// characters, the target reaches the server in a new encoding. The server
/// reads it as a different target, and answers 403.
///
/// `None` states that the header holds no URL for a request. This covers a
/// value that is not text, an empty value, and a value that the resolution
/// cannot read. A value that resolves to the URL of the response itself, a
/// fragment alone such as `#frag`, is a hop of its own. It spends one of the
/// hops of the attempt.
fn resolve_location(from: &str, location: &HeaderValue) -> Option<String> {
    let location = location.to_str().ok()?;
    // An empty value resolves to the URL of the response that carried it. The
    // attempt then follows the hop that it just made, so the code returns
    // `None` for it.
    if location.is_empty() {
        return None;
    }
    let mut resolved = url::Url::parse(from).ok()?.join(location).ok()?;
    resolved.set_fragment(None);
    Some(resolved.into())
}

/// Reads the URL that a redirect named into the destination of the next hop.
///
/// The function refuses two hops. Both refusals name the URL that redirected
/// and the URL that it named:
///
/// - a scheme other than `http` or `https`, under which the fetcher serves
///   nothing
/// - a hop from `https` to `http`, which puts a request that the caller made
///   over TLS on the wire in the clear.
///
/// The function follows a hop from `http` to `https`.
///
/// The input is the resolved URL, normalized by [`resolve_location`]. The
/// parse reads it as it reads a [`Target::Url`]. So that parse refuses
/// userinfo and a port that the URL parser cannot read, with its own message.
/// A userinfo holds a password, so the two refusals of this function name the
/// URL with the userinfo left out.
fn redirect_destination(from: &Destination, to: &str) -> Result<Destination> {
    let refused = |what: &str| {
        Error::Fetch(format!(
            "{} redirects to {}, {what}",
            from.url(),
            without_userinfo(to)
        ))
    };
    let tls = match to.split_once("://").map(|(scheme, _)| scheme) {
        Some(scheme) if scheme.eq_ignore_ascii_case(Scheme::HTTPS.as_str()) => true,
        Some(scheme) if scheme.eq_ignore_ascii_case(Scheme::HTTP.as_str()) => false,
        _ => return Err(refused("which is not an absolute http or https url")),
    };
    if from.origin.tls && !tls {
        return Err(refused(
            "which is cleartext: a request made over tls is not followed onto http",
        ));
    }
    parse_url(to)
}

/// Returns the error of a fetch of a TLS origin on a fetcher that holds no
/// trust anchors.
///
/// The route or a redirect hop can name the origin.
fn no_trust_anchors(origin: &str) -> Error {
    Error::Fetch(format!(
        "the certificate of the tls origin {origin} has nothing to verify against: the \
         fetcher holds no trust anchors, so set TlsOptions::roots"
    ))
}

/// Classifies an unsuccessful status as retryable or definitive.
fn classify(status: StatusCode, url: &str) -> Failure {
    let error = Error::HttpStatus {
        status: status.as_u16(),
        url: url.to_string(),
        response: None,
    };
    if status.is_server_error()
        || status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
    {
        Failure::Retry(error)
    } else {
        Failure::Fatal(error)
    }
}

/// Returns the error of a transport failure against one URL.
fn transport(url: &str, error: hyper::Error) -> Error {
    Error::Fetch(format!("{url}: {error}"))
}

/// Returns the error of a response that did not deliver its head within the
/// progress window.
fn stalled(url: &str, limit: Duration) -> Error {
    Error::Fetch(format!("{url}: no response after {limit:?}"))
}

/// Returns the error of a connect that did not complete within `limit`.
///
/// The window covers the connect to the endpoint of the hop. So the error of
/// a proxied hop names the proxy. The fetcher reaches the origin over that
/// connection, and nothing contacts the origin before the connection is open.
fn connect_timed_out(origin: &Origin, via: Via<'_>, limit: Duration) -> Error {
    Error::Fetch(match via {
        Via::Direct => format!(
            "connect to {}:{} timed out after {limit:?}",
            origin.host, origin.port
        ),
        Via::Absolute(proxy) | Via::Tunnel(proxy) => format!(
            "connect to the proxy {} timed out after {limit:?}",
            proxy.named
        ),
    })
}

/// Returns the error of an upload whose body failed before the hand-over. The
/// request was never sent.
fn not_sent(url: &str, reason: String) -> Error {
    Error::Fetch(format!("upload to {url} not sent: {reason}"))
}

/// Returns the failure of an upload that failed after hyper took its request.
fn interrupted(url: &str, message: String) -> UploadFailure {
    UploadFailure::Sent {
        url: url.to_string(),
        message,
    }
}

/// Returns the failure of an upload that does not deliver its response, for
/// `cause`.
///
/// hyper took the request, so the upload is interrupted. The message names
/// the cause.
fn undelivered(url: &str, cause: Error) -> UploadFailure {
    interrupted(url, cause.to_string())
}

/// Appends `data` to `bytes` if the result holds at most `cap` bytes, and
/// returns `false` otherwise.
///
/// The capacity of `bytes` doubles as it grows, and never passes `cap`.
fn extend_capped(bytes: &mut Vec<u8>, data: &[u8], cap: u64) -> bool {
    let needed = bytes.len().saturating_add(data.len());
    if needed as u64 > cap {
        return false;
    }
    if needed > bytes.capacity() {
        let doubled = bytes.capacity().saturating_mul(2).max(needed);
        let grown = usize::try_from(cap).map_or(doubled, |cap| doubled.min(cap));
        bytes.reserve_exact(grown - bytes.len());
    }
    bytes.extend_from_slice(data);
    true
}

/// Returns the message of an error and of its cause.
///
/// The message of a hyper error is generic, and its cause names what the
/// connection did.
fn with_cause(error: &dyn std::error::Error) -> String {
    match error.source() {
        Some(cause) => format!("{error}: {cause}"),
        None => error.to_string(),
    }
}

/// Returns the error of a response that did not deliver its head within the
/// time of the low-speed rule.
fn too_slow(url: &str, rule: LowSpeed) -> Error {
    let LowSpeed { limit, time } = rule;
    Error::Fetch(format!(
        "{url}: transfer below {limit} bytes per second for {time:?}"
    ))
}

/// Runs `future` under a deadline, and returns `None` if `limit` expires
/// first.
///
/// The function drops the future on expiry, which cancels its work.
async fn within<F: Future>(limit: Duration, future: F) -> Option<F::Output> {
    // The future is pinned before the race. So the block that awaits it holds
    // a pointer, and no second copy of it. A caller that fetches many objects
    // holds one such future for each object in flight, and its size is a cost
    // on the stack.
    let mut future = core::pin::pin!(future);
    futures_lite::future::or(async { Some(future.as_mut().await) }, async {
        rt::Timer::after(limit).await;
        None
    })
    .await
}

/// Runs `future` under a deadline of `limit` that applies while `handed` is
/// `false`, and returns `None` if the deadline expires first.
///
/// The deadline runs from the call. An upload sets `handed` when hyper takes
/// the request. The request then has deadlines of its own, and the function
/// drops the timer. A request that comes back unsent clears `handed`, and the
/// function arms the timer again for the rest of the deadline.
async fn before_hand_over<F: Future>(
    limit: Duration,
    handed: &AtomicBool,
    future: F,
) -> Option<F::Output> {
    let mut future = core::pin::pin!(future);
    let end = Instant::now().checked_add(limit);
    let mut deadline: Option<rt::Deadline> = None;
    std::future::poll_fn(|cx| {
        if let Poll::Ready(output) = future.as_mut().poll(cx) {
            return Poll::Ready(Some(output));
        }
        if handed.load(Ordering::Relaxed) {
            deadline = None;
            return Poll::Pending;
        }
        // An end past the range of the clock is never reached. A timer of the
        // whole limit stands for it.
        let deadline = deadline.get_or_insert_with(|| {
            rt::Deadline::new(
                end.map_or(limit, |end| end.saturating_duration_since(Instant::now())),
            )
        });
        deadline.poll_expired(cx).map(|()| None)
    })
    .await
}

/// Waits for the answer to a request that hyper took.
///
/// While a streamed body streams, nothing bounds the wait here, because the
/// stall window of the writer bounds the body. A body given whole has no
/// writer, so its stall window runs here. A frame that hyper does not take
/// within the window fails the body and ends the wait.
///
/// A body that fails ends the wait at once, also if hyper does not poll it
/// again. The window for the response head starts when hyper takes the end of
/// the body.
async fn answer<F: Future>(send: F, exchange: &Exchange, window: Duration) -> Answer<F::Output> {
    let mut send = core::pin::pin!(send);
    let mut head: Option<rt::Deadline> = None;
    let mut stall: Option<rt::Deadline> = None;
    std::future::poll_fn(|cx| {
        if let Poll::Ready(output) = send.as_mut().poll(cx) {
            return Poll::Ready(Answer::Sent(output));
        }
        while head.is_none() {
            match exchange.watch(cx) {
                Watch::Streaming(None) => return Poll::Pending,
                Watch::Streaming(Some(end)) => {
                    if poll_until(&mut stall, cx, end).is_pending() {
                        return Poll::Pending;
                    }
                    if let Ok(reason) = exchange.check_stall() {
                        return Poll::Ready(Answer::Aborted(reason));
                    }
                }
                Watch::Aborted(reason) => return Poll::Ready(Answer::Aborted(reason)),
                Watch::Ended => {
                    stall = None;
                    head = Some(rt::Deadline::new(window));
                }
            }
        }
        head.as_mut()
            .expect("the head window runs once the body has ended")
            .poll_expired(cx)
            .map(|()| Answer::Silent(window))
    })
    .await
}

/// Returns the delay before retry round `round`: 250 ms, doubled for each
/// round, up to 2 seconds.
fn backoff(round: u32) -> Duration {
    let ms = 250u64 << (round - 1).min(3);
    Duration::from_millis(ms)
}

// The fetcher, its bodies, and the parts of an upload move freely across tasks
// and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Fetcher>();
    assert_send_sync::<Body>();
    assert_send_sync::<Fetched>();
    assert_send_sync::<BearerToken>();
    assert_send_sync::<UploadBody>();
    assert_send_sync::<UploadWriter>();
    assert_send_sync::<UploadRequest<'static>>();
    assert_send_sync::<Uploaded>();
    assert_send_sync::<ErrorResponse>();
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The connection window holds one stream window for each request that
    /// the fetcher admits, and stops at the ceiling of the protocol.
    #[test]
    fn the_connection_window_covers_every_admitted_stream() {
        assert_eq!(h2_connection_window(1), H2_STREAM_WINDOW);
        assert_eq!(h2_connection_window(8), 8 * H2_STREAM_WINDOW);
        assert_eq!(h2_connection_window(usize::MAX), H2_MAX_WINDOW);
    }

    #[test]
    fn mirror_urls_join_base_and_path() {
        let mirror = parse_mirror("https://example.com/repo/").unwrap();
        assert_eq!(
            mirror.destination("objects/ab/cd.filez", None).url(),
            "https://example.com/repo/objects/ab/cd.filez"
        );
        assert_eq!(mirror.origin.port, 443);
        assert!(mirror.origin.tls);

        let root = parse_mirror("http://example.com").unwrap();
        assert_eq!(
            root.destination("summary", None).url(),
            "http://example.com/summary"
        );
        assert_eq!(root.origin.port, 80);
        assert!(!root.origin.tls);

        // A non-default port stays in the URL and in the host header. A leading
        // slash on the path is not doubled.
        let ported = parse_mirror("http://127.0.0.1:8080/r").unwrap();
        let config = ported.destination("/config", None);
        assert_eq!(config.url(), "http://127.0.0.1:8080/r/config");
        assert_eq!(config.target(), "/r/config");
        assert_eq!(ported.authority, "127.0.0.1:8080");
        assert_eq!(root.authority, "example.com");
    }

    /// A query string goes after the request path, as written, in the URL
    /// and in the origin-form target.
    #[test]
    fn mirror_urls_join_base_path_and_query() {
        let mirror = parse_mirror("http://127.0.0.1:8080/base/").unwrap();
        let destination = mirror.destination("_ostrya/refs/v1", Some("pattern=a%2Fb&pattern=c"));
        assert_eq!(
            destination.url(),
            "http://127.0.0.1:8080/base/_ostrya/refs/v1?pattern=a%2Fb&pattern=c"
        );
        assert_eq!(
            destination.target(),
            "/base/_ostrya/refs/v1?pattern=a%2Fb&pattern=c"
        );
        // An empty query keeps its `?`.
        let root = parse_mirror("https://example.com").unwrap();
        assert_eq!(
            root.destination("/p", Some("")).url(),
            "https://example.com/p?"
        );
    }

    /// An IPv6 literal has brackets in the authority, and has none where the
    /// address itself is used. The brackets reach neither the connect nor the
    /// TLS server name, and both fail on them.
    #[test]
    fn an_ipv6_literal_keeps_its_brackets_only_in_the_authority() {
        let ported = parse_mirror("http://[::1]:8080/r").unwrap();
        assert_eq!(ported.origin.host, "::1");
        assert_eq!(ported.origin.port, 8080);
        assert_eq!(ported.authority, "[::1]:8080");
        assert_eq!(
            ported.destination("summary", None).url(),
            "http://[::1]:8080/r/summary"
        );

        let tls = parse_mirror("https://[2001:db8::1]/repo").unwrap();
        assert_eq!(tls.origin.host, "2001:db8::1");
        assert_eq!(tls.origin.port, 443);
        assert_eq!(tls.authority, "[2001:db8::1]");
        assert_eq!(
            tls.destination("summary", None).url(),
            "https://[2001:db8::1]/repo/summary"
        );
        // The server name the TLS handshake is opened with comes from the same
        // field, and rejects the bracketed form.
        rustls::pki_types::ServerName::try_from(tls.origin.host.clone()).unwrap();
    }

    #[test]
    fn mirror_urls_are_validated() {
        let err = parse_mirror("file:///srv/repo").unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        let err = parse_mirror("/srv/repo").unwrap_err();
        assert!(err.to_string().contains("not an absolute"), "{err}");
        let err = parse_mirror("http://").unwrap_err();
        assert!(err.to_string().contains("invalid url"), "{err}");

        // Neither a query nor userinfo reaches the wire. So the parse refuses
        // a URL with one, and does not serve it with the part missing.
        let err = parse_mirror("https://host/repo?X-Amz-Signature=deadbeef").unwrap_err();
        assert!(err.to_string().contains("query string"), "{err}");
        let err = parse_mirror("https://user:pass@host/repo").unwrap_err();
        assert!(err.to_string().contains("userinfo"), "{err}");
        // A bare user with no password is userinfo too.
        let err = parse_mirror("http://user@host/repo").unwrap_err();
        assert!(err.to_string().contains("userinfo"), "{err}");
    }

    /// A base URL check takes each URL a mirror takes, and refuses a
    /// fragment and an empty host as well. A refusal holds no password.
    #[test]
    fn a_base_url_check_refuses_what_a_mirror_cannot_carry() {
        for url in [
            "http://host",
            "https://host/repo/",
            "http://127.0.0.1:8080/r",
            "https://[::1]:8443/",
            "HTTPS://host/repo",
        ] {
            check_base_url(url).unwrap();
        }
        let refused = |url: &str, part: &str| {
            let err = check_base_url(url).unwrap_err();
            let text = err.to_string();
            assert!(text.contains(part), "{url}: {text}");
            assert!(!text.contains("secret"), "{url}: {text}");
        };
        refused("https://user:secret@host/repo", "userinfo");
        refused("https://host/repo?q=1", "query string");
        refused("https://host/repo#part", "fragment");
        refused("https://u:secret@host/repo#part", "fragment");
        refused("http://", "invalid url");
        refused("http:///repo", "invalid url");
        refused("http://:80/repo", "has no host");
        refused("http://host:99999/repo", "not a number");
        refused("http://host:x/repo", "not a number");
        refused("ftp://host/repo", "scheme ftp");
        refused("host/repo", "not an absolute");
        // A password that holds a `/` or a `?` ends the authority before the
        // `@`. So the rest of the userinfo reads as the path or the query.
        refused("https://user:443/pw-secret@host/repo", "userinfo");
        refused("https://user:1234?pw-secret@host/", "userinfo");
        refused("https://host/repo@v1", "userinfo");
        // A port is ASCII digits alone. Leading zeros are digits.
        refused("http://h:+80/", "not a number");
        refused("http://h:-80/", "not a number");
        check_base_url("http://h:080/").unwrap();
        assert_eq!(parse_mirror("http://h:080/r").unwrap().prefix, "http://h");
        assert_eq!(
            parse_mirror("http://h:0808/r").unwrap().prefix,
            "http://h:808"
        );
    }

    /// No refusal of a mirror URL names the userinfo that a password holding
    /// a `?` hides in the query.
    #[test]
    fn a_mirror_refusal_names_no_userinfo() {
        let err = parse_mirror("https://user:1234?pw-secret@host/").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("query string"), "{text}");
        assert!(!text.contains("secret"), "{text}");
        let err = parse_mirror("http://h:+80/x").unwrap_err();
        assert!(err.to_string().contains("not a number"), "{err}");
    }

    #[test]
    fn options_are_validated_at_construction() {
        rt::block_on(async {
            let mut options = direct_options("http://example.com");
            options.headers = vec![("not a header".into(), "v".into())];
            let err = Fetcher::new(options).await.unwrap_err();
            assert!(err.to_string().contains("invalid header name"), "{err}");

            // The host header comes from the url of the request, so a host
            // header from the caller collides with it.
            let mut options = direct_options("http://example.com");
            options.headers = vec![("host".into(), "elsewhere".into())];
            let err = Fetcher::new(options).await.unwrap_err();
            assert!(err.to_string().contains("host header"), "{err}");

            // Credentials and an authorization header both set the same
            // header, and which of the two to send is not stated.
            let mut options = tls_options("https://example.com");
            options.headers = vec![("authorization".into(), "Basic aaa".into())];
            options.basic_auth = Some(BasicAuth {
                user: "u".into(),
                password: "p".into(),
            });
            let err = Fetcher::new(options).await.unwrap_err();
            assert!(err.to_string().contains("pass one of them"), "{err}");

            // A low-speed rule with a zero measures nothing. The constructor
            // refuses it, and does not read it as no rule.
            for low_speed in [
                LowSpeed {
                    limit: 0,
                    time: Duration::from_secs(30),
                },
                LowSpeed {
                    limit: 1000,
                    time: Duration::ZERO,
                },
            ] {
                let mut options = direct_options("http://example.com");
                options.low_speed = Some(low_speed);
                let err = Fetcher::new(options).await.unwrap_err();
                assert!(err.to_string().contains("neither may be zero"), "{err}");
            }
        });
    }

    /// A low-speed time is rounded up to whole seconds, and saturates at the
    /// maximum with no wrap.
    #[test]
    fn a_low_speed_time_rounds_up_to_whole_seconds() {
        let rule = |time| LowSpeed { limit: 1000, time };
        let secs = Duration::from_secs;
        assert_eq!(rule(secs(30)).whole_seconds(), secs(30));
        assert_eq!(rule(Duration::from_millis(200)).whole_seconds(), secs(1));
        assert_eq!(rule(Duration::from_millis(1500)).whole_seconds(), secs(2));
        assert_eq!(rule(Duration::MAX).whole_seconds(), secs(u64::MAX));
    }

    /// The second at which the low-speed rule fails a body that delivers
    /// `bursts`. Each burst is a byte count at a whole second after the first
    /// read. `None` states that the rule does not fail the body within
    /// `seconds`.
    fn low_speed_failure(time: u64, bursts: &[(u64, u64)], seconds: u64) -> Option<u64> {
        let mut monitor = Monitor::new(LowSpeed {
            limit: 1000,
            time: Duration::from_secs(time),
        });
        (1..=seconds).find(|&second| {
            let arrived: u64 = bursts
                .iter()
                .filter(|(at, _)| *at == second - 1)
                .map(|(_, bytes)| bytes)
                .sum();
            monitor.counted += arrived;
            monitor.sample()
        })
    }

    /// The low-speed rule fails a body at the second at which the `ostree`
    /// command fails the same transfer. The limit is 1000 bytes per second,
    /// and the time is 2 seconds.
    #[test]
    fn the_low_speed_rule_fails_where_the_tool_fails() {
        rt::block_on(async {
            // Nothing arrives: the rate is below the limit from the start.
            assert_eq!(low_speed_failure(2, &[], 20), Some(2));
            assert_eq!(low_speed_failure(3, &[], 20), Some(3));
            // One burst and then nothing. The rate falls below the limit when
            // the burst ages out of the five-second span. It also falls below
            // when the burst over the seconds so far is below the limit. A
            // sample of exactly the limit counts as below it.
            assert_eq!(low_speed_failure(2, &[(0, 1_000)], 20), Some(2));
            assert_eq!(low_speed_failure(2, &[(0, 3_000)], 20), Some(5));
            assert_eq!(low_speed_failure(2, &[(0, 5_000)], 20), Some(7));
            assert_eq!(low_speed_failure(2, &[(0, 20_000)], 20), Some(8));
            assert_eq!(low_speed_failure(2, &[(0, 8_000)], 20), Some(8));
            assert_eq!(low_speed_failure(2, &[(0, 3_500)], 20), Some(6));
            // A second burst that arrives before the rate stays below the
            // limit for 2 seconds starts the count again. The body ends with
            // the second burst.
            let second = |at| [(0, 6_000), (at, 6_000)];
            assert_eq!(low_speed_failure(2, &second(6), 7), None);
            assert_eq!(low_speed_failure(2, &second(7), 8), None);
            assert_eq!(low_speed_failure(2, &second(8), 9), Some(8));
            // Bursts whose average is above the limit pass, though some whole
            // seconds carry nothing.
            let bursts: Vec<(u64, u64)> = (0..20).step_by(2).map(|at| (at, 2_100)).collect();
            assert_eq!(low_speed_failure(1, &bursts, 20), None);
        });
    }

    /// A fetcher with no mirror serves the URLs its requests name. A path
    /// target has nowhere to go there, and is refused before admission.
    #[test]
    fn a_path_target_needs_a_mirror() {
        rt::block_on(async {
            let fetcher = Fetcher::new(mirrorless_options()).await.unwrap();
            let err = fetcher.route(Target::Path("summary")).unwrap_err();
            assert!(err.to_string().contains("no mirror is configured"), "{err}");
            let route = fetcher
                .route(Target::Url("https://example.com/summary"))
                .unwrap();
            let Route::One(destination) = route else {
                panic!("a url target names one destination");
            };
            assert_eq!(destination.url(), "https://example.com/summary");
        });
    }

    /// A request path is added to the base path as written. So a `?` or a `#`
    /// in it is a delimiter, and the target is not the target that the caller
    /// asked for.
    #[test]
    fn a_query_or_a_fragment_in_a_path_is_rejected() {
        for path in ["refs/heads/a?b=c", "refs/heads/a#frag"] {
            let Err(err) = check_path(path) else {
                panic!("{path} was accepted as a request path");
            };
            assert!(
                err.to_string().contains("no query and no fragment"),
                "{path}: {err}"
            );
        }
        check_path("refs/heads/a").unwrap();
    }

    /// A path with a query goes to the mirrors. The path has the rules of a
    /// path target, and a `#` in the query is refused before admission.
    #[test]
    fn a_path_query_target_is_checked_and_goes_to_the_mirrors() {
        rt::block_on(async {
            let fetcher = Fetcher::new(direct_options("http://example.com/r"))
                .await
                .unwrap();
            let route = fetcher
                .route(Target::PathQuery {
                    path: "_ostrya/refs/v1",
                    query: "pattern=a",
                })
                .unwrap();
            let Route::Mirrors { path, query } = route else {
                panic!("a path query target goes to the mirrors");
            };
            assert_eq!((&*path, query), ("_ostrya/refs/v1", Some("pattern=a")));

            let refused = [
                ("p?x", "q", "no query and no fragment"),
                ("p#x", "q", "no query and no fragment"),
                ("p", "q#x", "a query holds no fragment"),
            ];
            for (path, query, message) in refused {
                let err = fetcher
                    .route(Target::PathQuery { path, query })
                    .unwrap_err();
                assert!(matches!(err, Error::Fetch(_)), "{err:?}");
                assert!(err.to_string().contains(message), "{path}?{query}: {err}");
            }

            let fetcher = Fetcher::new(mirrorless_options()).await.unwrap();
            let err = fetcher
                .route(Target::PathQuery {
                    path: "p",
                    query: "q",
                })
                .unwrap_err();
            assert!(
                err.to_string().contains("path p?q has nowhere to go"),
                "{err}"
            );
        });
    }

    /// The request path is added to the base path of the mirror, and the
    /// target carries the origin form for HTTP/1.1.
    #[test]
    fn a_request_target_appends_the_path_to_the_base() {
        rt::block_on(async {
            let fetcher = Fetcher::new(direct_options("http://example.com/r"))
                .await
                .unwrap();
            let mirror = &fetcher.inner.mirrors[0];
            let destination = mirror.destination("refs/heads/a", None);
            let request = fetcher
                .build_request(
                    &destination,
                    &FetchRequest::path("refs/heads/a"),
                    &fetcher.inner.headers,
                    Protocol::Http11,
                    Via::Direct,
                )
                .unwrap();
            assert_eq!(request.uri(), "/r/refs/heads/a");
        });
    }

    /// A `Location` is resolved against the URL of the response that carried
    /// it. So it reads as an absolute URL, a relative URL, or a
    /// scheme-relative URL. A fragment names a part of a representation and
    /// reaches no request, so a redirect drops it.
    #[test]
    fn a_location_resolves_against_the_response_that_carried_it() {
        let resolved = |value: &str| {
            resolve_location(
                "https://example.com/repo/objects/summary?x=1",
                &HeaderValue::try_from(value).unwrap(),
            )
        };
        for (value, hop) in [
            // Absolute, at another origin and at another port.
            ("http://other.example/p", "http://other.example/p"),
            (
                "https://other.example:8443/p?q=2",
                "https://other.example:8443/p?q=2",
            ),
            // Relative: rooted at the origin, and a sibling of the path the
            // response was answered at.
            ("/other/path", "https://example.com/other/path"),
            ("sibling", "https://example.com/repo/objects/sibling"),
            // Scheme-relative, which takes the scheme of the response that
            // redirected.
            ("//host.example/path", "https://host.example/path"),
            // A fragment is dropped, and the resolution does not refuse it.
            ("/other/path#frag", "https://example.com/other/path"),
            ("http://other.example/p#frag", "http://other.example/p"),
            // A scheme under which the fetcher serves nothing resolves here.
            // The hop check refuses it.
            ("file:///srv/repo", "file:///srv/repo"),
        ] {
            assert_eq!(resolved(value).as_deref(), Some(hop), "{value}");
        }

        // A value that the resolution cannot read holds no URL for a request.
        // An empty value holds none either, because it resolves to the URL of
        // the response itself.
        assert_eq!(resolved("http://"), None);
        assert_eq!(resolved(""), None);

        // A fragment alone resolves to the URL of the response itself, which is
        // a hop of its own.
        assert_eq!(
            resolved("#frag").as_deref(),
            Some("https://example.com/repo/objects/summary?x=1")
        );

        // The resolution normalizes its result. A dot segment is resolved
        // away, a backslash reads as a path separator, and a tab is removed. A
        // character that a query cannot carry is percent-encoded, and an IPv4
        // host is canonicalized.
        for (value, hop) in [
            ("/deep/../root", "https://example.com/root"),
            ("/./p", "https://example.com/p"),
            ("/a\\b", "https://example.com/a/b"),
            ("/pa\tth", "https://example.com/path"),
            ("/p?q='x'", "https://example.com/p?q=%27x%27"),
            ("http://2130706433/p", "http://127.0.0.1/p"),
        ] {
            assert_eq!(resolved(value).as_deref(), Some(hop), "{value}");
        }
    }

    /// A hop is read as a URL target is. Two hops are refused with both URLs
    /// named: a scheme under which the fetcher serves nothing, and a hop from
    /// `https` to `http`. A hop from `http` to `https` is followed.
    #[test]
    fn a_redirect_hop_is_validated_against_the_url_that_redirected() {
        let secure = parse_url("https://example.com/repo/summary").unwrap();
        let cleartext = parse_url("http://example.com/repo/summary").unwrap();

        // A hop at another origin, and one at the origin that redirected.
        let hop = redirect_destination(&secure, "https://other.example/p?q=1").unwrap();
        assert_eq!(hop.url(), "https://other.example/p?q=1");
        assert_eq!(hop.origin.host, "other.example");
        let hop = redirect_destination(&secure, "https://example.com/elsewhere").unwrap();
        assert_eq!(hop.origin, secure.origin);
        // A hop from cleartext to tls is followed, and so is one that stays
        // cleartext.
        let hop = redirect_destination(&cleartext, "https://example.com/elsewhere").unwrap();
        assert!(hop.origin.tls);
        redirect_destination(&cleartext, "http://other.example/p").unwrap();

        // A hop from tls to cleartext is refused, and both URLs are named.
        let err = redirect_destination(&secure, "http://other.example/p").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("https://example.com/repo/summary"),
            "{message}"
        );
        assert!(message.contains("http://other.example/p"), "{message}");
        assert!(message.contains("cleartext"), "{message}");

        // A scheme under which the fetcher serves nothing, named in the same
        // way.
        let err = redirect_destination(&secure, "file:///srv/repo").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("https://example.com/repo/summary"),
            "{message}"
        );
        assert!(message.contains("file:///srv/repo"), "{message}");
        assert!(
            message.contains("not an absolute http or https url"),
            "{message}"
        );

        // Userinfo is refused, and the password reaches no message.
        let err =
            redirect_destination(&secure, "https://alice:sup3rs3cret@other.example/p").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("userinfo"), "{message}");
        assert!(!message.contains("sup3rs3cret"), "{message}");
    }

    /// The statuses that send a fetch to another URL. A fetch is a GET, so the
    /// statuses that differ on the method are one case.
    #[test]
    fn the_followed_statuses_are_the_five_redirects() {
        for status in [301u16, 302, 303, 307, 308] {
            assert!(
                is_redirect(StatusCode::from_u16(status).unwrap()),
                "{status}"
            );
        }
        for status in [200u16, 300, 304, 305, 306, 400, 404, 500] {
            assert!(
                !is_redirect(StatusCode::from_u16(status).unwrap()),
                "{status}"
            );
        }
    }

    #[test]
    fn retryable_statuses_are_classified() {
        for status in [500u16, 502, 503, 408, 429] {
            let failure = classify(StatusCode::from_u16(status).unwrap(), "http://h/p");
            assert!(matches!(failure, Failure::Retry(_)), "{status}");
        }
        for status in [400u16, 401, 403, 404, 410] {
            let failure = classify(StatusCode::from_u16(status).unwrap(), "http://h/p");
            assert!(matches!(failure, Failure::Fatal(_)), "{status}");
        }
    }

    #[test]
    fn backoff_doubles_and_stops_at_two_seconds() {
        assert_eq!(backoff(1), Duration::from_millis(250));
        assert_eq!(backoff(2), Duration::from_millis(500));
        assert_eq!(backoff(3), Duration::from_secs(1));
        assert_eq!(backoff(4), Duration::from_secs(2));
        assert_eq!(backoff(9), Duration::from_secs(2));
    }

    #[test]
    fn basic_auth_and_extra_headers_reach_the_header_list() {
        let mut options = tls_options("https://example.com");
        options.basic_auth = Some(BasicAuth {
            user: "u".into(),
            password: "p".into(),
        });
        options.headers = vec![("x-trace".into(), "abc".into())];
        let fetcher = rt::block_on(Fetcher::new(options)).unwrap();
        let headers = &fetcher.inner.headers;
        let value = |name: HeaderName| {
            headers
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.to_str().unwrap().to_string())
        };
        assert_eq!(
            value(hyper::header::USER_AGENT).as_deref(),
            Some(USER_AGENT)
        );
        assert_eq!(
            value(HeaderName::from_static("x-trace")).as_deref(),
            Some("abc")
        );
        // base64("u:p")
        assert_eq!(
            value(hyper::header::AUTHORIZATION).as_deref(),
            Some("Basic dTpw")
        );
    }

    /// Options for a fetcher with no mirror, which serves the URLs its
    /// requests name. The anchors come from the fixture authority, so the
    /// constructor reads no host trust store, which an empty mirror list
    /// otherwise demands.
    fn mirrorless_options() -> FetcherOptions {
        FetcherOptions {
            mirrors: Vec::new(),
            ..tls_options("unused")
        }
    }

    /// Options for a fetcher at `url` that reaches every origin directly.
    ///
    /// A test that is not about the proxy states this. So the proxy variables
    /// of the host that runs the suite have no effect. The default form reads
    /// them, and a fetcher built under one goes to a proxy that no test
    /// started.
    fn direct_options(url: impl Into<String>) -> FetcherOptions {
        FetcherOptions {
            proxy: Proxy::None,
            ..FetcherOptions::new(url)
        }
    }

    /// Options for an `https` mirror whose anchors come from the fixture
    /// authority, so the constructor reads no host trust store.
    fn tls_options(url: &str) -> FetcherOptions {
        FetcherOptions {
            tls: TlsOptions {
                roots: TrustRoots::Pem(
                    include_bytes!("../../../tests/fixtures/tls/ca.pem").to_vec(),
                ),
                ..TlsOptions::default()
            },
            ..direct_options(url)
        }
    }

    /// A credential reaches every mirror, so one cleartext mirror is enough to
    /// refuse the configuration. Credentials named in `headers` are refused in
    /// the same way. Any other header is sent, whatever the scheme.
    #[test]
    fn credentials_alongside_a_cleartext_mirror_are_refused() {
        let auth = || {
            Some(BasicAuth {
                user: "u".into(),
                password: "p".into(),
            })
        };

        // The message names the cleartext mirror, also if it is one entry among
        // https entries.
        for mirrors in [
            vec!["http://cleartext.example/repo".to_owned()],
            vec![
                "https://secure.example/repo".to_owned(),
                "http://cleartext.example/repo".to_owned(),
            ],
        ] {
            let options = FetcherOptions {
                mirrors,
                basic_auth: auth(),
                ..tls_options("unused")
            };
            let err = rt::block_on(Fetcher::new(options)).unwrap_err();
            let message = err.to_string();
            assert!(message.contains("basic-auth credentials"), "{message}");
            assert!(
                message.contains("http://cleartext.example/repo"),
                "{message}"
            );
        }

        // Each header name that carries a credential, refused in the same way.
        for name in ["authorization", "proxy-authorization", "cookie"] {
            let options = FetcherOptions {
                headers: vec![(name.to_owned(), "secret".to_owned())],
                ..direct_options("http://cleartext.example/repo")
            };
            let err = rt::block_on(Fetcher::new(options)).unwrap_err();
            let message = err.to_string();
            assert!(message.contains(name), "{message}");
            assert!(message.contains("carries credentials"), "{message}");
        }

        // A header that is not a credential reaches a cleartext mirror.
        let options = FetcherOptions {
            headers: vec![("x-trace".to_owned(), "abc".to_owned())],
            ..direct_options("http://cleartext.example/repo")
        };
        rt::block_on(Fetcher::new(options)).unwrap();

        // With every mirror on https, both kinds are accepted.
        let options = FetcherOptions {
            mirrors: vec![
                "https://one.example/repo".to_owned(),
                "https://two.example/repo".to_owned(),
            ],
            basic_auth: auth(),
            headers: vec![("cookie".to_owned(), "session=1".to_owned())],
            ..tls_options("unused")
        };
        rt::block_on(Fetcher::new(options)).unwrap();
    }

    /// A request URL is served as it is written. The query string is part of
    /// the name of the request, and reaches the wire. Userinfo and a fragment
    /// are never sent, so the parse refuses them. The absolute URL, the
    /// origin-form target, the authority, and the origin all come from the one
    /// string of the destination.
    #[test]
    fn url_targets_are_parsed_and_validated() {
        // Every row states the URL, then the absolute URL, the origin-form
        // target, the authority, and the origin the parse produces.
        let rows = [
            (
                "https://example.com/repo/summary?sig=a%2Fb&x=1",
                "https://example.com/repo/summary?sig=a%2Fb&x=1",
                "/repo/summary?sig=a%2Fb&x=1",
                "example.com",
                "https://example.com",
            ),
            // A URL with no path of its own asks for the root, with or without
            // the trailing slash.
            ("http://h", "http://h/", "/", "h", "http://h"),
            ("http://h/", "http://h/", "/", "h", "http://h"),
            // An empty query is part of what the request names.
            ("http://h/p?", "http://h/p?", "/p?", "h", "http://h"),
            (
                "http://h/p?a=%2F&b=1",
                "http://h/p?a=%2F&b=1",
                "/p?a=%2F&b=1",
                "h",
                "http://h",
            ),
            // The default port of the scheme is left out of the authority, also
            // if the URL wrote it. The scheme is held in lower case.
            ("https://h:443/p", "https://h/p", "/p", "h", "https://h"),
            ("HTTP://h/p", "http://h/p", "/p", "h", "http://h"),
            // An IPv6 literal keeps its brackets in the authority, and a
            // non-default port stays with it.
            (
                "http://[2001:db8::1]:8080/r/config",
                "http://[2001:db8::1]:8080/r/config",
                "/r/config",
                "[2001:db8::1]:8080",
                "http://[2001:db8::1]:8080",
            ),
        ];
        for (url, absolute, target, authority, origin) in rows {
            let dest = parse_url(url).unwrap();
            assert_eq!(dest.url(), absolute, "{url}");
            assert_eq!(dest.target(), target, "{url}");
            assert_eq!(dest.authority, authority, "{url}");
            assert_eq!(dest.origin_url(), origin, "{url}");
        }

        let dest = parse_url("https://example.com/repo/summary?sig=a%2Fb&x=1").unwrap();
        assert_eq!(dest.origin.port, 443);
        assert!(dest.origin.tls);
        let root = parse_url("http://example.com").unwrap();
        assert_eq!(root.origin.port, 80);
        assert!(!root.origin.tls);
        // The address is held without the brackets of the authority.
        let ported = parse_url("http://[::1]:8080/r/config").unwrap();
        assert_eq!(ported.origin.host, "::1");
        assert_eq!(ported.origin.port, 8080);

        // The refusal names the scheme and the host, and leaves the password
        // out of a message a caller logs.
        let err = parse_url("https://alice:sup3rs3cret@example.com/p").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("userinfo"), "{message}");
        assert!(message.contains("https url for example.com"), "{message}");
        assert!(message.contains("FetchRequest::basic_auth"), "{message}");
        assert!(!message.contains("sup3rs3cret"), "{message}");

        let err = parse_url("https://example.com/p#frag").unwrap_err();
        assert!(err.to_string().contains("fragment"), "{err}");
        let err = parse_url("file:///srv/repo").unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        let err = parse_url("/srv/repo").unwrap_err();
        assert!(err.to_string().contains("not an absolute"), "{err}");
    }

    /// Each message about a URL whose authority the parse did not read yet
    /// leaves out the userinfo.
    #[test]
    fn a_password_reaches_no_message() {
        for url in [
            "https://alice:sup3rs3cret@example.com/p",
            "https://alice:sup3rs3cret@example.com/p#frag",
            "http://alice:sup3rs3cret@example.com/ p",
            "http://alice:sup3rs3cret@",
            "alice:sup3rs3cret@example.com/p",
        ] {
            let err = parse_url(url).unwrap_err();
            let message = err.to_string();
            assert!(!message.contains("sup3rs3cret"), "{url}: {message}");
        }

        // A password with a `/`, a `?`, or a `#` ends the authority before the
        // `@`. The userinfo is left out also in this case.
        for password in ["pa#ss", "pa?ss", "p/ss"] {
            let url = format!("https://alice:{password}@example.com/p");
            let message = parse_url(&url).unwrap_err().to_string();
            assert!(!message.contains(password), "{password}: {message}");
        }
    }

    /// `Uri` accepts an authority whose port it cannot read, and reports no
    /// port for it. So the parse refuses a URL that names such a port, and does
    /// not serve it from the default of the scheme.
    #[test]
    fn a_port_the_url_parser_cannot_read_is_refused() {
        for (url, text) in [
            ("http://h:99999/x", "99999"),
            ("http://h:65536/x", "65536"),
            ("http://h:abc/x", "abc"),
            ("http://h:/x", ""),
            // The integer parse of `std` takes a leading `+`, and a port is
            // ASCII digits alone.
            ("http://h:+80/x", "+80"),
        ] {
            let err = parse_url(url).unwrap_err();
            let message = err.to_string();
            assert!(message.contains(url), "{url}: {message}");
            assert!(message.contains(text), "{url}: {message}");
            assert!(message.contains("not a number"), "{url}: {message}");
            // A mirror URL is read by the same parse.
            assert!(parse_mirror(url).is_err(), "{url}");
        }

        // A URL with no port at all takes the scheme default, and a port the
        // parser reads is kept.
        let default = parse_url("http://h/x").unwrap();
        assert_eq!(default.origin.port, 80);
        assert_eq!(default.url(), "http://h/x");
        let ported = parse_url("http://h:8080/x").unwrap();
        assert_eq!(ported.origin.port, 8080);
        assert_eq!(ported.url(), "http://h:8080/x");
        // Leading zeros are digits: the port is the number they give.
        let zeros = parse_url("http://h:0080/x").unwrap();
        assert_eq!(zeros.origin.port, 80);
        assert_eq!(zeros.url(), "http://h/x");
    }

    /// A host is one origin in each case of its letters, so two spellings of
    /// one origin are one pool key.
    #[test]
    fn a_host_in_another_case_is_one_origin() {
        let upper = parse_url("http://LOCALHOST:8080/x").unwrap();
        let lower = parse_url("http://localhost:8080/x").unwrap();
        assert_eq!(upper.origin, lower.origin);
        assert_eq!(upper.origin.host, "localhost");
        // The authority reaches the wire as the caller wrote it.
        assert_eq!(upper.authority, "LOCALHOST:8080");
        assert_eq!(upper.url(), "http://LOCALHOST:8080/x");
    }

    /// The rendering of a struct with credentials leaves out the password.
    #[test]
    fn basic_auth_debug_holds_no_password() {
        let auth = BasicAuth {
            user: "alice".into(),
            password: "sup3rs3cret".into(),
        };
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("alice"), "{rendered}");
        assert!(!rendered.contains("sup3rs3cret"), "{rendered}");

        let request = FetchRequest {
            basic_auth: Some(&auth),
            ..FetchRequest::path("summary")
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("sup3rs3cret"), "{rendered}");

        let options = FetcherOptions {
            basic_auth: Some(auth),
            ..direct_options("https://example.com")
        };
        let rendered = format!("{options:?}");
        assert!(!rendered.contains("sup3rs3cret"), "{rendered}");
    }

    /// The origin of one absolute URL, which is what a proxy decision reads.
    fn origin_of(url: &str) -> Origin {
        parse_url(url).unwrap().origin
    }

    /// How a hop at `url` is reached: the proxy that it names, and the request
    /// form, which is the absolute form or a tunnel.
    fn via_of(proxies: &Proxies, url: &str) -> Option<(String, bool)> {
        match proxies.via(&origin_of(url)) {
            Via::Direct => None,
            Via::Absolute(proxy) => Some((proxy.named.clone(), false)),
            Via::Tunnel(proxy) => Some((proxy.named.clone(), true)),
        }
    }

    /// The variable list one test states, as the options carry it.
    fn variables(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// A proxy URL names an endpoint and nothing else. A path, a query, a
    /// fragment, or a scheme other than `http` states a value that a proxy
    /// connection has no place for. The constructor refuses each of them.
    #[test]
    fn a_proxy_url_names_an_http_endpoint() {
        // Every row states the URL, then the endpoint host, the port, and how a
        // diagnostic names the proxy.
        for (url, host, port, named) in [
            (
                "http://proxy.example",
                "proxy.example",
                80,
                "http://proxy.example",
            ),
            (
                "http://proxy.example:3128",
                "proxy.example",
                3128,
                "http://proxy.example:3128",
            ),
            // A path of `/` alone is the root, which is no path at all.
            (
                "http://proxy.example/",
                "proxy.example",
                80,
                "http://proxy.example",
            ),
            (
                "HTTP://Proxy.Example:3128",
                "proxy.example",
                3128,
                "http://Proxy.Example:3128",
            ),
            // An environment variable can carry space around its value. The
            // endpoint is read without it.
            (
                " http://proxy.example:3128 ",
                "proxy.example",
                3128,
                "http://proxy.example:3128",
            ),
            // An IPv6 literal keeps its brackets in the authority, and is held
            // without them. The connect resolves the bracketed form to nothing.
            ("http://[::1]:3128", "::1", 3128, "http://[::1]:3128"),
            (
                "http://alice:s3cret@proxy.example:3128",
                "proxy.example",
                3128,
                "http://proxy.example:3128",
            ),
        ] {
            let proxy = parse_proxy(url).unwrap_or_else(|e| panic!("{url}: {e}"));
            assert_eq!(proxy.endpoint.host, host, "{url}");
            assert_eq!(proxy.endpoint.port, port, "{url}");
            assert!(!proxy.endpoint.tls, "{url}");
            assert_eq!(proxy.named, named, "{url}");
        }

        // Userinfo is the credential of the proxy, after the percent-decode:
        // base64("alice:s3cret") and base64("al:ce:p@ss").
        let credential = |url: &str| {
            parse_proxy(url)
                .unwrap()
                .credential
                .map(|value| value.to_str().unwrap().to_owned())
        };
        assert_eq!(credential("http://proxy.example"), None);
        assert_eq!(
            credential("http://alice:s3cret@proxy.example").as_deref(),
            Some("Basic YWxpY2U6czNjcmV0")
        );
        assert_eq!(
            credential("http://al%3Ace:p%40ss@proxy.example").as_deref(),
            Some("Basic YWw6Y2U6cEBzcw==")
        );
        // A user with no password is userinfo too, and it is sent with the
        // empty password an `Authorization` value holds: base64("alice:").
        assert_eq!(
            credential("http://alice@proxy.example").as_deref(),
            Some("Basic YWxpY2U6")
        );

        // Every row states a URL the fetcher cannot connect through and a word
        // its refusal carries.
        for (url, says) in [
            ("socks5://proxy.example:1080", "http://host[:port] alone"),
            ("https://proxy.example:3128", "http://host[:port] alone"),
            ("proxy.example:3128", "http://host[:port] alone"),
            ("http://proxy.example/squid", "carries no path"),
            ("http://proxy.example/?upstream=1", "carries no query"),
            ("http://proxy.example/#frag", "carries no fragment"),
            ("http://", "invalid url"),
            ("http://proxy.example:99999", "not a number"),
            ("http://proxy.example:abc", "not a number"),
            ("http://alice:p%zz@proxy.example", "percent-encoded"),
            ("http://alice:p%4@proxy.example", "percent-encoded"),
        ] {
            let err = parse_proxy(url).unwrap_err();
            assert!(matches!(err, Error::Unsupported(_)), "{url}: {err}");
            let message = err.to_string();
            assert!(message.contains(says), "{url}: {message}");
        }
    }

    /// `http_proxy` serves cleartext origins, and `https_proxy` serves TLS
    /// origins. `all_proxy` serves both schemes if the scheme-specific variable
    /// is unset. Lower case wins over upper case, and an empty value counts as
    /// unset. Nothing reads `HTTP_PROXY`.
    #[test]
    fn the_proxy_variables_are_read_per_scheme() {
        let cleartext = "http://origin.example/summary";
        let tls = "https://origin.example/summary";
        let absolute = |named: &str| Some((named.to_owned(), false));
        let tunnel = |named: &str| Some((named.to_owned(), true));

        // Each scheme is served by its own variable, and the request form
        // follows the origin. Cleartext uses the absolute form over a proxy
        // connection, and TLS uses a tunnel.
        let proxies = resolve_variables(&variables(&[
            ("http_proxy", "http://plain.example:3128"),
            ("https_proxy", "http://secure.example:3128"),
        ]))
        .unwrap();
        assert_eq!(
            via_of(&proxies, cleartext),
            absolute("http://plain.example:3128")
        );
        assert_eq!(via_of(&proxies, tls), tunnel("http://secure.example:3128"));

        // One variable serves its own scheme alone.
        let proxies =
            resolve_variables(&variables(&[("http_proxy", "http://plain.example:3128")])).unwrap();
        assert_eq!(
            via_of(&proxies, cleartext),
            absolute("http://plain.example:3128")
        );
        assert_eq!(via_of(&proxies, tls), None);
        let proxies =
            resolve_variables(&variables(&[("https_proxy", "http://secure.example:3128")]))
                .unwrap();
        assert_eq!(via_of(&proxies, cleartext), None);
        assert_eq!(via_of(&proxies, tls), tunnel("http://secure.example:3128"));

        // `all_proxy` serves either scheme, and the scheme-specific variable
        // takes the scheme it names.
        let proxies =
            resolve_variables(&variables(&[("all_proxy", "http://any.example:3128")])).unwrap();
        assert_eq!(
            via_of(&proxies, cleartext),
            absolute("http://any.example:3128")
        );
        assert_eq!(via_of(&proxies, tls), tunnel("http://any.example:3128"));
        let proxies = resolve_variables(&variables(&[
            ("all_proxy", "http://any.example:3128"),
            ("https_proxy", "http://secure.example:3128"),
        ]))
        .unwrap();
        assert_eq!(
            via_of(&proxies, cleartext),
            absolute("http://any.example:3128")
        );
        assert_eq!(via_of(&proxies, tls), tunnel("http://secure.example:3128"));

        // The upper-case name is read for each variable except `http_proxy`. A
        // CGI gateway gives a request header called `Proxy` to its program
        // under that name.
        let proxies = resolve_variables(&variables(&[
            ("HTTP_PROXY", "http://cgi.example:3128"),
            ("HTTPS_PROXY", "http://secure.example:3128"),
        ]))
        .unwrap();
        assert_eq!(via_of(&proxies, cleartext), None);
        assert_eq!(via_of(&proxies, tls), tunnel("http://secure.example:3128"));
        let proxies =
            resolve_variables(&variables(&[("ALL_PROXY", "http://any.example:3128")])).unwrap();
        assert_eq!(
            via_of(&proxies, cleartext),
            absolute("http://any.example:3128")
        );

        // Lower case wins over upper case, and an empty value counts as unset.
        // So the upper-case name is the one that is read.
        let proxies = resolve_variables(&variables(&[
            ("https_proxy", "http://lower.example:3128"),
            ("HTTPS_PROXY", "http://upper.example:3128"),
        ]))
        .unwrap();
        assert_eq!(via_of(&proxies, tls), tunnel("http://lower.example:3128"));
        let proxies = resolve_variables(&variables(&[
            ("https_proxy", ""),
            ("HTTPS_PROXY", "http://upper.example:3128"),
        ]))
        .unwrap();
        assert_eq!(via_of(&proxies, tls), tunnel("http://upper.example:3128"));
        let proxies = resolve_variables(&variables(&[("http_proxy", "")])).unwrap();
        assert_eq!(via_of(&proxies, cleartext), None);

        // A value the fetcher cannot connect through fails the resolution
        // whichever variable held it.
        for name in ["http_proxy", "https_proxy", "all_proxy"] {
            let err = resolve_variables(&variables(&[(name, "socks5://proxy.example:1080")]))
                .unwrap_err();
            assert!(matches!(err, Error::Unsupported(_)), "{name}: {err}");
        }
        // A variable that the selection passes over is parsed too. An
        // `all_proxy` beside both scheme-specific variables is read by no
        // fetch. If it holds a value that the fetcher cannot connect through,
        // the resolution fails.
        let err = resolve_variables(&variables(&[
            ("all_proxy", "socks5://proxy.example:1080"),
            ("http_proxy", "http://plain.example:3128"),
            ("https_proxy", "http://secure.example:3128"),
        ]))
        .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");

        // No variable at all, and the explicit forms of the option.
        let proxies = resolve_variables(&[]).unwrap();
        assert_eq!(via_of(&proxies, cleartext), None);
        assert_eq!(via_of(&proxies, tls), None);
        let proxies = resolve_proxy(&Proxy::None).unwrap();
        assert_eq!(via_of(&proxies, cleartext), None);
        // One URL serves every origin, and it reads no exemption.
        let proxies = resolve_proxy(&Proxy::Url("http://any.example:3128".into())).unwrap();
        assert_eq!(
            via_of(&proxies, cleartext),
            absolute("http://any.example:3128")
        );
        assert_eq!(via_of(&proxies, tls), tunnel("http://any.example:3128"));
    }

    /// A proxy variable with white space at the start or the end of its value
    /// fails the resolution, also a value of white space alone. The message
    /// names the variable, and holds nothing of the value. Each variable that
    /// the selection reads is checked, also if no fetch uses it. A variable
    /// that the selection does not read is not checked.
    #[test]
    fn a_proxy_variable_with_white_space_around_it_is_refused() {
        let url = "http://alice:s3cret@proxy.example:3128";
        let refused = |pairs: &[(&str, &str)], name: &str| {
            let err = resolve_variables(&variables(pairs)).unwrap_err();
            assert!(matches!(err, Error::Unsupported(_)), "{pairs:?}: {err}");
            let message = err.to_string();
            assert!(message.contains(name), "{pairs:?}: {message}");
            assert!(!message.contains("s3cret"), "{pairs:?}: {message}");
            assert!(!message.contains("proxy.example"), "{pairs:?}: {message}");
        };

        for name in [
            "http_proxy",
            "https_proxy",
            "HTTPS_PROXY",
            "all_proxy",
            "ALL_PROXY",
        ] {
            for value in [
                format!(" {url}"),
                format!("{url} "),
                format!("{url}\t"),
                format!("{url}\n"),
                format!("{url}\u{a0}"),
                "   ".to_owned(),
            ] {
                refused(&[(name, &value)], name);
            }
        }
        // If the lower-case value is empty, the upper-case name is read, and
        // the refusal names it.
        refused(
            &[("all_proxy", ""), ("ALL_PROXY", "http://p:1 ")],
            "ALL_PROXY",
        );
        // The check comes before the parse, so a value the parse refuses as
        // well gets the white-space refusal.
        refused(
            &[("all_proxy", "socks5://alice:s3cret@proxy.example:1080 ")],
            "all_proxy",
        );
        // The refusal occurs when the fetcher is built. So an exemption of
        // every origin does not prevent it.
        refused(
            &[("http_proxy", &format!("{url} ")), ("no_proxy", "*")],
            "http_proxy",
        );
        // `all_proxy` beside both scheme-specific variables is read by no
        // fetch, and the check still reads its value.
        refused(
            &[
                ("all_proxy", &format!("{url} ")),
                ("http_proxy", "http://plain.example:3128"),
                ("https_proxy", "http://secure.example:3128"),
            ],
            "all_proxy",
        );

        // An upper-case name shadowed by its lower-case one is not read, and
        // `HTTP_PROXY` is read by nothing.
        resolve_variables(&variables(&[
            ("https_proxy", "http://secure.example:3128"),
            ("HTTPS_PROXY", "http://upper.example:3128 "),
        ]))
        .unwrap();
        resolve_variables(&variables(&[("HTTP_PROXY", "http://cgi.example:3128 ")])).unwrap();
        // A URL the caller states in the options keeps its trim.
        resolve_proxy(&Proxy::Url("http://p:3128 ".into())).unwrap();
    }

    /// What `no_proxy` exempts: an exact host, a host under a listed domain, a
    /// port-qualified entry, and every host under `*`. The match is made
    /// against the host text and never against the address it resolves to.
    #[test]
    fn no_proxy_exempts_by_host_text_and_port() {
        let proxied = |no_proxy: &str, url: &str| {
            let proxies = resolve_variables(&variables(&[
                ("all_proxy", "http://any.example:3128"),
                ("no_proxy", no_proxy),
            ]))
            .unwrap();
            via_of(&proxies, url).is_some()
        };

        // An exact host, and a host of another name at the same domain.
        assert!(!proxied("origin.example", "http://origin.example/p"));
        assert!(proxied("origin.example", "http://other.example/p"));
        // A host under a listed domain, in each of the two spellings of the
        // entry. A name that only ends with the same letters is not exempted.
        for entry in ["example.com", ".example.com"] {
            assert!(!proxied(entry, "http://a.example.com/p"));
            assert!(!proxied(entry, "http://deep.a.example.com/p"));
            assert!(!proxied(entry, "http://example.com/p"));
            assert!(proxied(entry, "http://notexample.com/p"));
        }
        // The list is comma-separated, space around an entry is ignored, and an
        // empty entry names nothing.
        assert!(!proxied(" a.example , b.example ", "http://b.example/p"));
        assert!(!proxied("a.example,,b.example", "http://a.example/p"));
        assert!(proxied(",", "http://a.example/p"));
        assert!(proxied("", "http://a.example/p"));
        // ASCII case is ignored on both sides.
        assert!(!proxied("ORIGIN.example", "http://origin.EXAMPLE/p"));
        // A port-qualified entry matches that port alone.
        assert!(!proxied(
            "origin.example:8080",
            "http://origin.example:8080/p"
        ));
        assert!(proxied(
            "origin.example:8080",
            "http://origin.example:8081/p"
        ));
        assert!(proxied("origin.example:8080", "http://origin.example/p"));
        assert!(!proxied("origin.example:443", "https://origin.example/p"));
        // An entry with no port matches whatever port the origin names.
        assert!(!proxied("origin.example", "http://origin.example:8080/p"));
        // `*` exempts every host, whatever else the list holds.
        for url in ["http://a.example/p", "https://b.example:8443/p"] {
            assert!(!proxied("*", url));
            assert!(!proxied("a.example,*", url));
        }
        // An IP literal matches that text and nothing else. So the address of a
        // name does not exempt the name, and a name does not exempt an address.
        assert!(!proxied("127.0.0.1", "http://127.0.0.1:8080/p"));
        assert!(proxied("localhost", "http://127.0.0.1:8080/p"));
        assert!(proxied("127.0.0.1", "http://localhost:8080/p"));
        // An IPv6 literal is exempted by the address alone, written with or
        // without the brackets the authority carries.
        for entry in ["::1", "[::1]", "[::1]:8080"] {
            assert!(!proxied(entry, "http://[::1]:8080/p"), "{entry}");
        }
        assert!(proxied("[::1]:8081", "http://[::1]:8080/p"));
        // A network in CIDR notation names no network here: it is read as a
        // host text, which no origin holds.
        assert!(proxied("127.0.0.0/8", "http://127.0.0.1:8080/p"));
        // A port text that is no port leaves the entry as one host text, which
        // no origin host holds.
        assert!(proxied("origin.example:abc", "http://origin.example/p"));
        // An entry that names no host exempts nothing, also for a host written
        // with a trailing `.`.
        for entry in [".", ":8080", ".:8080"] {
            assert!(proxied(entry, "http://a.example./p"), "{entry}");
            assert!(proxied(entry, "http://a.example:8080/p"), "{entry}");
        }
        // One leading `.` is stripped, so a second belongs to the host text the
        // entry names.
        assert!(proxied("..example.com", "http://a.example.com/p"));
        // `*` as a whole entry is the one wildcard of the list. Each other form
        // with a `*` is a host text.
        assert!(proxied("*.example.com", "http://a.example.com/p"));
        assert!(proxied("*.example.com", "http://example.com/p"));
    }

    /// The userinfo of a proxy URL holds a password. So it reaches neither a
    /// rendering of the options nor a refusal of the constructor.
    #[test]
    fn a_proxy_password_reaches_no_message() {
        let url = |tail: &str| format!("http://alice:sup3rs3cret@proxy.example:3128{tail}");

        // The rendering of every form that carries a URL.
        for proxy in [
            Proxy::Url(url("")),
            Proxy::Variables(vec![("https_proxy".to_owned(), url(""))]),
        ] {
            let rendered = format!("{proxy:?}");
            assert!(!rendered.contains("sup3rs3cret"), "{rendered}");
            assert!(rendered.contains("proxy.example:3128"), "{rendered}");

            let options = FetcherOptions {
                proxy,
                ..direct_options("https://example.com")
            };
            let rendered = format!("{options:?}");
            assert!(!rendered.contains("sup3rs3cret"), "{rendered}");
        }

        // Each refusal, whichever part of the URL the parse read.
        for tail in ["/squid", "/?upstream=1", "/#frag", ":99999"] {
            let err = parse_proxy(&url(tail)).unwrap_err();
            let message = err.to_string();
            assert!(!message.contains("sup3rs3cret"), "{tail}: {message}");
        }
        let err = parse_proxy("socks5://alice:sup3rs3cret@proxy.example:1080").unwrap_err();
        assert!(!err.to_string().contains("sup3rs3cret"), "{err}");

        // A password with a `/`, a `?`, or a `#` ends the authority before the
        // `@`. The userinfo is left out also in this case.
        for password in ["pa#ss", "pa?ss", "p/ss"] {
            let url = format!("http://alice:{password}@proxy.example:3128/squid");
            let rendered = format!("{:?}", Proxy::Url(url.clone()));
            assert!(!rendered.contains(password), "{password}: {rendered}");
            assert!(
                rendered.contains("proxy.example:3128"),
                "{password}: {rendered}"
            );
            let message = parse_proxy(&url).unwrap_err().to_string();
            assert!(!message.contains(password), "{password}: {message}");
            assert!(
                message.contains("proxy.example:3128"),
                "{password}: {message}"
            );
        }

        // A `/` or a `?` in the userinfo moves the text after it into the path
        // or the query. The refusal of that path or query shows no part of it.
        for userinfo in ["u/pw-QXZ", "tok?pw-QXZ", "u:x/pw-QXZ", "u:x?pw-QXZ"] {
            let url = format!("http://{userinfo}@proxy.invalid:3128");
            let message = parse_proxy(&url).unwrap_err().to_string();
            assert!(!message.contains("pw-QXZ"), "{userinfo}: {message}");
        }

        // The refusal the constructor writes is the one a caller logs.
        rt::block_on(async {
            let err = Fetcher::new(FetcherOptions {
                proxy: Proxy::Url(url("/squid")),
                ..direct_options("http://origin.example/repo")
            })
            .await
            .unwrap_err();
            assert!(matches!(err, Error::Unsupported(_)), "{err}");
            let message = err.to_string();
            assert!(!message.contains("sup3rs3cret"), "{message}");
            assert!(message.contains("proxy.example:3128"), "{message}");
        });
    }

    /// The `Debug` of a proxy writes each URL as `RedactedUrl` writes it. The
    /// form of each variant is the form of `derive(Debug)`.
    #[test]
    fn proxy_debug_redacts_each_url() {
        let url = "http://alice:pw-QXZ@proxy.example:3128/?t=QXZ#QXZ";
        assert_eq!(
            format!("{:?}", Proxy::Url(url.to_owned())),
            r#"Url("http://proxy.example:3128/?<redacted>#<redacted>")"#
        );
        let variables = Proxy::Variables(vec![
            ("https_proxy".to_owned(), url.to_owned()),
            ("no_proxy".to_owned(), ".internal.example.com".to_owned()),
        ]);
        assert_eq!(
            format!("{variables:?}"),
            concat!(
                r#"Variables([("https_proxy", "http://proxy.example:3128/?<redacted>#<redacted>"), "#,
                r#"("no_proxy", ".internal.example.com")])"#
            )
        );
        assert_eq!(format!("{:?}", Proxy::None), "None");
        assert_eq!(format!("{:?}", Proxy::Environment), "Environment");
    }

    /// The text before `://` is a scheme only when it is a valid scheme. Else
    /// the userinfo starts at the start of the text.
    #[test]
    fn without_userinfo_reads_only_a_valid_scheme() {
        assert_eq!(without_userinfo("u:a://b@h/p"), "h/p");
        assert_eq!(without_userinfo("svn+ssh://u@h/p"), "svn+ssh://h/p");
        assert_eq!(without_userinfo("https://h/p"), "https://h/p");
        assert_eq!(scheme_len("1http://h"), 0);
        assert_eq!(scheme_len("://h"), 0);
        assert_eq!(scheme_len("h/p"), 0);
    }

    /// A `CONNECT` names its target by host and port, and always writes the
    /// port. The proxy opens a TCP connection, which reads no scheme.
    #[test]
    fn a_connect_names_the_target_with_its_port() {
        for (url, authority) in [
            ("https://origin.example/p", "origin.example:443"),
            ("https://origin.example:8443/p", "origin.example:8443"),
            ("http://origin.example/p", "origin.example:80"),
            ("https://[2001:db8::1]/p", "[2001:db8::1]:443"),
            ("https://[::1]:8443/p", "[::1]:8443"),
        ] {
            assert_eq!(connect_authority(&origin_of(url)), authority, "{url}");
        }
    }

    /// A proxied cleartext request carries the absolute-form target and the
    /// `Host` header of the origin. It also carries the credential of the
    /// proxy, if the merged headers hold no header of that name. A direct
    /// request and the request over a tunnel carry the origin form and nothing
    /// of the proxy.
    #[test]
    fn a_proxied_cleartext_request_carries_the_absolute_form() {
        rt::block_on(async {
            let fetcher = Fetcher::new(FetcherOptions {
                proxy: Proxy::Url("http://alice:s3cret@proxy.example:3128".into()),
                ..tls_options("http://origin.example/r")
            })
            .await
            .unwrap();
            let destination = fetcher.inner.mirrors[0].destination("refs/heads/a", None);
            let request = FetchRequest::path("refs/heads/a");
            let built = |via: Via<'_>, headers: &[(HeaderName, HeaderValue)]| {
                fetcher
                    .build_request(&destination, &request, headers, Protocol::Http11, via)
                    .unwrap()
            };
            let proxy_credential = |request: &Request<RequestBody>| {
                request
                    .headers()
                    .get(hyper::header::PROXY_AUTHORIZATION)
                    .map(|value| value.to_str().unwrap().to_owned())
            };
            let Via::Absolute(proxy) = fetcher.inner.proxies.via(&destination.origin) else {
                panic!("a cleartext origin behind a proxy travels in absolute form");
            };
            let via = Via::Absolute(proxy);

            let absolute = built(via, &fetcher.inner.headers);
            assert_eq!(absolute.uri(), "http://origin.example/r/refs/heads/a");
            assert_eq!(
                absolute.headers().get(hyper::header::HOST).unwrap(),
                "origin.example"
            );
            // base64("alice:s3cret")
            assert_eq!(
                proxy_credential(&absolute).as_deref(),
                Some("Basic YWxpY2U6czNjcmV0")
            );

            // A `Proxy-Authorization` header that the caller set states the
            // value for the proxy. So the credential of the fetcher is left
            // out, and is not added to it.
            let mut headers = fetcher.inner.headers.clone();
            headers.push((
                hyper::header::PROXY_AUTHORIZATION,
                HeaderValue::from_static("Basic Y2FsbGVy"),
            ));
            let caller = built(via, &headers);
            assert_eq!(
                caller
                    .headers()
                    .get_all(hyper::header::PROXY_AUTHORIZATION)
                    .iter()
                    .count(),
                1
            );
            assert_eq!(proxy_credential(&caller).as_deref(), Some("Basic Y2FsbGVy"));

            // A direct hop and the request over a tunnel carry the origin form
            // and nothing of the proxy.
            for via in [Via::Direct, Via::Tunnel(proxy)] {
                let direct = built(via, &fetcher.inner.headers);
                assert_eq!(direct.uri(), "/r/refs/heads/a");
                assert_eq!(proxy_credential(&direct), None);
            }
        });
    }

    /// The connection layer frames a request and holds its connection. So a
    /// header of one of those names is refused. The constructor refuses a
    /// fetcher header, and a request header fails before admission.
    #[test]
    fn a_connection_header_is_refused_at_both_layers() {
        let fetcher_headers = vec![(
            HeaderName::from_static("x-trace"),
            HeaderValue::from_static("abc"),
        )];
        for name in CONNECTION_HEADERS {
            let options = FetcherOptions {
                headers: vec![(name.to_owned(), "10".to_owned())],
                ..direct_options("http://example.com")
            };
            let err = rt::block_on(Fetcher::new(options)).unwrap_err();
            let message = err.to_string();
            assert!(message.contains(name), "{name}: {message}");
            assert!(message.contains("connection layer"), "{name}: {message}");

            let request = vec![(name.to_owned(), "10".to_owned())];
            let err = merge_headers(&fetcher_headers, &request, None, None).unwrap_err();
            let message = err.to_string();
            assert!(message.contains(name), "{name}: {message}");
            assert!(message.contains("connection layer"), "{name}: {message}");
        }

        // A name written in another case is the same header name.
        let request = vec![("Content-Length".to_owned(), "10".to_owned())];
        let err = merge_headers(&fetcher_headers, &request, None, None).unwrap_err();
        assert!(err.to_string().contains("content-length"), "{err}");
    }

    /// A request that adds no header and no credentials sends the list of the
    /// fetcher by reference. A request header replaces the fetcher header of
    /// the same name. The credentials of the request replace the
    /// `Authorization` of the fetcher.
    #[test]
    fn request_headers_merge_over_the_fetchers() {
        let header = |name: &'static str, value: &'static str| {
            (
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            )
        };
        let fetcher = vec![
            header("x-trace", "fetcher"),
            header("x-only", "yes"),
            header("authorization", "Basic ZmV0Y2hlcg=="),
        ];
        let sent = |headers: &[(HeaderName, HeaderValue)]| {
            headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap().to_owned()))
                .collect::<Vec<_>>()
        };

        let borrowed = merge_headers(&fetcher, &[], None, None).unwrap();
        assert!(matches!(borrowed, Cow::Borrowed(_)));
        assert_eq!(sent(&borrowed), sent(&fetcher));

        // The replacement compares names as header names, so the case that the
        // request wrote has no effect. It leaves each other fetcher header in
        // place. Two request headers of one name both reach the wire.
        let extra = vec![
            ("X-Trace".to_owned(), "request".to_owned()),
            ("x-trace".to_owned(), "second".to_owned()),
        ];
        let merged = merge_headers(&fetcher, &extra, None, None).unwrap();
        assert_eq!(
            sent(&merged),
            [
                ("x-only".to_owned(), "yes".to_owned()),
                ("authorization".to_owned(), "Basic ZmV0Y2hlcg==".to_owned()),
                ("x-trace".to_owned(), "request".to_owned()),
                ("x-trace".to_owned(), "second".to_owned()),
            ]
        );

        // base64("u:p")
        let auth = BasicAuth {
            user: "u".into(),
            password: "p".into(),
        };
        let merged = merge_headers(&fetcher, &[], Some(&auth), None).unwrap();
        assert_eq!(
            sent(&merged),
            [
                ("x-trace".to_owned(), "fetcher".to_owned()),
                ("x-only".to_owned(), "yes".to_owned()),
                ("authorization".to_owned(), "Basic dTpw".to_owned()),
            ]
        );

        let both = vec![("authorization".to_owned(), "Basic aaa".to_owned())];
        let err = merge_headers(&fetcher, &both, Some(&auth), None).unwrap_err();
        assert!(err.to_string().contains("pass one of them"), "{err}");
        let host = vec![("host".to_owned(), "elsewhere".to_owned())];
        let err = merge_headers(&fetcher, &host, None, None).unwrap_err();
        assert!(err.to_string().contains("host header"), "{err}");
        let invalid = vec![("not a header".to_owned(), "v".to_owned())];
        let err = merge_headers(&fetcher, &invalid, None, None).unwrap_err();
        assert!(err.to_string().contains("invalid header name"), "{err}");
    }

    /// A fetch delivers the bytes that the remote stores. So a response is
    /// served only if it declares no coding, or declares `identity`. A value is
    /// a comma-separated list, and several headers state one list together. A
    /// token compares with no case and with no space around it.
    #[test]
    fn a_declared_content_coding_is_read_off_the_response() {
        let map = |values: &[&str]| {
            let mut headers = hyper::HeaderMap::new();
            for value in values {
                headers.append(
                    hyper::header::CONTENT_ENCODING,
                    HeaderValue::try_from(*value).unwrap(),
                );
            }
            headers
        };

        // Nothing to undo: no header at all, an empty value, a value of
        // separators alone, and every spelling of the one coding that is served.
        for values in [
            vec![],
            vec![""],
            vec![","],
            vec!["identity"],
            vec!["IDENTITY"],
            vec![" identity "],
            vec!["identity", "identity"],
        ] {
            assert_eq!(declared_coding(&map(&values)), None, "{values:?}");
        }

        // A coding that the body needs a decode from, named as the response
        // wrote it. A list with one coding refuses the whole response, at each
        // position of the coding. Several headers are read together, in the
        // order of arrival. A value whose tokens are all empty names nothing,
        // so it adds no separator to the message.
        for (values, named) in [
            (vec!["gzip"], "gzip"),
            (vec!["GZip"], "GZip"),
            (vec!["identity, gzip"], "identity, gzip"),
            (vec!["gzip, identity"], "gzip, identity"),
            (vec!["identity", "gzip"], "identity, gzip"),
            (vec!["gzip", "br"], "gzip, br"),
            (vec!["", "gzip"], "gzip"),
            (vec!["gzip", ""], "gzip"),
            (vec!["gzip", "", "br"], "gzip, br"),
            (vec!["gzip", ",", "br"], "gzip, br"),
        ] {
            assert_eq!(
                declared_coding(&map(&values)).as_deref(),
                Some(named),
                "{values:?}"
            );
        }
    }

    /// Each request asks for no content coding. A configured header with a
    /// name that the fetcher sets replaces that entry, and does not join it on
    /// the wire.
    #[test]
    fn a_fetcher_header_replaces_the_entry_the_fetcher_sets() {
        let sent = |fetcher: &Fetcher, name: HeaderName| {
            fetcher
                .inner
                .headers
                .iter()
                .filter(|(held, _)| *held == name)
                .map(|(_, value)| value.to_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };

        let fetcher = rt::block_on(Fetcher::new(direct_options("http://example.com"))).unwrap();
        assert_eq!(
            sent(&fetcher, hyper::header::ACCEPT_ENCODING),
            [IDENTITY.to_owned()]
        );

        for name in ["accept-encoding", "user-agent"] {
            let options = FetcherOptions {
                headers: vec![(name.to_owned(), "caller".to_owned())],
                ..direct_options("http://example.com")
            };
            let fetcher = rt::block_on(Fetcher::new(options)).unwrap();
            let header = HeaderName::from_static(name);
            assert_eq!(sent(&fetcher, header), ["caller".to_owned()], "{name}");
        }

        // Two entries of one name both reach the wire. The first of them
        // replaces the entry that the fetcher sets.
        let options = FetcherOptions {
            headers: vec![
                ("accept-encoding".to_owned(), "one".to_owned()),
                ("Accept-Encoding".to_owned(), "two".to_owned()),
            ],
            ..direct_options("http://example.com")
        };
        let fetcher = rt::block_on(Fetcher::new(options)).unwrap();
        assert_eq!(
            sent(&fetcher, hyper::header::ACCEPT_ENCODING),
            ["one".to_owned(), "two".to_owned()]
        );
        // A name under which the fetcher sets nothing also keeps both entries.
        let options = FetcherOptions {
            headers: vec![
                ("x-trace".to_owned(), "one".to_owned()),
                ("x-trace".to_owned(), "two".to_owned()),
            ],
            ..direct_options("http://example.com")
        };
        let fetcher = rt::block_on(Fetcher::new(options)).unwrap();
        assert_eq!(
            sent(&fetcher, HeaderName::from_static("x-trace")),
            ["one".to_owned(), "two".to_owned()]
        );
    }

    /// A credential is withheld from no destination. So one cleartext
    /// destination that a fetch can reach refuses it, and the message names
    /// the origin. A header that is not a credential reaches a cleartext
    /// destination.
    #[test]
    fn a_credential_refuses_a_cleartext_destination() {
        let credential = vec![(hyper::header::COOKIE, HeaderValue::from_static("session=1"))];
        let plain = vec![(
            HeaderName::from_static("x-trace"),
            HeaderValue::from_static("abc"),
        )];
        // A fetcher whose mirror list holds one cleartext entry among https
        // entries. The credential belongs to the request, so the construction
        // check of the list does not refuse it.
        let options = FetcherOptions {
            mirrors: vec![
                "https://secure.example/repo".to_owned(),
                "http://cleartext.example/repo".to_owned(),
            ],
            ..tls_options("unused")
        };
        let fetcher = rt::block_on(Fetcher::new(options)).unwrap();

        let mirrors = fetcher.route(Target::Path("summary")).unwrap();
        let err = fetcher.check_cleartext(&mirrors, &credential).unwrap_err();
        assert!(
            err.to_string().contains("http://cleartext.example"),
            "{err}"
        );
        fetcher.check_cleartext(&mirrors, &plain).unwrap();

        let cleartext = fetcher
            .route(Target::Url("http://cleartext.example/p"))
            .unwrap();
        let err = fetcher
            .check_cleartext(&cleartext, &credential)
            .unwrap_err();
        assert!(
            err.to_string().contains("http://cleartext.example"),
            "{err}"
        );
        fetcher.check_cleartext(&cleartext, &plain).unwrap();

        let secure = fetcher
            .route(Target::Url("https://secure.example/p"))
            .unwrap();
        fetcher.check_cleartext(&secure, &credential).unwrap();
    }

    /// A handshake verifies the server certificate against a trust anchor. So
    /// if the fetcher holds none, a fetch of a TLS origin is refused before
    /// admission, and the message names the origin.
    ///
    /// A clear flag stands for a fetcher built on a host whose trust store
    /// holds nothing. The test sets the flag by hand, because this host has a
    /// CA bundle. `TrustRoots::Pem` fails the constructor over a blob that
    /// holds no certificate.
    #[test]
    fn a_tls_destination_needs_a_trust_anchor() {
        rt::block_on(async {
            let mut fetcher = Fetcher::new(direct_options("http://cleartext.example/repo"))
                .await
                .unwrap();
            Arc::get_mut(&mut fetcher.inner)
                .expect("the one handle on this fetcher")
                .has_trust_anchors = false;

            // Nothing listens on port 1 of the loopback. So an attempt fails
            // its connect, and the fetcher tries again through each round and
            // each backoff. The refusal is definitive and takes no attempt, so
            // it resolves at once.
            let refused = within(
                Duration::from_secs(1),
                fetcher.fetch(FetchRequest::url("https://127.0.0.1:1/summary")),
            )
            .await;
            let err = refused
                .expect("the refusal takes no attempt")
                .expect_err("a tls url is refused without anchors");
            let message = err.to_string();
            assert!(message.contains("https://127.0.0.1:1"), "{message}");
            assert!(message.contains("no trust anchors"), "{message}");

            // A cleartext destination opens no handshake, so it is served by
            // the same fetcher.
            let cleartext = fetcher
                .route(Target::Url("http://cleartext.example/summary"))
                .unwrap();
            fetcher.check_trust_anchors(&cleartext).unwrap();
            let mirrors = fetcher.route(Target::Path("summary")).unwrap();
            fetcher.check_trust_anchors(&mirrors).unwrap();
        });
    }

    /// The constructor reads the host trust store only if a fetch can open a
    /// handshake. A fetcher whose mirrors are all `http`, and that follows no
    /// redirect, reads no store and holds no anchor. It refuses a URL target
    /// that names an `https` origin. An `https` mirror, an empty mirror list, and
    /// a redirect limit above zero each read the store.
    #[test]
    fn a_cleartext_fetcher_with_no_redirect_reads_no_trust_store() {
        let reads = || tls::SYSTEM_STORE_READS.with(std::cell::Cell::get);
        rt::block_on(async {
            let before = reads();
            let fetcher = Fetcher::new(FetcherOptions {
                max_redirects: 0,
                ..direct_options("http://cleartext.example/repo")
            })
            .await
            .unwrap();
            assert_eq!(reads(), before, "the store was read");
            assert!(!fetcher.inner.has_trust_anchors);
            let refused = within(
                Duration::from_secs(1),
                fetcher.fetch(FetchRequest::url("https://127.0.0.1:1/summary")),
            )
            .await
            .expect("the refusal takes no attempt")
            .expect_err("a tls url is refused without anchors");
            assert!(
                refused.to_string().contains("no trust anchors"),
                "{refused}"
            );

            let cases = [
                direct_options("http://cleartext.example/repo"),
                FetcherOptions {
                    max_redirects: 0,
                    ..direct_options("https://tls.example/repo")
                },
                FetcherOptions {
                    max_redirects: 0,
                    proxy: Proxy::None,
                    ..FetcherOptions::default()
                },
            ];
            for options in cases {
                let before = reads();
                let what = format!("{:?} {}", options.mirrors, options.max_redirects);
                // A host with no CA bundle fails the `https` cases, after the
                // read.
                let _ = Fetcher::new(options).await;
                assert_eq!(reads(), before + 1, "{what}");
            }
        });
    }

    /// The server chooses the origin of a redirect. So a hop to a TLS origin
    /// gets the refusal that a route to a TLS origin gets. The fetcher holds
    /// nothing to verify the certificate against. With no refusal, the
    /// handshake fails retryably with a message about the peer, and spends
    /// each round and each backoff.
    ///
    /// The test sets the flag by hand, for the reason that
    /// `a_tls_destination_needs_a_trust_anchor` states.
    ///
    /// The two peers are raw sockets: one answers a redirect to the other, and
    /// the other reports how many connections reached it.
    #[test]
    fn a_redirect_to_a_tls_origin_needs_a_trust_anchor() {
        use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
        use std::sync::atomic::{AtomicUsize, Ordering};

        rt::block_on(async {
            // The origin that the redirect names. Nothing connects to it, and
            // the count reports this.
            let tls_peer = rt::TcpListener::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let tls_port = tls_peer.local_addr().unwrap().port();
            let connections = Arc::new(AtomicUsize::new(0));
            let counted = connections.clone();
            drop(rt::spawn(async move {
                while let Ok((stream, _peer)) = tls_peer.accept().await {
                    counted.fetch_add(1, Ordering::SeqCst);
                    drop(stream);
                }
            }));

            let cleartext_peer = rt::TcpListener::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let cleartext_port = cleartext_peer.local_addr().unwrap().port();
            let requests = Arc::new(AtomicUsize::new(0));
            let counted = requests.clone();
            drop(rt::spawn(async move {
                while let Ok((mut stream, _peer)) = cleartext_peer.accept().await {
                    let mut request = [0u8; 1024];
                    let _ = stream.read(&mut request).await;
                    counted.fetch_add(1, Ordering::SeqCst);
                    let answer = format!(
                        "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:{tls_port}/hopped\r\n\
                         Content-Length: 0\r\n\r\n"
                    );
                    let _ = stream.write_all(answer.as_bytes()).await;
                    let _ = stream.flush().await;
                }
            }));

            let mut fetcher =
                Fetcher::new(direct_options(format!("http://127.0.0.1:{cleartext_port}")))
                    .await
                    .unwrap();
            Arc::get_mut(&mut fetcher.inner)
                .expect("the one handle on this fetcher")
                .has_trust_anchors = false;

            // Six rounds of a retryable handshake failure and their backoffs
            // run for more than five seconds. So only a refusal that ends the
            // attempt resolves inside this window.
            let refused = within(
                Duration::from_secs(2),
                fetcher.fetch(FetchRequest::path("summary")),
            )
            .await;
            let err = refused
                .expect("the refusal ends the attempt")
                .expect_err("a tls hop is refused without anchors");
            let message = err.to_string();
            assert!(
                message.contains(&format!("https://127.0.0.1:{tls_port}")),
                "{message}"
            );
            assert!(message.contains("no trust anchors"), "{message}");
            assert_eq!(requests.load(Ordering::SeqCst), 1);
            assert_eq!(connections.load(Ordering::SeqCst), 0);
        });
    }

    /// The reading end of a channel body, taken out of the body as an upload
    /// takes it.
    fn channel() -> (BodyEnd, UploadWriter) {
        let (body, writer) = UploadBody::channel();
        let UploadForm::Channel(end) = body.form else {
            panic!("a channel body holds its reading end");
        };
        (end, writer)
    }

    /// The next frame of `end`, as the bytes it carries.
    async fn next_frame(end: &mut BodyEnd) -> Option<std::io::Result<Bytes>> {
        let frame = std::future::poll_fn(|cx| end.poll_frame(cx)).await?;
        Some(frame.map(|frame| frame.into_data().expect("an upload body yields data")))
    }

    /// The writer hands the body over in frames of 64 KiB, a close hands over
    /// what is left, and the end follows the last frame. The close completes
    /// when the reading end gives the end.
    #[test]
    fn a_writer_hands_over_frames_of_64_kib() {
        rt::block_on(async {
            let (mut end, mut writer) = channel();
            let data = (0..150_000u32).map(|i| i as u8).collect::<Vec<_>>();
            let written = async {
                futures_lite::io::AsyncWriteExt::write_all(&mut writer, &data).await?;
                futures_lite::io::AsyncWriteExt::close(&mut writer).await
            };
            let read = async {
                let mut frames = Vec::new();
                while let Some(frame) = next_frame(&mut end).await {
                    frames.push(frame.unwrap());
                }
                frames
            };
            let (written, frames) = futures_lite::future::zip(written, read).await;
            written.unwrap();
            assert_eq!(
                frames.iter().map(Bytes::len).collect::<Vec<_>>(),
                [UPLOAD_FRAME, UPLOAD_FRAME, 150_000 - 2 * UPLOAD_FRAME]
            );
            assert_eq!(frames.concat(), data);
            assert!(end.is_end_stream());
            assert!(end.exchange.lock().ended);
            assert_eq!(end.exchange.exact, None);
        });
    }

    /// A flush hands over a part-filled frame, and completes when hyper takes
    /// it.
    #[test]
    fn a_flush_hands_over_a_part_filled_frame() {
        rt::block_on(async {
            let (mut end, mut writer) = channel();
            let flushed = async {
                futures_lite::io::AsyncWriteExt::write_all(&mut writer, b"hello").await?;
                futures_lite::io::AsyncWriteExt::flush(&mut writer).await
            };
            let (flushed, frame) = futures_lite::future::zip(flushed, next_frame(&mut end)).await;
            flushed.unwrap();
            assert_eq!(frame.unwrap().unwrap(), &b"hello"[..]);
            assert!(!end.is_end_stream());
        });
    }

    /// A writer reports the hand-over of its request, and a request given
    /// back unwritten is no longer handed over.
    #[test]
    fn a_writer_reports_the_hand_over() {
        let (end, writer) = channel();
        assert!(!writer.is_handed_over());
        end.exchange.hand_over(Duration::from_secs(1)).unwrap();
        assert!(writer.is_handed_over());
        end.exchange.withdraw();
        assert!(!writer.is_handed_over());
    }

    /// A writer holds no buffer until its first write. A flush of less than
    /// 4 KiB hands over a copy and keeps the frame buffer. A larger flush
    /// hands the buffer over, and the next one is allocated at the next
    /// write.
    #[test]
    fn a_small_flush_hands_over_a_copy_and_keeps_the_buffer() {
        rt::block_on(async {
            let (mut end, mut writer) = channel();
            assert_eq!(writer.buffer.capacity(), 0);
            futures_lite::io::AsyncWriteExt::write_all(&mut writer, b"small")
                .await
                .unwrap();
            assert_eq!(writer.buffer.capacity(), UPLOAD_FRAME);
            let kept = writer.buffer.as_ptr();
            let flushed = futures_lite::io::AsyncWriteExt::flush(&mut writer);
            let (flushed, frame) = futures_lite::future::zip(flushed, next_frame(&mut end)).await;
            flushed.unwrap();
            assert_eq!(frame.unwrap().unwrap(), &b"small"[..]);
            assert!(writer.buffer.is_empty());
            assert_eq!(writer.buffer.as_ptr(), kept);
            assert_eq!(writer.buffer.capacity(), UPLOAD_FRAME);

            let large = vec![7u8; SMALL_FRAME];
            let flushed = async {
                futures_lite::io::AsyncWriteExt::write_all(&mut writer, &large).await?;
                futures_lite::io::AsyncWriteExt::flush(&mut writer).await
            };
            let (flushed, frame) = futures_lite::future::zip(flushed, next_frame(&mut end)).await;
            flushed.unwrap();
            assert_eq!(frame.unwrap().unwrap(), large);
            assert_eq!(writer.buffer.capacity(), 0);
            futures_lite::io::AsyncWriteExt::write_all(&mut writer, b"x")
                .await
                .unwrap();
            assert_eq!(writer.buffer.capacity(), UPLOAD_FRAME);
        });
    }

    /// A writer dropped before close fails the body, so hyper never reads a
    /// clean end for a body cut short.
    #[test]
    fn a_writer_dropped_unclosed_fails_the_body() {
        rt::block_on(async {
            let (mut end, mut writer) = channel();
            futures_lite::io::AsyncWriteExt::write_all(&mut writer, b"part")
                .await
                .unwrap();
            drop(writer);
            let err = next_frame(&mut end).await.unwrap().unwrap_err();
            assert!(err.to_string().contains("dropped"), "{err}");
            assert!(!end.is_end_stream());
            assert!(!end.exchange.lock().ended);
            // The failure stands for every later poll.
            assert!(next_frame(&mut end).await.unwrap().is_err());
        });
    }

    /// Once the reading end is gone, a write, a flush, and a close fail with
    /// a broken pipe.
    #[test]
    fn a_write_after_the_reading_end_is_gone_is_a_broken_pipe() {
        rt::block_on(async {
            let (end, mut writer) = channel();
            drop(end);
            let err = futures_lite::io::AsyncWriteExt::write_all(&mut writer, b"late")
                .await
                .unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
            let err = futures_lite::io::AsyncWriteExt::flush(&mut writer)
                .await
                .unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
        });
    }

    /// A write after close is a broken pipe.
    #[test]
    fn a_write_after_close_is_a_broken_pipe() {
        rt::block_on(async {
            let (mut end, mut writer) = channel();
            let closed = futures_lite::io::AsyncWriteExt::close(&mut writer);
            let (closed, frame) = futures_lite::future::zip(closed, next_frame(&mut end)).await;
            closed.unwrap();
            assert!(frame.is_none());
            let err = futures_lite::io::AsyncWriteExt::write_all(&mut writer, b"x")
                .await
                .unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
        });
    }

    /// A frame that waits in the slot past the stall window fails the write
    /// with a timeout, and fails the body. The failure is latched. Before
    /// an upload starts the window, a full slot is no stall.
    #[test]
    fn a_frame_not_taken_within_the_window_fails_the_write() {
        rt::block_on(async {
            let (mut end, mut writer) = channel();
            let frame = vec![0u8; UPLOAD_FRAME];
            // The first frame fills the buffer, the second hands it to the
            // slot, and the third waits for the slot.
            for _ in 0..2 {
                futures_lite::io::AsyncWriteExt::write_all(&mut writer, &frame)
                    .await
                    .unwrap();
            }
            let unbounded = within(
                Duration::from_millis(100),
                futures_lite::io::AsyncWriteExt::write_all(&mut writer, &frame),
            )
            .await;
            assert!(unbounded.is_none(), "a wait before the upload has no bound");

            end.exchange.hand_over(Duration::from_millis(50)).unwrap();
            let started = Instant::now();
            let err = futures_lite::io::AsyncWriteExt::write_all(&mut writer, &frame)
                .await
                .unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
            assert!(started.elapsed() >= Duration::from_millis(50));
            let again = futures_lite::io::AsyncWriteExt::write_all(&mut writer, b"x")
                .await
                .unwrap_err();
            assert_eq!(again.kind(), std::io::ErrorKind::TimedOut);
            let failed = next_frame(&mut end).await.unwrap().unwrap_err();
            assert!(failed.to_string().contains("not taken"), "{failed}");
        });
    }

    /// A body given whole declares its length and travels in frames of 64 KiB
    /// cut from its bytes with no copy. It reaches its end with the last
    /// frame. An empty body is at its end at the hand-over. The hand-over
    /// reports this, so the request can declare a length of zero.
    #[test]
    fn a_whole_body_travels_in_frames_of_a_declared_length() {
        rt::block_on(async {
            let bytes = Bytes::from((0..150_000u32).map(|i| i as u8).collect::<Vec<_>>());
            let mut end = BodyEnd::whole(&bytes);
            assert_eq!(end.exchange.exact, Some(150_000));
            assert_eq!(end.exchange.hand_over(Duration::from_secs(60)), Ok(false));
            assert!(!end.is_end_stream());
            let mut at = 0;
            for len in [UPLOAD_FRAME, UPLOAD_FRAME, 150_000 - 2 * UPLOAD_FRAME] {
                assert!(!end.exchange.lock().ended);
                let frame = next_frame(&mut end).await.unwrap().unwrap();
                assert_eq!(frame.len(), len);
                assert_eq!(frame.as_ptr(), bytes[at..].as_ptr());
                at += len;
            }
            assert!(end.exchange.lock().ended);
            assert!(end.is_end_stream());
            assert!(next_frame(&mut end).await.is_none());

            let empty = BodyEnd::whole(&Bytes::new());
            assert_eq!(empty.exchange.exact, Some(0));
            assert!(!empty.is_end_stream());
            assert_eq!(empty.exchange.hand_over(Duration::from_secs(60)), Ok(true));
            assert!(empty.is_end_stream());
            assert!(empty.exchange.lock().ended);
        });
    }

    /// A channel body that reaches its end after the hand-over is framed as a
    /// stream: hyper learns of the end from its first poll.
    #[test]
    fn a_body_closed_after_the_hand_over_ends_at_the_first_poll() {
        rt::block_on(async {
            let (mut end, mut writer) = channel();
            assert_eq!(end.exchange.hand_over(Duration::from_secs(60)), Ok(false));
            end.exchange.lock().closed = true;
            assert!(!end.is_end_stream());
            assert!(next_frame(&mut end).await.is_none());
            assert!(end.is_end_stream());
            futures_lite::io::AsyncWriteExt::close(&mut writer)
                .await
                .unwrap();
        });
    }

    /// The timer of a window whose end moves later is armed once, fires at
    /// the first end, and is armed again for the rest alone.
    #[test]
    fn a_lazy_timer_fires_at_the_end_it_was_moved_to() {
        rt::block_on(async {
            let mut timer = None;
            let started = Instant::now();
            let mut end = started + Duration::from_millis(50);
            std::future::poll_fn(|cx| {
                if poll_until(&mut timer, cx, end).is_pending() {
                    end = started + Duration::from_millis(120);
                    return Poll::Pending;
                }
                Poll::Ready(())
            })
            .await;
            assert!(started.elapsed() >= Duration::from_millis(120));
            assert!(timer.is_none());
        });
    }

    /// A bearer token holds the token68 syntax, and a refusal names no part
    /// of it. The bearer and the Basic values are marked sensitive, and so is
    /// a credential header the caller sets.
    #[test]
    fn a_bearer_token_is_token68_and_sensitive() {
        let token = |token: &str| BearerToken {
            token: token.to_owned(),
        };
        for good in ["abc", "a-b.c_d~e+f/g", "dGVzdA==", "x="] {
            assert!(is_token68(good), "{good}");
        }
        for bad in ["", "=", "a b", "a=b", "tök", "a\n", "a,b"] {
            assert!(!is_token68(bad), "{bad:?}");
            let err = merge_headers(&[], &[], None, Some(&token(bad))).unwrap_err();
            let message = err.to_string();
            assert!(message.contains("token68"), "{message}");
            assert!(!message.contains("  "), "{message}");
            if !bad.is_empty() && bad != "=" {
                assert!(!message.contains(bad), "{message}");
            }
        }

        let authorization = |headers: &[(HeaderName, HeaderValue)]| {
            headers
                .iter()
                .find(|(name, _)| *name == hyper::header::AUTHORIZATION)
                .map(|(_, value)| value.clone())
                .unwrap()
        };
        let merged = merge_headers(&[], &[], None, Some(&token("t0k3n"))).unwrap();
        let value = authorization(&merged);
        assert_eq!(value, "Bearer t0k3n");
        assert!(value.is_sensitive());

        let auth = BasicAuth {
            user: "u".into(),
            password: "p".into(),
        };
        let merged = merge_headers(&[], &[], Some(&auth), None).unwrap();
        assert!(authorization(&merged).is_sensitive());
        let header = vec![("authorization".to_owned(), "Custom x".to_owned())];
        let merged = merge_headers(&[], &header, None, None).unwrap();
        assert!(authorization(&merged).is_sensitive());

        let err = merge_headers(&[], &[], Some(&auth), Some(&token("t"))).unwrap_err();
        assert!(err.to_string().contains("pass one of them"), "{err}");
        assert!(err.to_string().contains("bearer token"), "{err}");
        let err = merge_headers(&[], &header, None, Some(&token("t"))).unwrap_err();
        assert!(err.to_string().contains("pass one of them"), "{err}");
        assert!(err.to_string().contains("bearer token"), "{err}");
    }

    #[test]
    fn bearer_token_debug_holds_no_token() {
        let token = BearerToken {
            token: "s3cret".into(),
        };
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("s3cret"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    /// The bearer token of the fetcher is one sensitive `Authorization` entry
    /// in the header list. A request without a credential sends it. Each of
    /// these replaces it for one request: the `basic_auth` of the request, the
    /// `bearer_token` of the request, or an `Authorization` header of the
    /// request.
    #[test]
    fn a_fetcher_bearer_token_joins_the_header_list() {
        let options = FetcherOptions {
            bearer_token: Some(BearerToken {
                token: "t0k3n".into(),
            }),
            ..tls_options("https://example.com")
        };
        let fetcher = rt::block_on(Fetcher::new(options)).unwrap();
        let authorization = |headers: &[(HeaderName, HeaderValue)]| {
            headers
                .iter()
                .filter(|(name, _)| *name == hyper::header::AUTHORIZATION)
                .map(|(_, value)| value.clone())
                .collect::<Vec<_>>()
        };
        let held = authorization(&fetcher.inner.headers);
        assert_eq!(held, ["Bearer t0k3n"]);
        assert!(held[0].is_sensitive());

        let extra = vec![("x-trace".to_owned(), "abc".to_owned())];
        let merged = merge_headers(&fetcher.inner.headers, &extra, None, None).unwrap();
        assert_eq!(authorization(&merged), ["Bearer t0k3n"]);

        // base64("u:p")
        let auth = BasicAuth {
            user: "u".into(),
            password: "p".into(),
        };
        let merged = merge_headers(&fetcher.inner.headers, &[], Some(&auth), None).unwrap();
        assert_eq!(authorization(&merged), ["Basic dTpw"]);
        let token = BearerToken {
            token: "other".into(),
        };
        let merged = merge_headers(&fetcher.inner.headers, &[], None, Some(&token)).unwrap();
        assert_eq!(authorization(&merged), ["Bearer other"]);
        let header = vec![("authorization".to_owned(), "Custom x".to_owned())];
        let merged = merge_headers(&fetcher.inner.headers, &header, None, None).unwrap();
        assert_eq!(authorization(&merged), ["Custom x"]);
    }

    /// The constructor refuses the bearer token of the fetcher beside another
    /// value for `Authorization`, and a token outside the token68 syntax. A
    /// refusal names no part of the token.
    #[test]
    fn a_fetcher_bearer_token_is_refused_beside_another_credential_or_out_of_syntax() {
        let token = |token: &str| {
            Some(BearerToken {
                token: token.to_owned(),
            })
        };
        let beside_basic = FetcherOptions {
            bearer_token: token("t0k3n"),
            basic_auth: Some(BasicAuth {
                user: "u".into(),
                password: "p".into(),
            }),
            ..tls_options("https://example.com")
        };
        let beside_header = FetcherOptions {
            bearer_token: token("t0k3n"),
            headers: vec![("authorization".into(), "Basic aaa".into())],
            ..tls_options("https://example.com")
        };
        for options in [beside_basic, beside_header] {
            let err = rt::block_on(Fetcher::new(options)).unwrap_err();
            let message = err.to_string();
            assert!(message.contains("bearer token"), "{message}");
            assert!(message.contains("pass one of them"), "{message}");
        }

        let options = FetcherOptions {
            bearer_token: token("not a token"),
            ..tls_options("https://example.com")
        };
        let err = rt::block_on(Fetcher::new(options)).unwrap_err();
        assert!(matches!(err, Error::Fetch(_)), "{err}");
        let message = err.to_string();
        assert!(message.contains("token68"), "{message}");
        assert!(!message.contains("not a token"), "{message}");
    }

    /// A credential of the fetcher fails the constructor beside a cleartext
    /// mirror. The cleartext permission of the fetcher admits each kind of
    /// credential.
    #[test]
    fn the_fetcher_cleartext_permission_admits_a_cleartext_mirror() {
        let cleartext = "http://cleartext.example/repo";
        let token = || {
            Some(BearerToken {
                token: "t0k3n".into(),
            })
        };
        let options = FetcherOptions {
            bearer_token: token(),
            ..tls_options(cleartext)
        };
        let err = rt::block_on(Fetcher::new(options)).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("bearer token"), "{message}");
        assert!(message.contains(cleartext), "{message}");
        assert!(
            message.contains("FetcherOptions::allow_cleartext_credentials"),
            "{message}"
        );
        assert!(!message.contains("t0k3n"), "{message}");

        let options = FetcherOptions {
            bearer_token: token(),
            allow_cleartext_credentials: true,
            ..tls_options(cleartext)
        };
        let fetcher = rt::block_on(Fetcher::new(options)).unwrap();
        assert!(
            fetcher.inner.headers.iter().any(
                |(name, value)| name == hyper::header::AUTHORIZATION && value == "Bearer t0k3n"
            )
        );

        let options = FetcherOptions {
            basic_auth: Some(BasicAuth {
                user: "u".into(),
                password: "p".into(),
            }),
            allow_cleartext_credentials: true,
            ..tls_options(cleartext)
        };
        rt::block_on(Fetcher::new(options)).unwrap();
        let options = FetcherOptions {
            headers: vec![("cookie".into(), "session=1".into())],
            allow_cleartext_credentials: true,
            ..tls_options(cleartext)
        };
        rt::block_on(Fetcher::new(options)).unwrap();
    }

    /// A signer that returns one fixed header, or fails if it holds no header.
    #[derive(Debug)]
    struct FixedSigner {
        header: Option<(String, String)>,
    }

    impl RequestSigner for FixedSigner {
        fn sign(&self, _request: &SignRequest<'_>) -> Result<Vec<(String, String)>> {
            match &self.header {
                Some(header) => Ok(vec![header.clone()]),
                None => Err(Error::Fetch("the signer has no key".into())),
            }
        }
    }

    fn fixed_signer() -> Option<Arc<dyn RequestSigner>> {
        Some(Arc::new(FixedSigner {
            header: Some(("authorization".into(), "Fixed x".into())),
        }))
    }

    /// The constructor refuses a signer beside another value for
    /// `Authorization`. A signer is a credential, so a cleartext mirror fails
    /// the constructor unless the fetcher permits it.
    #[test]
    fn a_signer_is_refused_beside_basic_auth_a_bearer_token_or_an_authorization_header() {
        let beside_basic = FetcherOptions {
            signer: fixed_signer(),
            basic_auth: Some(BasicAuth {
                user: "u".into(),
                password: "p".into(),
            }),
            ..tls_options("https://example.com")
        };
        let beside_bearer = FetcherOptions {
            signer: fixed_signer(),
            bearer_token: Some(BearerToken {
                token: "t0k3n".into(),
            }),
            ..tls_options("https://example.com")
        };
        let beside_header = FetcherOptions {
            signer: fixed_signer(),
            headers: vec![("Authorization".into(), "Basic aaa".into())],
            ..tls_options("https://example.com")
        };
        for (options, other) in [
            (beside_basic, "basic-auth credentials"),
            (beside_bearer, "a bearer token"),
            (beside_header, "an authorization header"),
        ] {
            let err = rt::block_on(Fetcher::new(options)).unwrap_err();
            assert!(matches!(err, Error::Fetch(_)), "{err}");
            let message = err.to_string();
            assert!(message.contains("request signer"), "{message}");
            assert!(message.contains(other), "{message}");
            assert!(message.contains("pass one of them"), "{message}");
        }

        // Another header goes beside the signer.
        let options = FetcherOptions {
            signer: fixed_signer(),
            headers: vec![("x-trace".into(), "abc".into())],
            ..tls_options("https://example.com")
        };
        rt::block_on(Fetcher::new(options)).unwrap();

        let cleartext = "http://cleartext.example/repo";
        let options = FetcherOptions {
            signer: fixed_signer(),
            ..tls_options(cleartext)
        };
        let err = rt::block_on(Fetcher::new(options)).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("request signer"), "{message}");
        assert!(message.contains(cleartext), "{message}");
        assert!(
            message.contains("FetcherOptions::allow_cleartext_credentials"),
            "{message}"
        );
        let options = FetcherOptions {
            signer: fixed_signer(),
            allow_cleartext_credentials: true,
            ..tls_options(cleartext)
        };
        rt::block_on(Fetcher::new(options)).unwrap();
    }

    /// The request that a signer gets names the method, the authority of the
    /// `Host` header, and the path and the query of the request target.
    #[test]
    fn a_sign_request_carries_the_wire_authority_path_and_query() {
        let get = Method::GET;
        let put = Method::PUT;

        // A mirror with a base path and the default port of its scheme.
        let mirror = parse_mirror("https://Example.com:443/base/repo/").unwrap();
        let hop = mirror.destination("objects/ab/cd.file", None);
        let request = sign_request(&get, &hop, SignPayload::Empty);
        assert_eq!(request.method, "GET");
        assert_eq!(request.authority, "Example.com");
        assert_eq!(request.authority, hop.authority.to_str().unwrap());
        assert_eq!(request.path, "/base/repo/objects/ab/cd.file");
        assert_eq!(request.query, None);
        assert_eq!(request.payload, SignPayload::Empty);

        // A port other than the default, and a query.
        let mirror = parse_mirror("http://example.com:8080").unwrap();
        let hop = mirror.destination("summary", Some("x-id=1&b=%2F"));
        let request = sign_request(&get, &hop, SignPayload::Empty);
        assert_eq!(request.authority, "example.com:8080");
        assert_eq!(request.path, "/summary");
        assert_eq!(request.query, Some("x-id=1&b=%2F"));

        // An IPv6 literal keeps its brackets. An empty query is not `None`.
        let body = b"abc";
        let hop = parse_url("https://[::1]:8443/a/b?").unwrap();
        let request = sign_request(&put, &hop, SignPayload::Bytes(body));
        assert_eq!(request.method, "PUT");
        assert_eq!(request.authority, "[::1]:8443");
        assert_eq!(request.path, "/a/b");
        assert_eq!(request.query, Some(""));
        assert_eq!(request.payload, SignPayload::Bytes(b"abc"));
        assert_eq!(format!("{:?}", request.payload), "Bytes(3)");

        let hop = parse_url("https://[::1]/").unwrap();
        let request = sign_request(&put, &hop, SignPayload::Streamed);
        assert_eq!(request.authority, "[::1]");
        assert_eq!(request.path, "/");
        assert_eq!(request.query, None);
    }

    /// A signer that gives each `+` of a request path as `%2B`, as a signer of
    /// a canonical path does.
    #[derive(Debug)]
    struct PlusSigner;

    impl RequestSigner for PlusSigner {
        fn sign(&self, _request: &SignRequest<'_>) -> Result<Vec<(String, String)>> {
            Ok(Vec::new())
        }

        fn request_path<'a>(&self, path: &'a str) -> Result<Cow<'a, str>> {
            Ok(Cow::Owned(path.replace('+', "%2B")))
        }
    }

    /// The path of a path target goes through the signer, and the request
    /// target carries the form that the signer gives. The query does not.
    /// With no signer, or with a signer that keeps the default method, the
    /// path goes as written. A URL target goes as written with each signer.
    #[test]
    fn a_signer_gives_the_form_of_a_request_path() {
        rt::block_on(async {
            let cases: [(Option<Arc<dyn RequestSigner>>, &str); 3] = [
                (None, "/r/deltas/a+/b"),
                (fixed_signer(), "/r/deltas/a+/b"),
                (Some(Arc::new(PlusSigner)), "/r/deltas/a%2B/b"),
            ];
            for (signer, want) in cases {
                let fetcher = Fetcher::new(FetcherOptions {
                    signer,
                    allow_cleartext_credentials: true,
                    ..direct_options("http://example.com/r")
                })
                .await
                .unwrap();
                let targets = [
                    (Target::Path("deltas/a+/b"), want.to_owned()),
                    (
                        Target::PathQuery {
                            path: "deltas/a+/b",
                            query: "x=a+",
                        },
                        format!("{want}?x=a+"),
                    ),
                ];
                for (target, wire) in targets {
                    let Route::Mirrors { path, query } = fetcher.route(target).unwrap() else {
                        panic!("a path target goes to the mirrors");
                    };
                    let destination = fetcher.inner.mirrors[0].destination(&path, query);
                    let request = fetcher
                        .build_request(
                            &destination,
                            &FetchRequest::for_target(target),
                            &fetcher.inner.headers,
                            Protocol::Http11,
                            Via::Direct,
                        )
                        .unwrap();
                    assert_eq!(request.uri(), wire.as_str(), "{target:?}");
                }
                let Route::One(destination) = fetcher
                    .route(Target::Url("http://example.com/r/deltas/a+/b"))
                    .unwrap()
                else {
                    panic!("a url target names one destination");
                };
                assert_eq!(destination.target(), "/r/deltas/a+/b");
            }
        });
    }

    /// The headers of a signer replace the headers of the same name, and each
    /// of their values is marked sensitive, whatever its name is. A refused
    /// header and an error of the signer end the request.
    #[test]
    fn signed_headers_replace_their_names_and_failures_are_final() {
        let fetcher = rt::block_on(Fetcher::new(FetcherOptions {
            headers: vec![("x-amz-date".into(), "old".into())],
            ..tls_options("https://example.com")
        }))
        .unwrap();
        let hop = parse_url("https://example.com/x").unwrap();
        let signer = FixedSigner {
            header: Some(("x-amz-date".into(), "new".into())),
        };
        let merged = signed(
            &signer,
            &Method::GET,
            &hop,
            SignPayload::Empty,
            &fetcher.inner.headers,
        )
        .ok()
        .unwrap();
        let dates = merged
            .iter()
            .filter(|(name, _)| name == "x-amz-date")
            .map(|(_, value)| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(dates, ["new"]);
        for (name, value) in merged.iter() {
            assert_eq!(value.is_sensitive(), name == "x-amz-date", "{name}");
        }

        // A header that is not a credential by its name is sensitive too, so
        // an HTTP/2 connection never indexes a session token.
        let signer = FixedSigner {
            header: Some(("X-Amz-Security-Token".into(), "session".into())),
        };
        let merged = signed(&signer, &Method::GET, &hop, SignPayload::Empty, &[])
            .ok()
            .unwrap();
        assert_eq!(merged.len(), 1);
        assert!(merged[0].1.is_sensitive());

        let signer = FixedSigner {
            header: Some(("authorization".into(), "Fixed x".into())),
        };
        let merged = signed(&signer, &Method::GET, &hop, SignPayload::Empty, &[])
            .ok()
            .unwrap();
        assert!(merged[0].1.is_sensitive());

        for signer in [
            FixedSigner { header: None },
            FixedSigner {
                header: Some(("host".into(), "elsewhere".into())),
            },
        ] {
            let failure = signed(&signer, &Method::GET, &hop, SignPayload::Empty, &[]);
            assert!(matches!(failure, Err(Failure::Final(Error::Fetch(_)))));
        }
    }

    #[test]
    fn fetcher_options_debug_holds_no_bearer_token() {
        let options = FetcherOptions {
            bearer_token: Some(BearerToken {
                token: "s3cret".into(),
            }),
            ..FetcherOptions::default()
        };
        let rendered = format!("{options:?}");
        assert!(!rendered.contains("s3cret"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    /// Headers whose values hold the marker `QXZ`, which no `Debug` output
    /// shows.
    fn secret_headers() -> Vec<(String, String)> {
        vec![
            ("Authorization".into(), "Basic val-QXZ-1".into()),
            ("proxy-authorization".into(), "Basic val-QXZ-2".into()),
            ("cookie".into(), "id=val-QXZ-3".into()),
            ("X-Trace".into(), "val-QXZ-4".into()),
        ]
    }

    /// The `Debug` output of the headers of [`secret_headers`].
    const SECRET_HEADERS_SHOWN: &str = r#"[("Authorization", "<redacted>"), ("proxy-authorization", "<redacted>"), ("cookie", "<redacted>"), ("X-Trace", "<redacted>")]"#;

    /// Checks that `rendered` shows each header of [`secret_headers`] with
    /// `<redacted>`, and no header value.
    fn assert_no_header_value(rendered: &str) {
        assert!(!rendered.contains("QXZ"), "{rendered}");
        for (name, _) in secret_headers() {
            let entry = format!(r#"("{name}", "<redacted>")"#);
            assert!(rendered.contains(&entry), "{rendered}");
        }
    }

    /// The `Debug` output of the options shows each header name and no header
    /// value. Each other field shows as its own `Debug` shows it, in the order
    /// of declaration.
    #[test]
    fn fetcher_options_debug_holds_no_header_value() {
        let options = FetcherOptions {
            headers: secret_headers(),
            ..FetcherOptions::new("https://example.com/")
        };
        let rendered = format!("{options:?}");
        assert_no_header_value(&rendered);
        assert_eq!(
            rendered,
            format!(
                "FetcherOptions {{ mirrors: [\"https://example.com/\"], \
                 headers: {SECRET_HEADERS_SHOWN}, basic_auth: None, bearer_token: None, \
                 signer: None, allow_cleartext_credentials: false, \
                 tls: TlsOptions {{ roots: System, client_identity: None }}, \
                 proxy: Environment, http2: true, max_retries: 5, max_redirects: 10, \
                 max_outstanding: 8, connect_timeout: 30s, progress_timeout: 60s, \
                 low_speed: None, fetch_timeout: Some(300s) }}"
            )
        );
    }

    /// The `Debug` output of a fetch request shows each header name and no
    /// header value. Each other field shows as its own `Debug` shows it.
    #[test]
    fn fetch_request_debug_holds_no_header_value() {
        let headers = secret_headers();
        let request = FetchRequest {
            headers: &headers,
            max_error_body: Some(4096),
            ..FetchRequest::path("summary")
        };
        let rendered = format!("{request:?}");
        assert_no_header_value(&rendered);
        assert_eq!(
            rendered,
            format!(
                "FetchRequest {{ target: Path(\"summary\"), priority: Normal, \
                 validators: None, max_size: None, headers: {SECRET_HEADERS_SHOWN}, \
                 basic_auth: None, allow_cleartext_credentials: false, \
                 max_error_body: Some(4096) }}"
            )
        );
    }

    /// The `Debug` output of a kept error response shows the name of each
    /// header and the length of the body. It shows no header value and no
    /// byte of the body, in the response and in the error that carries it.
    #[test]
    fn an_error_response_debug_holds_no_header_value_and_no_body() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::SET_COOKIE,
            HeaderValue::from_static("session=QXZ"),
        );
        let response = ErrorResponse::new(headers, Some(b"SECRETBODY".to_vec()));
        assert_eq!(
            format!("{response:?}"),
            "ErrorResponse { headers: [(\"set-cookie\", \"<redacted>\")], body: Some(10) }"
        );
        let error = Error::HttpStatus {
            status: 403,
            url: "https://h/x".into(),
            response: Some(Box::new(response)),
        };
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("QXZ"), "{rendered}");
        assert!(!rendered.contains("SECRETBODY"), "{rendered}");
        assert_eq!(error.to_string(), "http status 403 for https://h/x");
    }

    /// An error response gives back the headers and the body that it was
    /// built from.
    #[test]
    fn an_error_response_keeps_its_parts() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-amz-bucket-region", HeaderValue::from_static("eu-west-1"));
        let response = ErrorResponse::new(headers.clone(), Some(b"<Error/>".to_vec()));
        assert_eq!(response.headers(), &headers);
        assert_eq!(response.body(), Some(&b"<Error/>"[..]));
        let headless = ErrorResponse::new(hyper::HeaderMap::new(), None);
        assert!(headless.headers().is_empty());
        assert_eq!(headless.body(), None);
    }

    /// A body of bytes has a copy that shares its buffer. A streamed body has
    /// no copy.
    #[test]
    fn a_bytes_body_clones_and_a_channel_body_does_not() {
        let body = UploadBody::bytes(b"part".to_vec());
        let copy = body.try_clone().expect("a bytes body has a copy");
        let (UploadForm::Bytes { bytes: first, .. }, UploadForm::Bytes { bytes: second, .. }) =
            (&body.form, &copy.form)
        else {
            panic!("the copy of a bytes body is a bytes body");
        };
        assert_eq!(first, second);
        assert_eq!(first.as_ptr(), second.as_ptr());
        let (channel, _writer) = UploadBody::channel();
        assert!(channel.try_clone().is_none());
    }

    /// A body of bytes gives its buffer back when no copy shares it. A
    /// shared body and a streamed body come back unchanged.
    #[test]
    fn a_bytes_body_gives_its_buffer_back_when_it_is_not_shared() {
        // A vector with spare capacity, and a vector with none.
        for mut bytes in [Vec::with_capacity(16), Vec::with_capacity(4)] {
            bytes.extend_from_slice(b"part");
            let (address, capacity) = (bytes.as_ptr(), bytes.capacity());
            let body = UploadBody::bytes(bytes);
            let copy = body.try_clone().expect("a bytes body has a copy");
            let Err(body) = body.into_vec() else {
                panic!("a shared body is not given back");
            };
            assert_eq!(body.as_bytes(), Some(&b"part"[..]));
            drop(copy);
            let Ok(bytes) = body.into_vec() else {
                panic!("a body with no copy gives its buffer back");
            };
            assert_eq!(bytes, b"part");
            assert_eq!(bytes.as_ptr(), address);
            assert_eq!(bytes.capacity(), capacity);
        }
        let (channel, _writer) = UploadBody::channel();
        let Err(channel) = channel.into_vec() else {
            panic!("a streamed body has no buffer");
        };
        assert!(channel.as_bytes().is_none());
    }

    /// A body with a digest keeps the digest in a copy and in a body that
    /// is not given back. The buffer that comes back holds no digest. The
    /// `Debug` output of its payload shows the length of the body.
    #[test]
    fn a_body_with_a_digest_keeps_it_in_a_copy_and_gives_the_buffer_back() {
        let digest = [7u8; 32];
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(b"part");
        let (address, capacity) = (bytes.as_ptr(), bytes.capacity());
        let body = UploadBody::bytes_with_sha256(bytes, digest);
        assert_eq!(body.sha256(), Some(digest));
        assert_eq!(body.as_bytes(), Some(&b"part"[..]));
        assert_eq!(format!("{body:?}"), "Bytes(4)");
        let copy = body.try_clone().expect("a bytes body has a copy");
        assert_eq!(copy.sha256(), Some(digest));
        assert_eq!(copy.as_bytes(), Some(&b"part"[..]));
        let Err(body) = body.into_vec() else {
            panic!("a shared body is not given back");
        };
        assert_eq!(body.sha256(), Some(digest));
        drop(copy);
        let Ok(bytes) = body.into_vec() else {
            panic!("a body with no copy gives its buffer back");
        };
        assert_eq!(bytes, b"part");
        assert_eq!(bytes.as_ptr(), address);
        assert_eq!(bytes.capacity(), capacity);
        assert_eq!(UploadBody::bytes(bytes).sha256(), None);
        let (channel, _writer) = UploadBody::channel();
        assert_eq!(channel.sha256(), None);

        let payload = SignPayload::Sha256 {
            bytes: b"abc",
            sha256: digest,
        };
        assert_eq!(format!("{payload:?}"), "Sha256(3)");
        assert_ne!(payload, SignPayload::Bytes(b"abc"));
    }

    /// The `Debug` output of an upload request shows each header name and no
    /// header value. Each other field shows as its own `Debug` shows it.
    #[test]
    fn upload_request_debug_holds_no_header_value() {
        let headers = secret_headers();
        let request = UploadRequest {
            headers: &headers,
            ..UploadRequest::path("objects", UploadBody::bytes(Vec::new()))
        };
        let rendered = format!("{request:?}");
        assert_no_header_value(&rendered);
        assert_eq!(
            rendered,
            format!(
                "UploadRequest {{ target: Path(\"objects\"), method: Post, body: Bytes(0), \
                 priority: Normal, max_response: 2097152, headers: {SECRET_HEADERS_SHOWN}, \
                 basic_auth: None, bearer_token: None, allow_cleartext_credentials: false, \
                 response_timeout: None }}"
            )
        );
    }

    /// Starts a raw socket peer that answers each request with fixed headers,
    /// and gives a fetcher with the peer as its mirror, and the port of the
    /// peer.
    ///
    /// Each header value holds the marker `QXZ`.
    async fn fixed_header_peer() -> (Fetcher, u16) {
        use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

        let peer = rt::TcpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let port = peer.local_addr().unwrap().port();
        drop(rt::spawn(async move {
            while let Ok((mut stream, _peer)) = peer.accept().await {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let answer = "HTTP/1.1 200 OK\r\nSet-Cookie: a=val-QXZ-5\r\n\
                              Set-Cookie: b=val-QXZ-6\r\nContent-Type: text/val-QXZ-7\r\n\
                              Content-Length: 0\r\n\r\n";
                let _ = stream.write_all(answer.as_bytes()).await;
                let _ = stream.flush().await;
            }
        }));

        // With no redirect and a cleartext mirror, the fetcher reads no system
        // trust store.
        let fetcher = Fetcher::new(FetcherOptions {
            max_redirects: 0,
            ..direct_options(format!("http://127.0.0.1:{port}"))
        })
        .await
        .unwrap();
        (fetcher, port)
    }

    /// The `Debug` output of an upload answer shows the name of each response
    /// header, once for each value, and no header value.
    #[test]
    fn uploaded_debug_holds_no_header_value() {
        rt::block_on(async {
            let (fetcher, port) = fixed_header_peer().await;
            let uploaded = within(
                Duration::from_secs(5),
                fetcher.upload(UploadRequest::path(
                    "objects",
                    UploadBody::bytes(Vec::new()),
                )),
            )
            .await
            .expect("the upload ends within the limit")
            .unwrap();
            let rendered = format!("{uploaded:?}");
            assert!(!rendered.contains("QXZ"), "{rendered}");
            let headers = r#"[("set-cookie", "<redacted>"), ("set-cookie", "<redacted>"), ("content-type", "<redacted>"), ("content-length", "<redacted>")]"#;
            assert_eq!(
                rendered,
                format!(
                    "Uploaded {{ status: 200, headers: {headers}, \
                     url: \"http://127.0.0.1:{port}/objects\", body: Body {{ \
                     protocol: Http11, content_length: Some(0), received: 0, .. }} }}"
                )
            );
        });
    }

    /// The `Debug` output of an upload answer shows the host and the path of
    /// its URL, and `<redacted>` in place of the query.
    #[test]
    fn uploaded_debug_holds_no_url_query() {
        rt::block_on(async {
            let (fetcher, port) = fixed_header_peer().await;
            let url = format!("http://127.0.0.1:{port}/objects?X-Amz-Signature=sig-QXZ");
            let uploaded = within(
                Duration::from_secs(5),
                fetcher.upload(UploadRequest::url(&url, UploadBody::bytes(Vec::new()))),
            )
            .await
            .expect("the upload ends within the limit")
            .unwrap();
            assert_eq!(uploaded.url(), url);
            let rendered = format!("{uploaded:?}");
            assert!(!rendered.contains("QXZ"), "{rendered}");
            assert!(
                rendered.contains(&format!(
                    "url: \"http://127.0.0.1:{port}/objects?<redacted>\""
                )),
                "{rendered}"
            );
        });
    }

    /// For a text with no `@`, `?`, and `#`, the `Debug` output of a URL and
    /// of a path is the `Debug` output of the `str`.
    #[test]
    fn redacted_url_debug_quotes_as_str_debug() {
        let texts = [
            "https://example.com/it's",
            "a\"b\\c",
            "line\nnext\ttab\u{7f}",
            "caf\u{e9}",
            "\u{301}start",
            "mid\u{301}dle",
            "zero\u{200b}width",
            "emoji \u{1f980}",
            "",
        ];
        for text in texts {
            let expected = format!("{text:?}");
            assert_eq!(format!("{:?}", RedactedUrl::url(text)), expected);
            assert_eq!(format!("{:?}", RedactedUrl::path(text)), expected);
        }
    }

    /// The `Debug` output of a URL removes the text up to the last `@` after
    /// the scheme, and shows `<redacted>` in place of a query and a fragment.
    /// A path keeps each `@`.
    #[test]
    fn redacted_url_debug_removes_userinfo_query_and_fragment() {
        let urls = [
            ("https://example.com/repo", "https://example.com/repo"),
            (
                "https://user:pw@example.com/repo",
                "https://example.com/repo",
            ),
            (
                "https://u:pa#ss@example.com/repo",
                "https://example.com/repo",
            ),
            (
                "https://u:pa?ss@example.com/repo",
                "https://example.com/repo",
            ),
            (
                "https://u:p/ss@example.com/repo",
                "https://example.com/repo",
            ),
            ("https://example.com/a@b/c", "https://b/c"),
            (
                "https://example.com/s?a=1",
                "https://example.com/s?<redacted>",
            ),
            (
                "https://example.com/s#f",
                "https://example.com/s#<redacted>",
            ),
            (
                "https://u:p@example.com/s?a=1#f",
                "https://example.com/s?<redacted>#<redacted>",
            ),
            ("https://example.com/s?", "https://example.com/s?<redacted>"),
            ("https://example.com/s#", "https://example.com/s#<redacted>"),
            (
                "https://example.com/s?#",
                "https://example.com/s?<redacted>#<redacted>",
            ),
            ("https://example.com/s?a=x@y&b=1", "https://y&b=1"),
            ("example.com/s?a=1", "example.com/s?<redacted>"),
            ("u:p@example.com/s", "example.com/s"),
            ("u:a://b@h/p", "h/p"),
            ("https://[::1]:8/p?q", "https://[::1]:8/p?<redacted>"),
            ("https://h/p#a?b", "https://h/p#<redacted>"),
            ("é@é?é#é", "é?<redacted>#<redacted>"),
        ];
        for (url, shown) in urls {
            assert_eq!(
                format!("{:?}", RedactedUrl::url(url)),
                format!("\"{shown}\"")
            );
        }
        let paths = [
            ("objects/ab", "objects/ab"),
            ("a@b/c", "a@b/c"),
            ("summary?sig=1", "summary?<redacted>"),
            ("summary#f", "summary#<redacted>"),
            ("summary?sig=1#f", "summary?<redacted>#<redacted>"),
        ];
        for (path, shown) in paths {
            assert_eq!(
                format!("{:?}", RedactedUrl::path(path)),
                format!("\"{shown}\"")
            );
        }
    }

    /// The `Debug` output of a target alone shows the layout of a tuple
    /// variant, with the URL rule.
    #[test]
    fn target_debug_redacts_url_and_path() {
        let url = Target::Url("https://u:pw-QXZ@h/p?t=QXZ#QXZ");
        let path = Target::Path("summary?sig=QXZ#QXZ");
        assert_eq!(
            format!("{url:?}"),
            r#"Url("https://h/p?<redacted>#<redacted>")"#
        );
        assert_eq!(
            format!("{path:?}"),
            r#"Path("summary?<redacted>#<redacted>")"#
        );
        assert_eq!(
            format!("{url:#?}"),
            "Url(\n    \"https://h/p?<redacted>#<redacted>\",\n)"
        );
        assert_eq!(
            format!("{path:#?}"),
            "Path(\n    \"summary?<redacted>#<redacted>\",\n)"
        );
        let path_query = Target::PathQuery {
            path: "p?QXZ",
            query: "pattern=QXZ",
        };
        assert_eq!(
            format!("{path_query:?}"),
            r#"PathQuery { path: "p?<redacted>", query: "<redacted>" }"#
        );
        let rendered = format!("{:?}", FetchRequest::path_query("refs/v1", "pattern=QXZ"));
        assert!(!rendered.contains("QXZ"), "{rendered}");
        assert!(
            rendered.contains(r#"target: PathQuery { path: "refs/v1", query: "<redacted>" }"#),
            "{rendered}"
        );
    }

    /// A URL that holds the marker `QXZ` in its userinfo, query, and fragment.
    const SECRET_URL: &str =
        "https://user-QXZ:pw-QXZ@example.com/repo?X-Amz-Signature=sig-QXZ#frag-QXZ";

    /// The `Debug` output of the options shows the host and the path of each
    /// mirror, and no userinfo, query, or fragment.
    #[test]
    fn fetcher_options_debug_holds_no_mirror_secret() {
        let options = FetcherOptions {
            mirrors: vec![SECRET_URL.into(), "https://mirror.example.com/os".into()],
            ..FetcherOptions::default()
        };
        let rendered = format!("{options:?}");
        assert!(!rendered.contains("QXZ"), "{rendered}");
        assert!(
            rendered.contains(
                r#"mirrors: ["https://example.com/repo?<redacted>#<redacted>", "https://mirror.example.com/os"]"#
            ),
            "{rendered}"
        );
    }

    /// The `Debug` output of a fetch request shows the host and the path of
    /// its target, and no userinfo, query, or fragment.
    #[test]
    fn fetch_request_debug_holds_no_target_secret() {
        let rendered = format!("{:?}", FetchRequest::url(SECRET_URL));
        assert!(!rendered.contains("QXZ"), "{rendered}");
        assert!(
            rendered.contains(r#"target: Url("https://example.com/repo?<redacted>#<redacted>")"#),
            "{rendered}"
        );
        let rendered = format!("{:?}", FetchRequest::path("summary?sig=QXZ#f"));
        assert!(!rendered.contains("QXZ"), "{rendered}");
        assert!(
            rendered.contains(r#"target: Path("summary?<redacted>#<redacted>")"#),
            "{rendered}"
        );
    }

    /// The `Debug` output of an upload request shows the host and the path of
    /// its target, and no userinfo, query, or fragment.
    #[test]
    fn upload_request_debug_holds_no_target_secret() {
        let request = UploadRequest::url(SECRET_URL, UploadBody::bytes(Vec::new()));
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("QXZ"), "{rendered}");
        assert!(
            rendered.contains(r#"target: Url("https://example.com/repo?<redacted>#<redacted>")"#),
            "{rendered}"
        );
    }

    /// A kept error body with no declared length grows as its frames arrive,
    /// and its capacity never passes the cap. The first frame of 10,000 bytes
    /// and the frames of 16 KiB after it do not fall on the cap.
    #[test]
    fn a_kept_error_body_holds_no_capacity_past_the_cap() {
        use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

        const CAP: usize = 100_000;
        rt::block_on(async {
            let peer = rt::TcpListener::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let port = peer.local_addr().unwrap().port();
            drop(rt::spawn(async move {
                while let Ok((mut stream, _peer)) = peer.accept().await {
                    let mut request = [0u8; 1024];
                    let _ = stream.read(&mut request).await;
                    let mut answer =
                        b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                    let mut left = CAP - 1;
                    let mut size = 10_000;
                    while left > 0 {
                        let n = size.min(left);
                        answer.extend_from_slice(format!("{n:x}\r\n").as_bytes());
                        answer.resize(answer.len() + n, b'e');
                        answer.extend_from_slice(b"\r\n");
                        left -= n;
                        size = 16 * 1024;
                    }
                    answer.extend_from_slice(b"0\r\n\r\n");
                    for piece in answer.chunks(size) {
                        if stream.write_all(piece).await.is_err() || stream.flush().await.is_err() {
                            break;
                        }
                    }
                }
            }));
            let fetcher = Fetcher::new(direct_options(format!("http://127.0.0.1:{port}")))
                .await
                .unwrap();
            let request = FetchRequest {
                max_error_body: Some(CAP as u64),
                ..FetchRequest::path("config")
            };
            let err = within(Duration::from_secs(10), fetcher.fetch(request))
                .await
                .expect("the fetch ends within the limit")
                .unwrap_err();
            let Error::HttpStatus {
                status: 404,
                response: Some(response),
                ..
            } = err
            else {
                panic!("{err}");
            };
            let body = response.body.as_ref().expect("the body is kept");
            assert_eq!(body.len(), CAP - 1);
            assert!(body.capacity() <= CAP, "capacity {}", body.capacity());
        });
    }
}
