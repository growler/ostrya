//! The async HTTP fetcher pull is built on.
//!
//! A [`Fetcher`] holds the mirrors, headers, credentials, and TLS
//! configuration of one remote, and serves [`FetchRequest`]s. A request names
//! a [`Target`]: a path under every mirror's base URL, or an absolute `http`
//! or `https` URL of its own, which is served from that URL's origin and
//! consults no mirror. A fetcher whose mirror list is empty serves URL targets
//! alone. Every fetch is streaming: the response arrives as a [`Body`] that
//! yields bounded chunks, so an object of any size passes through without
//! being buffered whole.
//!
//! Protocol selection is the TLS handshake's: ALPN offers `h2` and
//! `http/1.1`, and the fetcher speaks whichever the server chose. Over
//! cleartext it speaks HTTP/1.1. HTTP/2 connections are pooled per origin and
//! carry concurrent requests on one connection; HTTP/1.1 connections are pooled
//! and reused once the previous body has been read to the end. The pool is
//! keyed by origin, so a URL target shares a connection with a mirror at the
//! same origin.
//!
//! A request sends the fetcher's headers with its own merged over them: a
//! request header replaces the fetcher header of the same name, and two
//! headers of one name both reach the wire. The `Authorization` header a
//! request carries is the first of these that is set --
//! [`FetchRequest::basic_auth`], an `Authorization` entry in
//! [`FetchRequest::headers`], [`FetcherOptions::basic_auth`], an
//! `Authorization` entry in [`FetcherOptions::headers`]. Within one layer,
//! credentials beside an `Authorization` header give two answers to one
//! question, so they are refused: on the fetcher by [`Fetcher::new`], and on a
//! request by the fetch. A header the connection layer sets -- `Host`, the
//! framing headers, and the hop-by-hop ones -- is refused at both layers as
//! well: the framing of a request and the fate of its connection belong to the
//! connection, and a value of the caller's own puts the wire and the connection
//! pool out of step with each other.
//!
//! A fetch delivers the bytes the remote stores, so every request carries
//! `Accept-Encoding: identity` and asks for no content coding. A server that
//! compresses a response where the header is absent stays within the HTTP
//! specification, and its body would then hold bytes other than the ones the
//! object's checksum names. An `Accept-Encoding` entry in
//! [`FetcherOptions::headers`] or [`FetchRequest::headers`] replaces the value
//! the fetcher asks with, and what it changes is the question the request puts
//! to the server. A 200 whose `Content-Encoding` names a coding other than
//! `identity`, or whose `Transfer-Encoding` names a coding other than
//! `chunked`, fails the attempt definitively with [`Error::ContentEncoded`],
//! whichever layer asked for the coding. The fetcher delivers stored bytes
//! alone, so a caller that wants a coded body decodes it outside the fetcher.
//! `chunked` frames a message and the connection undoes the framing, so a
//! response carrying it alone delivers the body as the remote wrote it.
//!
//! A credential is withheld from no destination, so credentials and cleartext
//! are refused together. [`basic_auth`](FetcherOptions::basic_auth), or an
//! `Authorization`, `Proxy-Authorization`, or `Cookie` entry in
//! [`headers`](FetcherOptions::headers), fails [`Fetcher::new`] when any mirror
//! is `http`. A fetch whose merged headers carry a credential fails before
//! admission when a destination it may reach is `http`, and names that origin;
//! [`FetchRequest::allow_cleartext_credentials`] admits such a fetch, and the
//! construction check has no such switch. The alternative is to withhold the
//! credential from that one destination, which turns a configuration mistake
//! into a 401 that names nothing.
//!
//! A TLS destination needs a trust anchor to verify the server certificate
//! against. A fetcher whose mirrors are all cleartext holds none where the host
//! trust store is empty, and the one fetch that would consult them there -- a
//! request naming an `https` URL of its own -- is refused before admission with
//! the origin named.
//!
//! What a fetch does when something goes wrong. A path target is served under
//! every mirror, in the mirror order, and its destination is resolved at the
//! attempt that uses it; a URL target has the one destination the URL names.
//!
//! - Every destination is tried in order before anything is retried.
//! - Transport failures and the statuses 408, 429, and 5xx are retryable; a
//!   round in which at least one destination failed that way is repeated, up to
//!   [`max_retries`](FetcherOptions::max_retries) times, with a doubling delay
//!   starting at 250ms and capped at two seconds. A repeated round asks only the
//!   destinations whose failure was retryable.
//! - Every other unsuccessful status is definitive: the destination that
//!   answered it is not asked again, its answer being the same whichever round
//!   asks.
//! - A fetch runs out either of destinations to ask or of rounds to repeat, and
//!   both report a definitive answer when the fetch received one, and the first
//!   retryable failure otherwise. A definitive answer is what a caller can act
//!   on -- a 404 is how absence reads -- so it is reported whichever round it
//!   came from, and a retryable failure seen before it does not hide it. Among
//!   definitive answers the earliest is reported, which is the mirror order the
//!   fetcher honors everywhere else: the earliest entry in the list that had
//!   something definitive to say about the request is what the caller hears.
//!
//! An attempt that ends on an unsuccessful status, or on a `Content-Length`
//! over the request's cap, leaves a response body in flight. A body whose
//! declared length is at or below 64 KiB is read to the end so its HTTP/1.1
//! connection returns to the pool; a larger declared length, or none at all,
//! closes the connection instead. A 404 is the ordinary answer for an object a
//! remote does not hold, so without this a scan would pay a connection setup per
//! absent object.
//!
//! Two deadlines bound one attempt against one destination:
//!
//! - [`connect_timeout`](FetcherOptions::connect_timeout) covers opening a
//!   connection -- the TCP connect, the TLS handshake, and the HTTP handshake
//!   together.
//! - [`progress_timeout`](FetcherOptions::progress_timeout) covers a response
//!   making progress: the wait for the response head, and then each stall while
//!   the body streams. The window runs from the read that finds nothing until
//!   bytes arrive, so it caps how long a peer may stay silent and leaves the
//!   total transfer time of a large object unbounded. What it measures is silence
//!   since a read wanted bytes: once a read has found nothing the window runs
//!   whether or not a read is outstanding, and a body no read has yet found empty
//!   is not on the clock at all. A body that stalls fails the read with
//!   [`io::ErrorKind::TimedOut`](std::io::ErrorKind::TimedOut), and keeps failing
//!   it.
//!
//! Both expire as transport failures, so they are retryable and the next
//! destination is tried.
//!
//! [`fetch_timeout`](FetcherOptions::fetch_timeout) bounds the fetch as a whole:
//! every round, every retry, and the delays between them, from admission to the
//! response head. It expires as [`Error::Fetch`](crate::Error::Fetch)
//! with nothing left to try, and the attempt it cancels takes the admission
//! permit with it. This is what keeps an unresponsive peer from stalling a pull
//! for the product of the destination count, the retry count, and the two
//! per-attempt deadlines.
//!
//! Requests carry a [`Priority`]. The fetcher admits
//! [`max_outstanding`](FetcherOptions::max_outstanding) requests at a time and
//! serves the queue highest priority first, ties in arrival order; a permit is
//! held until the fetch fails, or until its response body reaches its end or is
//! dropped, because a body in flight occupies a connection. A failure ends the
//! body without releasing either, so both go on the drop path.
//!
//! Range requests are not used: an interrupted body is refetched from the
//! start.

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_io::{AsyncRead, AsyncWrite};
use hyper::body::{Body as _, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::uri::Scheme;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use ostrya_rt as rt;
use std::pin::Pin;
#[cfg(feature = "tokio")]
use std::task::ready;
use std::task::{Context, Poll};

use crate::error::{Error, Result};

pub(crate) mod gate;
mod io;
mod tls;

use gate::{Gate, Permit};
use io::{FuturesIo, RtExecutor, RtTimer, WriteVectored};
use tls::client_config;
pub use tls::{ClientIdentity, TlsOptions, TrustRoots};

/// The user agent a request carries, which a `User-Agent` header the fetcher or
/// the request sets replaces.
const USER_AGENT: &str = concat!("ostrya/", env!("CARGO_PKG_VERSION"));

/// The one content coding a fetch accepts, which is the absence of a coding.
/// Every request asks for it, and a response declaring anything else fails the
/// attempt. An `Accept-Encoding` header the fetcher or the request sets replaces
/// the one the fetcher asks with.
const IDENTITY: &str = "identity";

/// The one transfer coding a response may declare. It frames a message, and the
/// connection undoes the framing, so the body reaches the caller as the remote
/// wrote it. The port advertises no `TE`, so any other transfer coding is a
/// server fault, and a response declaring one fails the attempt.
const CHUNKED: &str = "chunked";

/// What a layer that sets both credentials and an `Authorization` header is
/// told. Which of the two the request should carry is not stated, and picking
/// one would send a credential the caller did not choose.
const AMBIGUOUS_AUTHORIZATION: &str =
    "basic-auth credentials and an authorization header both set Authorization: pass one of them";

/// What a layer that sets a `Host` header is told. The header states the
/// authority of the destination the request goes to, which the fetcher reads
/// from the URL.
const HOST_COMES_FROM_THE_URL: &str = "the host header is set from the url the request is sent to";

/// The header names the connection layer sets: the ones that frame a request
/// and the ones that state what becomes of the connection carrying it. A value
/// of a caller's own puts the wire and the connection pool out of step with
/// each other -- a `Content-Length` of a caller's own ends the HTTP/1.1
/// connection under a pooled sender, and the next fetch over that fetcher
/// fails on a channel the connection task has dropped.
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

/// The largest declared response body a failed attempt reads to the end so its
/// HTTP/1.1 connection can go back to the pool. Above this, and with no declared
/// length at all, the connection is closed rather than drained.
const DRAIN_LIMIT: u64 = 64 * 1024;

/// The HTTP/2 per-stream flow-control window. hyper's default is 64 KiB, which
/// caps single-stream throughput on a link with a high bandwidth-delay product;
/// an object fetch is one stream, so the window is what bounds it.
const H2_STREAM_WINDOW: u32 = 2 * 1024 * 1024;

/// The largest flow-control window the protocol allows, 2^31 - 1.
const H2_MAX_WINDOW: u32 = i32::MAX as u32;

/// How often an HTTP/2 connection with an open stream pings its peer, and how
/// long it waits for the reply. Both sit inside the default
/// [`progress_timeout`](FetcherOptions::progress_timeout), so a peer that has
/// gone away is reported by the ping rather than by a read that never returns.
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(15);

/// How urgently a request is served when the fetcher is at its limit.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum Priority {
    /// Served after everything else: bulk content.
    Low,
    /// The default.
    #[default]
    Normal,
    /// Served first: the metadata a scan is blocked on.
    High,
}

/// Which HTTP version carried a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    /// HTTP/1.1.
    Http11,
    /// HTTP/2.
    Http2,
}

/// Credentials for a remote behind HTTP basic authentication.
///
/// The [`Debug`] rendering holds the user name and a fixed word in place of the
/// password, so a struct that carries credentials is logged without them.
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

/// The validators a response carried, replayed to make the next fetch of the
/// same target conditional.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Validators {
    /// The response's `ETag`, sent back as `If-None-Match`.
    pub etag: Option<String>,
    /// The response's `Last-Modified`, sent back as `If-Modified-Since`.
    pub last_modified: Option<String>,
}

impl Validators {
    /// Whether there is nothing to make a request conditional with.
    pub fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

/// How a [`Fetcher`] reaches its remote.
#[derive(Clone, Debug)]
pub struct FetcherOptions {
    /// Base URLs, tried in order for every request naming a [`Target::Path`]. A
    /// remote with a mirrorlist contributes one entry per mirror. A base URL is
    /// a scheme, an authority, and a path; a query string or userinfo is
    /// rejected at construction, since a request target is the base path with
    /// the object path appended and neither part would be sent. An empty list
    /// serves [`Target::Url`] requests alone.
    pub mirrors: Vec<String>,
    /// Extra headers sent with every request, to every destination. A request
    /// header of the same name replaces one of these. The fetcher itself sets
    /// `User-Agent` and `Accept-Encoding: identity`, and an entry of one of
    /// those names replaces the value the fetcher sets. An `Authorization`,
    /// `Proxy-Authorization`, or `Cookie` header is refused at construction
    /// when any mirror is cleartext `http`, since its value is a secret
    /// whatever it holds. A `Host` header, and a header the connection layer
    /// sets -- the framing and hop-by-hop names -- is refused at construction
    /// as well. Any other header is sent as written.
    pub headers: Vec<(String, String)>,
    /// Credentials for `Authorization: Basic`, sent with every request to every
    /// destination, and replaced for one request by
    /// [`FetchRequest::basic_auth`]. Every mirror must be `https`: a cleartext
    /// one is refused at construction rather than sent the credentials in the
    /// clear. An `Authorization` entry in
    /// [`headers`](FetcherOptions::headers) alongside these is refused at
    /// construction, both of them setting the same header.
    pub basic_auth: Option<BasicAuth>,
    /// Trust anchors and the client certificate, for `https` mirrors.
    pub tls: TlsOptions,
    /// Whether to offer HTTP/2 in ALPN. With this false the fetcher speaks
    /// HTTP/1.1 even against a server that supports HTTP/2.
    pub http2: bool,
    /// How many times a round of destinations is repeated after a retryable
    /// failure.
    pub max_retries: u32,
    /// How many requests are in flight at once.
    pub max_outstanding: usize,
    /// How long opening a connection may take: the TCP connect, the TLS
    /// handshake, and the HTTP handshake together.
    pub connect_timeout: Duration,
    /// How long a response may go without delivering bytes -- the wait for the
    /// response head, and each stall while the body streams. The window measures
    /// silence since a read wanted bytes, so it caps silence and leaves transfer
    /// time unbounded.
    pub progress_timeout: Duration,
    /// How long one fetch may spend reaching a response: every round, every
    /// retry, and the delays between them, from the moment the fetch is
    /// admitted until the response head arrives. The body that follows is
    /// bounded by [`progress_timeout`](FetcherOptions::progress_timeout) alone.
    /// This caps how long a fetch that reaches no response holds an admission
    /// permit, so it is what a caller sizes against
    /// [`max_outstanding`](FetcherOptions::max_outstanding). `None` applies no
    /// cap.
    pub fetch_timeout: Option<Duration>,
}

impl Default for FetcherOptions {
    fn default() -> Self {
        FetcherOptions {
            mirrors: Vec::new(),
            headers: Vec::new(),
            basic_auth: None,
            tls: TlsOptions::default(),
            http2: true,
            max_retries: 5,
            max_outstanding: 8,
            connect_timeout: Duration::from_secs(30),
            progress_timeout: Duration::from_secs(60),
            fetch_timeout: Some(Duration::from_secs(300)),
        }
    }
}

impl FetcherOptions {
    /// Options for a single base URL, with the defaults elsewhere.
    pub fn new(url: impl Into<String>) -> FetcherOptions {
        FetcherOptions {
            mirrors: vec![url.into()],
            ..FetcherOptions::default()
        }
    }
}

/// What a request names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target<'a> {
    /// A path under each mirror's base URL.
    Path(&'a str),
    /// An absolute `http` or `https` URL. The mirror list is not consulted.
    Url(&'a str),
}

impl Target<'_> {
    /// The string the target holds, which every diagnostic names it by.
    fn as_str(&self) -> &str {
        match self {
            Target::Path(path) => path,
            Target::Url(url) => url,
        }
    }
}

/// One thing to fetch.
#[derive(Clone, Debug)]
pub struct FetchRequest<'a> {
    /// What is fetched: a path under every mirror's base URL, or an absolute
    /// URL of the request's own.
    ///
    /// A path is appended to the base path as written, so it carries the
    /// escaping the server is meant to see, and it holds neither a `?` nor a
    /// `#`: both fail the fetch before it is admitted, neither being part of a
    /// path. A URL's query string is sent as written, and a URL holds no
    /// fragment, which is never sent either. A character no request target may
    /// hold fails the fetch where the URL is assembled.
    pub target: Target<'a>,
    /// Where the request sits in the queue when the fetcher is at its limit.
    pub priority: Priority,
    /// Validators from a previous fetch. When the server reports the copy is
    /// still current the fetch resolves to [`Fetched::NotModified`].
    pub validators: Option<&'a Validators>,
    /// The most bytes the response body may hold. A larger `Content-Length`
    /// fails the fetch with [`Error::FetchTooLarge`]; a body that outgrows the
    /// cap mid-stream fails the read with
    /// [`io::ErrorKind::FileTooLarge`](std::io::ErrorKind::FileTooLarge).
    pub max_size: Option<u64>,
    /// Headers merged over the fetcher's, replacing a fetcher header of the
    /// same name.
    ///
    /// The fetcher sets `User-Agent` and `Accept-Encoding: identity`, and an
    /// entry of one of those names replaces it. An entry that asks for a
    /// content coding changes what the request asks the server for, and a
    /// response that carries a coding is refused whichever layer asked for it.
    ///
    /// Names compare as `HeaderName`, so the comparison is case-insensitive.
    /// Two entries of one name both reach the wire. A `Host` entry is refused,
    /// the header coming from the URL the request is sent to, and so is a
    /// header the connection layer sets -- the framing and hop-by-hop names.
    /// An invalid name or value fails the fetch before it is admitted.
    pub headers: &'a [(String, String)],
    /// Credentials that replace the fetcher's for this request.
    ///
    /// These set the `Authorization` header, so an `Authorization` entry in
    /// [`headers`](FetchRequest::headers) alongside them fails the fetch.
    pub basic_auth: Option<&'a BasicAuth>,
    /// Whether a credential may reach a cleartext origin.
    ///
    /// With this false, a fetch whose merged headers carry a credential fails
    /// when a destination it may reach is `http`. The check
    /// [`Fetcher::new`] makes over the mirror list stands whatever this holds.
    pub allow_cleartext_credentials: bool,
}

impl<'a> FetchRequest<'a> {
    /// A normal-priority, unconditional, uncapped request for `path` under
    /// every mirror, carrying the fetcher's headers and credentials.
    pub fn path(path: &'a str) -> FetchRequest<'a> {
        FetchRequest::for_target(Target::Path(path))
    }

    /// A normal-priority, unconditional, uncapped request for the absolute URL
    /// `url`, carrying the fetcher's headers and credentials.
    pub fn url(url: &'a str) -> FetchRequest<'a> {
        FetchRequest::for_target(Target::Url(url))
    }

    /// A request for `target` with every other field at its default.
    fn for_target(target: Target<'a>) -> FetchRequest<'a> {
        FetchRequest {
            target,
            priority: Priority::default(),
            validators: None,
            max_size: None,
            headers: &[],
            basic_auth: None,
            allow_cleartext_credentials: false,
        }
    }
}

/// What a fetch produced.
///
/// The body variant is much the larger of the two. Boxing it would trade a
/// moved struct for an allocation on the path every object travels, so it is
/// carried inline.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Fetched {
    /// The server sent the object; read it from the body.
    Body(Body),
    /// The server confirmed the caller's copy is current (304).
    NotModified,
}

/// A parsed base URL.
#[derive(Clone, Debug)]
struct Mirror {
    /// The origin's scheme, host, and port.
    origin: Origin,
    /// The `host[:port]` this mirror is addressed by, the value of the `Host`
    /// header on HTTP/1.1 requests. It holds the authority as the base URL
    /// wrote it, the default port for the scheme left out, and an IPv6 literal
    /// keeps its brackets.
    authority: HeaderValue,
    /// The `scheme://authority` prefix of every absolute URL built for this
    /// mirror, which is also the origin a diagnostic names it by.
    prefix: String,
    /// The base path, without a trailing slash. Empty for a mirror at the root.
    base: String,
}

impl Mirror {
    /// Where a request for `path` under this mirror is sent. The one string the
    /// destination holds is built here: the mirror's prefix and base path, then
    /// the request path.
    fn destination(&self, path: &str) -> Destination {
        Destination {
            origin: self.origin.clone(),
            authority: self.authority.clone(),
            url: format!(
                "{}{}/{}",
                self.prefix,
                self.base,
                path.trim_start_matches('/')
            ),
            path_at: self.prefix.len(),
        }
    }
}

/// Where one attempt sends its request. A URL target resolves its one
/// destination once per fetch, and every attempt and every retry round uses
/// that one; a path target resolves the destination of the mirror an attempt is
/// about to use, at that attempt.
#[derive(Clone, Debug)]
struct Destination {
    /// The origin's scheme, host, and port, which the connection pool is keyed
    /// by.
    origin: Origin,
    /// The `host[:port]` the request is addressed by, the value of the `Host`
    /// header on HTTP/1.1 requests. It holds the authority as the caller wrote
    /// it, the default port for the scheme left out, and an IPv6 literal keeps
    /// its brackets.
    authority: HeaderValue,
    /// The absolute URL, which holds both forms one request needs: the whole
    /// string, and the tail from `path_at`.
    url: String,
    /// Where the request path begins in `url`, which is the length of the
    /// `scheme://authority` prefix.
    path_at: usize,
}

impl Destination {
    /// The absolute URL, which an HTTP/2 request carries and every diagnostic
    /// names.
    fn url(&self) -> &str {
        &self.url
    }

    /// The origin-form request target -- the path, and the query string a URL
    /// target carries -- which is what an HTTP/1.1 request to an origin server
    /// carries.
    fn target(&self) -> &str {
        &self.url[self.path_at..]
    }

    /// The `scheme://authority` this destination is reached at, which a
    /// diagnostic about the origin names it by.
    fn origin_url(&self) -> &str {
        &self.url[..self.path_at]
    }
}

/// Where a fetch sends its requests, in the order it asks.
///
/// A path target is served under every mirror, so a round walks the mirror list
/// and builds the destination of the mirror it is about to ask: a fetch the
/// first mirror answers builds one destination whatever the length of the list.
/// A URL target names one destination, which is parsed once per fetch.
#[derive(Debug)]
enum Route<'a> {
    /// Every mirror in order, serving this request path.
    Mirrors(&'a str),
    /// The one destination a URL target names.
    One(Destination),
}

/// A connection endpoint: connections are pooled per origin.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Origin {
    tls: bool,
    /// What the connect resolves and the TLS server name is built from, so an
    /// IPv6 literal is held without the brackets the authority carries. An
    /// ASCII host is held in lower case, so one origin written in two cases is
    /// one pool key and one connection.
    host: String,
    port: u16,
}

/// The request body: every request is a GET, so there is nothing to send.
struct NoBody;

impl hyper::body::Body for NoBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        true
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(0)
    }
}

type H1Sender = hyper::client::conn::http1::SendRequest<NoBody>;
type H2Sender = hyper::client::conn::http2::SendRequest<NoBody>;

/// A connection ready to carry one request.
enum Sender {
    /// An HTTP/1.1 connection, which carries one request at a time and returns
    /// to the pool when its response body ends.
    H1(H1Sender),
    /// A handle on a pooled HTTP/2 connection, which multiplexes.
    H2(H2Sender),
}

/// The connections pooled for one origin.
#[derive(Default)]
struct PoolEntry {
    /// The origin's HTTP/2 connection, if one is open.
    h2: Option<H2Sender>,
    /// Idle HTTP/1.1 connections.
    h1: Vec<H1Sender>,
}

/// Shared fetcher state. `Fetcher` is a handle on this.
struct Inner {
    mirrors: Vec<Mirror>,
    headers: Vec<(HeaderName, HeaderValue)>,
    tls: Arc<rustls::ClientConfig>,
    /// Whether the TLS configuration holds a trust anchor. A fetcher whose
    /// mirrors are all cleartext builds without one where the host trust store
    /// is empty, and a TLS destination is refused there.
    has_trust_anchors: bool,
    max_retries: u32,
    connect_timeout: Duration,
    progress_timeout: Duration,
    fetch_timeout: Option<Duration>,
    gate: Arc<Gate>,
    h2_connection_window: u32,
    pool: Mutex<HashMap<Origin, PoolEntry>>,
}

/// The HTTP/2 connection flow-control window for a fetcher admitting
/// `max_outstanding` requests: one per-stream window for each of them.
///
/// A receiver credits a window back when the data is consumed, so a stream whose
/// body the caller has received and not yet read holds its own credit for as long
/// as it is parked. Giving the connection the sum of the stream windows keeps that
/// credit the parked stream's own: whatever a caller parks, every other stream it
/// has open still has a full window to receive over. An HTTP pull parks content
/// bodies while they wait for a write permit, and the metadata object its scan is
/// blocked on travels over the same connection.
///
/// The cost is the data one connection may hold received and unread, which is
/// this window: 16 MiB at the default limit of 8.
fn h2_connection_window(max_outstanding: usize) -> u32 {
    u32::try_from(max_outstanding)
        .unwrap_or(u32::MAX)
        .saturating_mul(H2_STREAM_WINDOW)
        .min(H2_MAX_WINDOW)
}

/// A failed attempt, and whether trying again could help.
enum Failure {
    /// A transport failure or a status that a later attempt may not hit.
    Retry(Error),
    /// A definitive answer: retrying would get the same one.
    Fatal(Error),
}

/// An async HTTP client for one remote.
///
/// Cloning a `Fetcher` yields another handle on the same connection pool and
/// the same concurrency limit.
#[derive(Clone)]
pub struct Fetcher {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Fetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetcher")
            .field("mirrors", &self.inner.mirrors)
            .finish_non_exhaustive()
    }
}

impl Fetcher {
    /// Build a fetcher from `options`.
    ///
    /// The mirror list may be empty, in which case the fetcher serves
    /// [`Target::Url`] requests alone.
    ///
    /// Fails when a mirror URL is not an absolute `http`/`https` URL, carries a
    /// query string or userinfo, or names a port the URL parser cannot read;
    /// when a header name or value is not valid; when a header the connection
    /// layer sets is configured; when credentials are configured alongside a
    /// cleartext mirror; when credentials are configured alongside an
    /// `Authorization` header; or when the TLS material does not parse.
    ///
    /// This is async because [`TrustRoots::System`](crate::TrustRoots::System),
    /// the default, reads the host trust store, which goes to the blocking
    /// pool. The TLS configuration is built whatever the mirrors' scheme is, so
    /// a cleartext-only fetcher reads it too; under
    /// [`TrustRoots::Pem`](crate::TrustRoots::Pem) the work is all in memory and
    /// the constructor never yields. A system store holding no certificate
    /// fails the constructor when at least one mirror is `https`, and when the
    /// mirror list is empty, since a request may then name an `https` URL; a
    /// host without a CA bundle still reaches a cleartext remote.
    pub async fn new(options: FetcherOptions) -> Result<Fetcher> {
        let mirrors = options
            .mirrors
            .iter()
            .map(|url| parse_mirror(url))
            .collect::<Result<Vec<_>>>()?;
        // A credential is sent with every request to every mirror, so one
        // cleartext entry in the list is enough to put it on the wire in the
        // clear. Such a configuration is refused rather than served with the
        // credential withheld, which would answer 401 without saying why.
        let cleartext = options
            .mirrors
            .iter()
            .zip(&mirrors)
            .find(|(_, mirror)| !mirror.origin.tls)
            .map(|(url, _)| url.as_str());
        if options.basic_auth.is_some()
            && let Some(url) = cleartext
        {
            return Err(Error::Fetch(format!(
                "basic-auth credentials would reach the http mirror {url} in the clear: \
                 use https mirrors or drop the credentials"
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
        // How much of the list the fetcher itself sets. A configured header of
        // one of those names replaces that entry, the way a request header
        // replaces a fetcher header of the same name: the two would otherwise
        // both reach the wire and give one question two answers. A name outside
        // this region is a configured header, which two entries of one name
        // both reach the wire under.
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
            if is_credential(&name)
                && let Some(url) = cleartext
            {
                return Err(Error::Fetch(format!(
                    "the {name} header carries credentials, which the http mirror {url} \
                     would receive in the clear: use https mirrors or drop the header"
                )));
            }
            let value = HeaderValue::try_from(value.as_str())
                .map_err(|_| Error::Fetch(format!("invalid value for header {name}")))?;
            if let Some(at) = headers[..base].iter().position(|(held, _)| *held == name) {
                headers.remove(at);
                base -= 1;
            }
            headers.push((name, value));
        }
        if let Some(auth) = &options.basic_auth {
            headers.push((hyper::header::AUTHORIZATION, basic_auth_value(auth)?));
        }
        let max_outstanding = options.max_outstanding.max(1);
        // A fetcher with no mirror serves the URLs its requests name, any of
        // which may be `https`, so it has to hold trust anchors: an empty
        // system store is as fatal there as it is for an `https` mirror.
        let https = mirrors.is_empty() || mirrors.iter().any(|mirror| mirror.origin.tls);
        let (tls, has_trust_anchors) = client_config(&options.tls, options.http2, https).await?;
        Ok(Fetcher {
            inner: Arc::new(Inner {
                mirrors,
                headers,
                tls,
                has_trust_anchors,
                max_retries: options.max_retries,
                connect_timeout: options.connect_timeout,
                progress_timeout: options.progress_timeout,
                fetch_timeout: options.fetch_timeout,
                gate: Arc::new(Gate::new(max_outstanding)),
                h2_connection_window: h2_connection_window(max_outstanding),
                pool: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Fetch `request`, trying every destination and retrying as configured.
    pub async fn fetch(&self, request: FetchRequest<'_>) -> Result<Fetched> {
        // What the request names, the headers it sends, the credentials they
        // carry, and the anchors a TLS destination verifies against are the
        // same whichever destination serves the request, so all of them are
        // settled before admission: a failure is reported once rather than once
        // per destination and once per round, and no permit is taken and no
        // socket opened for it.
        let route = self.route(request.target)?;
        let headers = merge_headers(&self.inner.headers, request.headers, request.basic_auth)?;
        if !request.allow_cleartext_credentials {
            self.check_cleartext(&route, &headers)?;
        }
        self.check_trust_anchors(&route)?;
        let permit = self.inner.gate.acquire(request.priority).await;
        let rounds = self.rounds(&request, &route, &headers, permit);
        let Some(limit) = self.inner.fetch_timeout else {
            return rounds.await;
        };
        // Expiry drops the rounds, and with them the attempt in flight and the
        // permit, so the slot is free before the failure is reported.
        match within(limit, rounds).await {
            Some(result) => result,
            None => Err(Error::Fetch(format!(
                "fetch of {} timed out after {limit:?}",
                request.target.as_str()
            ))),
        }
    }

    /// Where a fetch of `target` sends its requests, in the order it asks.
    ///
    /// A URL target names its one destination itself, which is parsed here. A
    /// path target is served under the mirrors, so a fetcher with no mirror has
    /// nowhere to send it.
    fn route<'a>(&self, target: Target<'a>) -> Result<Route<'a>> {
        match target {
            Target::Url(url) => Ok(Route::One(parse_url(url)?)),
            Target::Path(path) => {
                check_path(path)?;
                if self.inner.mirrors.is_empty() {
                    return Err(Error::Fetch(format!(
                        "fetch of the path {path} has nowhere to go: no mirror is configured"
                    )));
                }
                Ok(Route::Mirrors(path))
            }
        }
    }

    /// Refuse a fetch whose headers carry a credential a cleartext destination
    /// would receive in the clear.
    ///
    /// A credential is withheld from no destination, so one cleartext
    /// destination among the ones the fetch may reach is enough to refuse it.
    /// The alternative is to send the request without the credential, which
    /// answers 401 and names nothing.
    fn check_cleartext(
        &self,
        route: &Route<'_>,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<()> {
        if !headers.iter().any(|(name, _)| is_credential(name)) {
            return Ok(());
        }
        let Some(origin) = self.matching_origin(route, |origin| !origin.tls) else {
            return Ok(());
        };
        Err(Error::Fetch(format!(
            "the request carries credentials, which the cleartext origin {origin} would receive \
             in the clear: fetch over https, drop the credentials, or set \
             FetchRequest::allow_cleartext_credentials"
        )))
    }

    /// Refuse a fetch of a TLS destination on a fetcher that holds no trust
    /// anchors.
    ///
    /// A handshake verifies the server certificate against an anchor, so a
    /// fetcher with none reaches no TLS origin. What arrives here is a request
    /// naming an `https` URL of its own on a fetcher whose mirrors are all
    /// cleartext, since every other combination fails [`Fetcher::new`]. The
    /// handshake reports it as an unknown issuer, a retryable failure that
    /// spends every round and every backoff before it names anything, so the
    /// refusal is made here instead, before admission.
    fn check_trust_anchors(&self, route: &Route<'_>) -> Result<()> {
        if self.inner.has_trust_anchors {
            return Ok(());
        }
        let Some(origin) = self.matching_origin(route, |origin| origin.tls) else {
            return Ok(());
        };
        Err(Error::Fetch(format!(
            "the certificate of the tls origin {origin} has nothing to verify against: the \
             fetcher holds no trust anchors, so set TlsOptions::roots"
        )))
    }

    /// The `scheme://authority` of the first destination on `route` whose
    /// origin `wanted` accepts.
    fn matching_origin<'a>(
        &'a self,
        route: &'a Route<'_>,
        wanted: fn(&Origin) -> bool,
    ) -> Option<&'a str> {
        match route {
            Route::Mirrors(_) => self
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

    /// Try every destination in turn, repeating the round while a destination
    /// failed in a way another attempt may not. The permit moves into the body
    /// a successful round produces, and is dropped with this future otherwise.
    async fn rounds(
        &self,
        request: &FetchRequest<'_>,
        route: &Route<'_>,
        headers: &[(HeaderName, HeaderValue)],
        permit: Permit,
    ) -> Result<Fetched> {
        let destination_count = match route {
            Route::Mirrors(_) => self.inner.mirrors.len(),
            Route::One(_) => 1,
        };
        // A destination that answered definitively answers the same in every
        // round, so it is asked once: a repeated round asks only the
        // destinations whose failure another attempt may not repeat.
        let mut settled = vec![false; destination_count];
        // The failure both exhaustion paths report. A definitive answer is what
        // a caller can act on, so it outranks a retryable failure whichever
        // round each came from: a destination that fails transiently and then
        // answers 404 reports the 404. Among failures of one kind the earliest
        // is kept, which is the mirror order the fetcher honors everywhere
        // else.
        let mut reported: Option<Error> = None;
        let mut definitive = false;
        let mut round = 0;
        loop {
            let mut retryable = false;
            for (position, settled) in settled.iter_mut().enumerate() {
                if *settled {
                    continue;
                }
                // The destination of a mirror is built for the attempt that
                // uses it, so a fetch the first mirror answers builds one
                // whatever the length of the list.
                let destination = match route {
                    Route::Mirrors(path) => {
                        Cow::Owned(self.inner.mirrors[position].destination(path))
                    }
                    Route::One(destination) => Cow::Borrowed(destination),
                };
                let failure = match self.attempt(&destination, request, headers).await {
                    Ok(Attempted::Body(mut body)) => {
                        body.permit = Some(permit);
                        return Ok(Fetched::Body(body));
                    }
                    Ok(Attempted::NotModified) => return Ok(Fetched::NotModified),
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
                }
            }
            // At least one destination failed in a way a later attempt may not;
            // otherwise every destination has answered definitively.
            if !retryable || round >= self.inner.max_retries {
                return Err(reported.expect("a failed round holds a failure"));
            }
            round += 1;
            rt::Timer::after(backoff(round)).await;
        }
    }

    /// One request against one destination.
    async fn attempt(
        &self,
        destination: &Destination,
        request: &FetchRequest<'_>,
        headers: &[(HeaderName, HeaderValue)],
    ) -> std::result::Result<Attempted, Failure> {
        let origin = &destination.origin;
        let url = destination.url();
        let connect_timeout = self.inner.connect_timeout;
        let progress_timeout = self.inner.progress_timeout;
        let sender = match self.inner.take_conn(origin) {
            Some(sender) => sender,
            None => {
                // Opening a connection is by far the largest state a fetch
                // holds -- the TLS handshake and hyper's own -- and it is the
                // rarest, taken only when the pool has nothing for this origin.
                // Boxing it keeps that state off the fetch future, which every
                // caller nests inside its own: a fetch is ten times smaller
                // this way, and a pull that wraps several helpers around one
                // multiplies what it saves.
                let opened = within(connect_timeout, Box::pin(self.connect(origin))).await;
                match opened {
                    Some(result) => result.map_err(Failure::Retry)?,
                    None => {
                        return Err(Failure::Retry(Error::Fetch(format!(
                            "connect to {}:{} timed out after {connect_timeout:?}",
                            origin.host, origin.port
                        ))));
                    }
                }
            }
        };
        let (response, protocol, reuse) = match sender {
            Sender::H1(mut sender) => {
                let http_request = self
                    .build_request(destination, request, headers, Protocol::Http11)
                    .map_err(Failure::Fatal)?;
                // The request and the wait for the response head share the
                // progress window: the head is the first bytes the response
                // delivers.
                let sent = within(progress_timeout, async {
                    sender.ready().await?;
                    sender.send_request(http_request).await
                })
                .await;
                let response = match sent {
                    Some(result) => result.map_err(|e| Failure::Retry(transport(url, e)))?,
                    None => return Err(Failure::Retry(stalled(url, progress_timeout))),
                };
                (response, Protocol::Http11, Some(sender))
            }
            Sender::H2(mut sender) => {
                let http_request = self
                    .build_request(destination, request, headers, Protocol::Http2)
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
                (response, Protocol::Http2, None)
            }
        };
        let status = response.status();
        if status == StatusCode::NOT_MODIFIED {
            // A 304 carries no body, so the connection is immediately reusable.
            if let Some(sender) = reuse {
                self.inner.put_h1(origin, sender);
            }
            return Ok(Attempted::NotModified);
        }
        if status != StatusCode::OK {
            let failure = classify(status, url);
            self.discard(origin, response, reuse).await;
            return Err(failure);
        }
        // A coded body holds bytes other than the ones the remote stores, so
        // the declared length says nothing about the object either: the coding
        // is refused before the cap is compared. A refusal that names the
        // coding is what a checksum mismatch cannot say. The refusal is
        // definitive, another attempt against the same destination being
        // answered the same way.
        if let Some(encoding) = declared_coding(response.headers()) {
            self.discard(origin, response, reuse).await;
            return Err(Failure::Fatal(Error::ContentEncoded {
                url: url.to_string(),
                encoding,
            }));
        }
        let validators = read_validators(response.headers());
        let content_length = content_length(response.headers());
        if let (Some(limit), Some(length)) = (request.max_size, content_length)
            && length > limit
        {
            self.discard(origin, response, reuse).await;
            return Err(Failure::Fatal(Error::FetchTooLarge { limit }));
        }
        let protocol = match response.version() {
            Version::HTTP_2 => Protocol::Http2,
            _ => protocol,
        };
        Ok(Attempted::Body(Body {
            incoming: response.into_body(),
            chunk: Bytes::new(),
            received: 0,
            max_size: request.max_size,
            validators,
            content_length,
            protocol,
            inner: self.inner.clone(),
            origin: origin.clone(),
            reuse,
            permit: None,
            done: false,
            failed: None,
            deadline: rt::Deadline::new(progress_timeout),
            waiting: false,
        }))
    }

    /// End an attempt whose response is not the one the caller asked for.
    ///
    /// A response that declares a body of at most [`DRAIN_LIMIT`] bytes is read
    /// to the end, which frees its HTTP/1.1 connection for the next request; a
    /// larger declared body, or one with no declared length, is dropped, closing
    /// the connection, since the rest of the response is still in flight. An
    /// HTTP/2 stream carries no such cost -- its connection stays pooled
    /// whatever the stream did -- so there is nothing to drain.
    async fn discard(
        &self,
        origin: &Origin,
        response: Response<Incoming>,
        reuse: Option<H1Sender>,
    ) {
        let Some(sender) = reuse else { return };
        if content_length(response.headers()).is_none_or(|length| length > DRAIN_LIMIT) {
            return;
        }
        let mut body = response.into_body();
        // The drain runs under the progress window, so a peer that declares a
        // short body and then stops sending costs the attempt no more than a
        // stalled body would.
        let drained = within(self.inner.progress_timeout, async {
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
            self.inner.put_h1(origin, sender);
        }
    }

    /// Assemble the GET for `request` against `destination`, sending `headers`.
    ///
    /// An HTTP/1.1 request carries the origin-form target and a `Host` header,
    /// which is what an origin server expects; the absolute form belongs to
    /// proxy requests, and a plain static-file server answers 404 to it. An
    /// HTTP/2 request carries the absolute URL, from which hyper fills the
    /// `:scheme` and `:authority` pseudo-headers.
    fn build_request(
        &self,
        destination: &Destination,
        request: &FetchRequest<'_>,
        headers: &[(HeaderName, HeaderValue)],
        protocol: Protocol,
    ) -> Result<Request<NoBody>> {
        let url = match protocol {
            Protocol::Http11 => destination.target(),
            Protocol::Http2 => destination.url(),
        };
        let uri =
            Uri::try_from(url).map_err(|e| Error::Fetch(format!("invalid url {url}: {e}")))?;
        let mut builder = Request::builder().method(Method::GET).uri(uri);
        if protocol == Protocol::Http11 {
            builder = builder.header(hyper::header::HOST, &destination.authority);
        }
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        if let Some(validators) = request.validators {
            if let Some(etag) = &validators.etag {
                builder = builder.header(hyper::header::IF_NONE_MATCH, etag);
            }
            if let Some(last_modified) = &validators.last_modified {
                builder = builder.header(hyper::header::IF_MODIFIED_SINCE, last_modified);
            }
        }
        builder
            .body(NoBody)
            .map_err(|e| Error::Fetch(format!("invalid request for {url}: {e}")))
    }

    /// Open a connection to `origin`, negotiating the protocol over ALPN when
    /// the origin is TLS.
    async fn connect(&self, origin: &Origin) -> Result<Sender> {
        let tcp = rt::TcpStream::connect(&origin.host, origin.port)
            .await
            .map_err(|e| {
                Error::Fetch(format!(
                    "connect to {}:{} failed: {e}",
                    origin.host, origin.port
                ))
            })?;
        if !origin.tls {
            // Cleartext HTTP/2 needs prior knowledge or an upgrade; neither is
            // used, so a cleartext origin speaks HTTP/1.1.
            return self.handshake_h1(origin, FuturesIo::new(tcp)).await;
        }
        let server_name = rustls::pki_types::ServerName::try_from(origin.host.clone())
            .map_err(|e| Error::Fetch(format!("invalid server name {}: {e}", origin.host)))?;
        let stream = futures_rustls::TlsConnector::from(self.inner.tls.clone())
            .connect(server_name, tcp)
            .await
            .map_err(|e| Error::Fetch(format!("tls handshake with {} failed: {e}", origin.host)))?;
        let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
        let io = FuturesIo::new(stream);
        if h2 {
            self.handshake_h2(origin, io).await
        } else {
            self.handshake_h1(origin, io).await
        }
    }

    /// Complete an HTTP/1.1 handshake and drive the connection in its own task.
    async fn handshake_h1<S>(&self, origin: &Origin, io: FuturesIo<S>) -> Result<Sender>
    where
        S: AsyncRead + AsyncWrite + WriteVectored + Send + Unpin + 'static,
    {
        let (sender, connection) =
            hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| {
                    Error::Fetch(format!(
                        "http/1.1 handshake with {} failed: {e}",
                        origin.host
                    ))
                })?;
        drop(rt::spawn(async move {
            // The connection ends when the last sender drops or the peer closes
            // it; an error here surfaces on the next request over it.
            let _ = connection.await;
        }));
        Ok(Sender::H1(sender))
    }

    /// Complete an HTTP/2 handshake, drive the connection in its own task, and
    /// pool it: further requests to this origin multiplex over it.
    ///
    /// The connection is built rather than handshaken free-standing, since the
    /// flow-control windows and the keep-alive ping are settings only the
    /// builder reaches.
    async fn handshake_h2<S>(&self, origin: &Origin, io: FuturesIo<S>) -> Result<Sender>
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
                Error::Fetch(format!("http/2 handshake with {} failed: {e}", origin.host))
            })?;
        drop(rt::spawn(async move {
            let _ = connection.await;
        }));
        self.inner.put_h2(origin, sender.clone());
        Ok(Sender::H2(sender))
    }
}

impl Inner {
    /// A pooled connection for `origin`, if one is still usable.
    fn take_conn(&self, origin: &Origin) -> Option<Sender> {
        let mut pool = self.pool.lock().expect("fetcher pool mutex");
        let entry = pool.get_mut(origin)?;
        if let Some(h2) = &entry.h2 {
            if h2.is_closed() {
                entry.h2 = None;
            } else {
                return Some(Sender::H2(h2.clone()));
            }
        }
        while let Some(h1) = entry.h1.pop() {
            if !h1.is_closed() {
                return Some(Sender::H1(h1));
            }
        }
        None
    }

    /// Return an idle HTTP/1.1 connection to the pool.
    fn put_h1(&self, origin: &Origin, sender: H1Sender) {
        if sender.is_closed() {
            return;
        }
        let mut pool = self.pool.lock().expect("fetcher pool mutex");
        pool.entry(origin.clone()).or_default().h1.push(sender);
    }

    /// Record the origin's HTTP/2 connection, keeping a usable one already
    /// pooled.
    ///
    /// Two concurrent connects to one origin each complete a handshake. The
    /// connection that loses the race would otherwise replace a pooled entry
    /// other requests are already multiplexing over, and stay alive unreferenced
    /// until its own senders drop; instead it serves only the request that
    /// opened it and closes with that request.
    fn put_h2(&self, origin: &Origin, sender: H2Sender) {
        let mut pool = self.pool.lock().expect("fetcher pool mutex");
        let entry = pool.entry(origin.clone()).or_default();
        match &entry.h2 {
            Some(pooled) if !pooled.is_closed() => {}
            _ => entry.h2 = Some(sender),
        }
    }
}

/// What one attempt produced.
#[allow(clippy::large_enum_variant)]
enum Attempted {
    Body(Body),
    NotModified,
}

/// A failure that ends a body, replayed by every later read.
struct Failed {
    kind: std::io::ErrorKind,
    message: String,
}

impl Failed {
    fn error(&self) -> std::io::Error {
        std::io::Error::new(self.kind, self.message.clone())
    }
}

/// The response body of a successful fetch.
///
/// Reading yields the object's bytes in bounded chunks. The connection and the
/// fetcher's concurrency permit are released when the body reaches the end or is
/// dropped; a body dropped before the end closes its connection rather than
/// returning it to the pool, since the rest of the response is still in flight.
///
/// A failure ends the body: the size cap, the progress deadline, and a transport
/// failure each fail that read and every read after it with the same error, so a
/// consumer that keeps reading past a failure never sees a clean end of stream
/// and cannot mistake a truncated object for a complete one.
pub struct Body {
    incoming: Incoming,
    /// Bytes received from the connection and not yet copied to the caller.
    chunk: Bytes,
    /// Bytes taken off the connection, which the caller trails by whatever is
    /// still in `chunk`. This is the counter the size cap is enforced against.
    received: u64,
    max_size: Option<u64>,
    validators: Validators,
    content_length: Option<u64>,
    protocol: Protocol,
    inner: Arc<Inner>,
    origin: Origin,
    /// The HTTP/1.1 connection to return to the pool at the end of the body.
    reuse: Option<H1Sender>,
    /// The concurrency permit, held for as long as the body is in flight.
    permit: Option<Permit>,
    done: bool,
    /// The failure that ended the body, once one has.
    failed: Option<Failed>,
    /// How long the peer may stay silent once a read is waiting on it.
    deadline: rt::Deadline,
    /// Whether the window is running, which it is from the read that finds
    /// nothing until the next frame arrives. What it measures is silence since a
    /// read wanted bytes: the window keeps running whether or not a read is
    /// outstanding, and a body no read has yet found empty is not on the clock at
    /// all.
    waiting: bool,
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
    /// The validators to replay on the next fetch of this target.
    pub fn validators(&self) -> &Validators {
        &self.validators
    }

    /// The `Content-Length` the response declared, when it declared one.
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// The HTTP version that carried the response.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// How many bytes have been taken off the connection, which may exceed what
    /// the caller has consumed: a frame is pulled whole and handed out in as
    /// many reads as the caller's buffers need, so this runs ahead by up to one
    /// chunk. It is the counter the size cap is enforced against. A caller that
    /// needs the delivered count has it from its own read loop.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// Latch a failure that ends the body and return it. The connection and the
    /// permit are left held, so they are released on the drop path, which closes
    /// the connection rather than pooling a response still in flight.
    fn fail(&mut self, kind: std::io::ErrorKind, message: String) -> std::io::Error {
        let failed = Failed { kind, message };
        let error = failed.error();
        self.failed = Some(failed);
        error
    }
}

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
                    // Nothing has arrived since the last frame, so the read
                    // fails once the progress window is gone.
                    if !me.waiting {
                        me.deadline.restart();
                        me.waiting = true;
                    }
                    return match me.deadline.poll_expired(cx) {
                        Poll::Ready(()) => {
                            let window = me.deadline.window();
                            Poll::Ready(Err(me.fail(
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
                    // The peer delivered: the window is off the clock until the
                    // next read finds nothing.
                    me.waiting = false;
                    // Trailers carry no payload; keep polling for data.
                    if let Ok(data) = frame.into_data() {
                        me.received += data.len() as u64;
                        if let Some(limit) = me.max_size
                            && me.received > limit
                        {
                            return Poll::Ready(Err(me.fail(
                                std::io::ErrorKind::FileTooLarge,
                                format!("fetched body exceeds the {limit}-byte cap"),
                            )));
                        }
                        me.chunk = data;
                    }
                }
                Some(Err(e)) => {
                    // hyper reports a body error once and then reports the body
                    // as ended, so an unlatched failure would let the next read
                    // return a clean end of stream for a truncated object. The
                    // error's own message is generic; its cause names what the
                    // connection did.
                    let message = match std::error::Error::source(&e) {
                        Some(cause) => format!("{e}: {cause}"),
                        None => e.to_string(),
                    };
                    return Poll::Ready(Err(me.fail(std::io::ErrorKind::Other, message)));
                }
                None => {
                    me.done = true;
                    // The whole response has arrived, so the connection can
                    // serve the next request.
                    if let Some(sender) = me.reuse.take() {
                        me.inner.put_h1(&me.origin, sender);
                    }
                    me.permit = None;
                    return Poll::Ready(Ok(0));
                }
            }
        }
    }
}

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

/// Whether a header name carries credentials, which no cleartext destination is
/// sent.
///
/// These three are the header names whose value is a secret whatever it holds.
/// A header outside this list, and outside the `Host` and connection-layer
/// names both layers refuse, is sent as the caller wrote it: a secret can be
/// spelled into one, and the fetcher has no way to tell.
fn is_credential(name: &HeaderName) -> bool {
    *name == hyper::header::AUTHORIZATION
        || *name == hyper::header::PROXY_AUTHORIZATION
        || *name == hyper::header::COOKIE
}

/// Whether the connection layer sets a header of this name, which is what makes
/// it one no caller may set. A `HeaderName` holds its name in lower case, which
/// is the case [`CONNECTION_HEADERS`] is written in.
fn is_connection_header(name: &HeaderName) -> bool {
    CONNECTION_HEADERS.contains(&name.as_str())
}

/// What a layer that sets a header of the connection layer's is told.
fn connection_header_refused(name: &HeaderName) -> Error {
    Error::Fetch(format!(
        "the {name} header is set by the connection layer, which frames the request and \
         holds its connection: drop the header"
    ))
}

/// Check that a request path can be appended to a mirror's base path.
///
/// A target is the base path with the request path appended as written, so a `?`
/// or a `#` in that path delimits rather than names: the first sends its tail as
/// a query string the server matches on, and the second is dropped at URL
/// assembly, asking for a different resource.
fn check_path(path: &str) -> Result<()> {
    if let Some(at) = path.find(['?', '#']) {
        let found = &path[at..=at];
        return Err(Error::Fetch(format!(
            "fetch path {path} carries {found}: a path holds no query and no fragment"
        )));
    }
    Ok(())
}

/// The headers one request sends: the fetcher's, with the request's own merged
/// over them.
///
/// A request header replaces the fetcher header of the same name, and the
/// request's credentials replace the fetcher's `Authorization`, whichever of
/// the two layers set it. Two request headers of one name both reach the wire,
/// as two fetcher headers do. A request that adds neither a header nor
/// credentials sends the fetcher's list as it stands, which is the path every
/// object fetch takes.
fn merge_headers<'a>(
    fetcher: &'a [(HeaderName, HeaderValue)],
    extra: &[(String, String)],
    basic_auth: Option<&BasicAuth>,
) -> Result<Cow<'a, [(HeaderName, HeaderValue)]>> {
    if extra.is_empty() && basic_auth.is_none() {
        return Ok(Cow::Borrowed(fetcher));
    }
    let mut added = Vec::with_capacity(extra.len() + usize::from(basic_auth.is_some()));
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
        let value = HeaderValue::try_from(value.as_str())
            .map_err(|_| Error::Fetch(format!("invalid value for header {name}")))?;
        added.push((name, value));
    }
    if let Some(auth) = basic_auth {
        added.push((hyper::header::AUTHORIZATION, basic_auth_value(auth)?));
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

/// The `Authorization` value basic credentials are sent as.
fn basic_auth_value(auth: &BasicAuth) -> Result<HeaderValue> {
    let encoded =
        ostrya_core::base64::encode(format!("{}:{}", auth.user, auth.password).as_bytes());
    HeaderValue::try_from(format!("Basic {encoded}"))
        .map_err(|_| Error::Fetch("invalid basic-auth credentials".into()))
}

/// The origin, and the authority it is addressed by, of one absolute URL.
///
/// The scheme is checked before the URL is parsed, because a URL the fetcher
/// cannot serve at all -- a `file://` one, say -- is worth saying so about even
/// when it is not a well-formed HTTP URL. Userinfo is refused rather than
/// dropped, since credentials that never reach the wire answer 401, which
/// points at nothing; `credentials` names the field that carries them instead.
/// A userinfo holds a password, so what the refusal names is the scheme and the
/// host, and a message about a URL whose authority the parse has not reached
/// names the URL with any userinfo left out.
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
    // `Uri::host` wraps an IPv6 literal in brackets. The brackets belong to the
    // authority -- the `Host` header and the absolute URL carry them -- and not
    // to the address itself: a connect resolves the bracketed form to nothing,
    // and a TLS server name is not built from it either.
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
    // A host compares as one origin whichever case it is written in, so the
    // pool key holds it in lower case: a `Location` header echoes the case the
    // origin server wrote, and two cases of one host would otherwise open two
    // connections and two HTTP/2 sessions to it.
    let host = literal
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(literal)
        .to_ascii_lowercase();
    // `Uri` accepts an authority whose port it cannot read -- `h:99999`, `h:`,
    // `h:abc` -- and reports no port for it. Taking the scheme default there
    // serves the request from a port the caller did not name, and the rebuilt
    // authority drops the port as well, so the port text is read from the
    // authority and refused.
    let port_text = uri
        .authority()
        .and_then(|authority| authority.as_str().strip_prefix(literal))
        .and_then(|rest| rest.strip_prefix(':'));
    let default_port = if tls { 443 } else { 80 };
    let port = match (uri.port_u16(), port_text) {
        (Some(port), _) => port,
        (None, None) => default_port,
        (None, Some(text)) => {
            return Err(Error::Fetch(format!(
                "url {url} names the port {text:?}, which is not a number from 0 to 65535"
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

/// How a message names a URL whose authority the parse has not reached, which
/// is a URL whose userinfo has not been refused yet. Userinfo holds a password,
/// so the part of the authority before the `@` is left out.
fn without_userinfo(url: &str) -> Cow<'_, str> {
    let start = url.find("://").map_or(0, |at| at + 3);
    let end = url[start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |at| start + at);
    match url[start..end].rfind('@') {
        Some(at) => Cow::Owned(format!("{}{}", &url[..start], &url[start + at + 1..])),
        None => Cow::Borrowed(url),
    }
}

/// The `Host` header value of one authority.
fn host_header(url: &str, authority: &str) -> Result<HeaderValue> {
    HeaderValue::try_from(authority)
        .map_err(|_| Error::Fetch(format!("url {url} has an unusable host")))
}

/// Parse one base URL into a [`Mirror`].
fn parse_mirror(url: &str) -> Result<Mirror> {
    let (uri, origin, authority) = parse_authority(url, "FetcherOptions::basic_auth")?;
    // A request target is the mirror's base path with the object path appended,
    // so a query string the base URL carries would be dropped without a word.
    // It is rejected rather than ignored: a presigned URL that lost its
    // signature answers 403, which does not point at the URL that caused it.
    if let Some(query) = uri.query() {
        return Err(Error::Fetch(format!(
            "mirror url {url} carries the query string ?{query}, which the fetcher does not send"
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

/// Parse the absolute URL a request names into its [`Destination`].
///
/// The query string is part of what the request names, so it reaches the wire
/// as written. A fragment is refused: it is never sent, so a URL carrying one
/// asks for a resource other than the one the caller named.
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
    // The one string the destination holds is assembled from the parts the
    // parse produced: the whole of it is the absolute URL, and its tail from
    // the prefix length is the origin-form target.
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

/// The `Content-Length` a response declared, when it declared a usable one.
fn content_length(headers: &hyper::HeaderMap) -> Option<u64> {
    headers
        .get(hyper::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// The coding a response declared, when it declared one a body would have to
/// be decoded from.
///
/// `Content-Encoding` codes the content, and `Transfer-Encoding` codes the
/// message the content travels in; a body under either holds bytes other than
/// the ones the remote stores, so both headers are read. A response that
/// declares both is named by its content coding.
fn declared_coding(headers: &hyper::HeaderMap) -> Option<String> {
    coding(headers, hyper::header::CONTENT_ENCODING, &[IDENTITY]).or_else(|| {
        coding(
            headers,
            hyper::header::TRANSFER_ENCODING,
            &[IDENTITY, CHUNKED],
        )
    })
}

/// The coding a response declared under `name`, when it declared one outside
/// `undone` -- the codings that leave the body as the remote wrote it.
///
/// A value is a comma-separated list of codings, and several headers of one
/// name state one list together, so every token of every value is read. A value
/// whose tokens are all empty names no coding, and it joins nothing to what
/// comes back either, so a stray separator reaches no message. What comes back
/// is the text the response carried, in the order it carried it, so the refusal
/// names the server's own value; a response with nothing to refuse builds no
/// string.
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

/// Whether one token of a coding list names a coding outside `undone`. The
/// comparison ignores case and the space around the token, and an empty token
/// names nothing.
fn names_a_coding(token: &str, undone: &[&str]) -> bool {
    let token = token.trim();
    !token.is_empty() && !undone.iter().any(|name| token.eq_ignore_ascii_case(name))
}

/// Read the cache validators out of a response.
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

/// Decide whether an unsuccessful status is worth another attempt.
fn classify(status: StatusCode, url: &str) -> Failure {
    let error = Error::HttpStatus {
        status: status.as_u16(),
        url: url.to_string(),
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

/// A transport-level failure against one URL.
fn transport(url: &str, error: hyper::Error) -> Error {
    Error::Fetch(format!("{url}: {error}"))
}

/// A response that did not deliver its head within the progress window.
fn stalled(url: &str, limit: Duration) -> Error {
    Error::Fetch(format!("{url}: no response after {limit:?}"))
}

/// Run `future` under a deadline, resolving to `None` when `limit` expires
/// first. The future is dropped on expiry, which cancels the work it holds.
async fn within<F: Future>(limit: Duration, future: F) -> Option<F::Output> {
    futures_lite::future::or(async { Some(future.await) }, async {
        rt::Timer::after(limit).await;
        None
    })
    .await
}

/// The delay before retry round `round`, doubling from 250ms up to two seconds.
fn backoff(round: u32) -> Duration {
    let ms = 250u64 << (round - 1).min(3);
    Duration::from_millis(ms)
}

/// The fetcher and its bodies move freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Fetcher>();
    assert_send_sync::<Body>();
    assert_send_sync::<Fetched>();
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The connection window holds one stream window for every request the
    /// fetcher admits, and stops at the protocol's own ceiling.
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
            mirror.destination("objects/ab/cd.filez").url(),
            "https://example.com/repo/objects/ab/cd.filez"
        );
        assert_eq!(mirror.origin.port, 443);
        assert!(mirror.origin.tls);

        let root = parse_mirror("http://example.com").unwrap();
        assert_eq!(
            root.destination("summary").url(),
            "http://example.com/summary"
        );
        assert_eq!(root.origin.port, 80);
        assert!(!root.origin.tls);

        // A non-default port stays in the URL and in the host header; a leading
        // slash on the path is not doubled.
        let ported = parse_mirror("http://127.0.0.1:8080/r").unwrap();
        let config = ported.destination("/config");
        assert_eq!(config.url(), "http://127.0.0.1:8080/r/config");
        assert_eq!(config.target(), "/r/config");
        assert_eq!(ported.authority, "127.0.0.1:8080");
        assert_eq!(root.authority, "example.com");
    }

    /// An IPv6 literal is bracketed in the authority and bare everywhere the
    /// address itself is used: the brackets reach neither the connect nor the
    /// TLS server name, and both fail on them.
    #[test]
    fn an_ipv6_literal_keeps_its_brackets_only_in_the_authority() {
        let ported = parse_mirror("http://[::1]:8080/r").unwrap();
        assert_eq!(ported.origin.host, "::1");
        assert_eq!(ported.origin.port, 8080);
        assert_eq!(ported.authority, "[::1]:8080");
        assert_eq!(
            ported.destination("summary").url(),
            "http://[::1]:8080/r/summary"
        );

        let tls = parse_mirror("https://[2001:db8::1]/repo").unwrap();
        assert_eq!(tls.origin.host, "2001:db8::1");
        assert_eq!(tls.origin.port, 443);
        assert_eq!(tls.authority, "[2001:db8::1]");
        assert_eq!(
            tls.destination("summary").url(),
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

        // Neither a query nor userinfo reaches the wire, so a URL carrying one
        // is refused instead of being served with the part missing.
        let err = parse_mirror("https://host/repo?X-Amz-Signature=deadbeef").unwrap_err();
        assert!(err.to_string().contains("query string"), "{err}");
        let err = parse_mirror("https://user:pass@host/repo").unwrap_err();
        assert!(err.to_string().contains("userinfo"), "{err}");
        // A bare user with no password is userinfo too.
        let err = parse_mirror("http://user@host/repo").unwrap_err();
        assert!(err.to_string().contains("userinfo"), "{err}");
    }

    #[test]
    fn options_are_validated_at_construction() {
        rt::block_on(async {
            let mut options = FetcherOptions::new("http://example.com");
            options.headers = vec![("not a header".into(), "v".into())];
            let err = Fetcher::new(options).await.unwrap_err();
            assert!(err.to_string().contains("invalid header name"), "{err}");

            // The host header comes from the url the request is sent to, so a
            // caller-supplied one would collide with it.
            let mut options = FetcherOptions::new("http://example.com");
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

    /// A request path is appended to the base path as written, so a `?` or a
    /// `#` in it delimits rather than names, and the target stops being the one
    /// the caller asked for.
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

    /// The request path is appended to the mirror's base path, and the target
    /// carries the origin form for HTTP/1.1.
    #[test]
    fn a_request_target_appends_the_path_to_the_base() {
        rt::block_on(async {
            let fetcher = Fetcher::new(FetcherOptions::new("http://example.com/r"))
                .await
                .unwrap();
            let mirror = &fetcher.inner.mirrors[0];
            let destination = mirror.destination("refs/heads/a");
            let request = fetcher
                .build_request(
                    &destination,
                    &FetchRequest::path("refs/heads/a"),
                    &fetcher.inner.headers,
                    Protocol::Http11,
                )
                .unwrap();
            assert_eq!(request.uri(), "/r/refs/heads/a");
        });
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
            ..FetcherOptions::new(url)
        }
    }

    /// A credential reaches every mirror, so one cleartext mirror is enough to
    /// refuse the configuration. Credentials named in `headers` are refused the
    /// same way; any other header is sent whatever the scheme.
    #[test]
    fn credentials_alongside_a_cleartext_mirror_are_refused() {
        let auth = || {
            Some(BasicAuth {
                user: "u".into(),
                password: "p".into(),
            })
        };

        // The cleartext mirror is named, whether it is the only one or one entry
        // among https ones.
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

        // Every credential-bearing header name, refused the same way.
        for name in ["authorization", "proxy-authorization", "cookie"] {
            let options = FetcherOptions {
                headers: vec![(name.to_owned(), "secret".to_owned())],
                ..FetcherOptions::new("http://cleartext.example/repo")
            };
            let err = rt::block_on(Fetcher::new(options)).unwrap_err();
            let message = err.to_string();
            assert!(message.contains(name), "{message}");
            assert!(message.contains("carries credentials"), "{message}");
        }

        // A header that is not a credential reaches a cleartext mirror.
        let options = FetcherOptions {
            headers: vec![("x-trace".to_owned(), "abc".to_owned())],
            ..FetcherOptions::new("http://cleartext.example/repo")
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

    /// A request URL is served as it is written: the query string is part of
    /// what the request names and reaches the wire, while userinfo and a
    /// fragment are refused, neither of them being sent. The absolute URL, the
    /// origin-form target, the authority, and the origin are all read off the
    /// one string the destination holds.
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
            // A URL with no path of its own asks for the root, whether it
            // writes the trailing slash or not.
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
            // The default port for the scheme is left out of the authority
            // whether the URL wrote it or not, and the scheme is held in lower
            // case.
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
        // The address itself is held without the brackets the authority carries.
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

    /// A message about a URL the parse has not read the authority of leaves the
    /// userinfo out, whichever of those messages it is.
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
    }

    /// `Uri` accepts an authority whose port it cannot read and reports no port
    /// for it, so a URL naming such a port is refused rather than served from
    /// the scheme default.
    #[test]
    fn a_port_the_url_parser_cannot_read_is_refused() {
        for (url, text) in [
            ("http://h:99999/x", "99999"),
            ("http://h:65536/x", "65536"),
            ("http://h:abc/x", "abc"),
            ("http://h:/x", ""),
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
    }

    /// A host compares as one origin whichever case it is written in, so two
    /// spellings of one origin are one pool key.
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

    /// The password is left out of what a struct carrying credentials renders.
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
            ..FetcherOptions::new("https://example.com")
        };
        let rendered = format!("{options:?}");
        assert!(!rendered.contains("sup3rs3cret"), "{rendered}");
    }

    /// The connection layer frames a request and holds its connection, so a
    /// header of one of those names is refused: by the constructor for a
    /// fetcher header, and before admission for a request header.
    #[test]
    fn a_connection_header_is_refused_at_both_layers() {
        let fetcher_headers = vec![(
            HeaderName::from_static("x-trace"),
            HeaderValue::from_static("abc"),
        )];
        for name in CONNECTION_HEADERS {
            let options = FetcherOptions {
                headers: vec![(name.to_owned(), "10".to_owned())],
                ..FetcherOptions::new("http://example.com")
            };
            let err = rt::block_on(Fetcher::new(options)).unwrap_err();
            let message = err.to_string();
            assert!(message.contains(name), "{name}: {message}");
            assert!(message.contains("connection layer"), "{name}: {message}");

            let request = vec![(name.to_owned(), "10".to_owned())];
            let err = merge_headers(&fetcher_headers, &request, None).unwrap_err();
            let message = err.to_string();
            assert!(message.contains(name), "{name}: {message}");
            assert!(message.contains("connection layer"), "{name}: {message}");
        }

        // A name written in another case is the same header name.
        let request = vec![("Content-Length".to_owned(), "10".to_owned())];
        let err = merge_headers(&fetcher_headers, &request, None).unwrap_err();
        assert!(err.to_string().contains("content-length"), "{err}");
    }

    /// A request that adds neither a header nor credentials sends the
    /// fetcher's list by reference. A request header replaces the fetcher
    /// header of the same name, and the request's credentials replace the
    /// fetcher's `Authorization`.
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

        let borrowed = merge_headers(&fetcher, &[], None).unwrap();
        assert!(matches!(borrowed, Cow::Borrowed(_)));
        assert_eq!(sent(&borrowed), sent(&fetcher));

        // The replacement compares names as header names, so it holds whatever
        // case the request wrote, and it leaves every other fetcher header in
        // place. Two request headers of one name both reach the wire.
        let extra = vec![
            ("X-Trace".to_owned(), "request".to_owned()),
            ("x-trace".to_owned(), "second".to_owned()),
        ];
        let merged = merge_headers(&fetcher, &extra, None).unwrap();
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
        let merged = merge_headers(&fetcher, &[], Some(&auth)).unwrap();
        assert_eq!(
            sent(&merged),
            [
                ("x-trace".to_owned(), "fetcher".to_owned()),
                ("x-only".to_owned(), "yes".to_owned()),
                ("authorization".to_owned(), "Basic dTpw".to_owned()),
            ]
        );

        let both = vec![("authorization".to_owned(), "Basic aaa".to_owned())];
        let err = merge_headers(&fetcher, &both, Some(&auth)).unwrap_err();
        assert!(err.to_string().contains("pass one of them"), "{err}");
        let host = vec![("host".to_owned(), "elsewhere".to_owned())];
        let err = merge_headers(&fetcher, &host, None).unwrap_err();
        assert!(err.to_string().contains("host header"), "{err}");
        let invalid = vec![("not a header".to_owned(), "v".to_owned())];
        let err = merge_headers(&fetcher, &invalid, None).unwrap_err();
        assert!(err.to_string().contains("invalid header name"), "{err}");
    }

    /// A fetch delivers the bytes the remote stores, so a response is served
    /// only where it declares no coding, or declares `identity`. A value is a
    /// comma-separated list, several headers state one list together, and a
    /// token compares without case and without the space around it.
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

        // A coding the body would have to be decoded from, named as the
        // response wrote it. A list holding one refuses the whole response,
        // whichever position the coding sits in, and several headers are read
        // together in the order they arrived. A value whose tokens are all
        // empty names nothing, so it joins no separator to the message either.
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

    /// Every request asks for no content coding, and a configured header of one
    /// of the names the fetcher sets replaces that entry rather than joining it
    /// on the wire.
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

        let fetcher =
            rt::block_on(Fetcher::new(FetcherOptions::new("http://example.com"))).unwrap();
        assert_eq!(
            sent(&fetcher, hyper::header::ACCEPT_ENCODING),
            [IDENTITY.to_owned()]
        );

        for name in ["accept-encoding", "user-agent"] {
            let options = FetcherOptions {
                headers: vec![(name.to_owned(), "caller".to_owned())],
                ..FetcherOptions::new("http://example.com")
            };
            let fetcher = rt::block_on(Fetcher::new(options)).unwrap();
            let header = HeaderName::from_static(name);
            assert_eq!(sent(&fetcher, header), ["caller".to_owned()], "{name}");
        }

        // Two entries of one name both reach the wire, the entry the fetcher
        // sets having been replaced by the first of them.
        let options = FetcherOptions {
            headers: vec![
                ("accept-encoding".to_owned(), "one".to_owned()),
                ("Accept-Encoding".to_owned(), "two".to_owned()),
            ],
            ..FetcherOptions::new("http://example.com")
        };
        let fetcher = rt::block_on(Fetcher::new(options)).unwrap();
        assert_eq!(
            sent(&fetcher, hyper::header::ACCEPT_ENCODING),
            ["one".to_owned(), "two".to_owned()]
        );
        // A name the fetcher sets nothing under keeps both entries as well.
        let options = FetcherOptions {
            headers: vec![
                ("x-trace".to_owned(), "one".to_owned()),
                ("x-trace".to_owned(), "two".to_owned()),
            ],
            ..FetcherOptions::new("http://example.com")
        };
        let fetcher = rt::block_on(Fetcher::new(options)).unwrap();
        assert_eq!(
            sent(&fetcher, HeaderName::from_static("x-trace")),
            ["one".to_owned(), "two".to_owned()]
        );
    }

    /// A credential is withheld from no destination, so one cleartext
    /// destination among those a fetch may reach refuses it, and the origin is
    /// named. A header that is not a credential reaches a cleartext
    /// destination.
    #[test]
    fn a_credential_refuses_a_cleartext_destination() {
        let credential = vec![(hyper::header::COOKIE, HeaderValue::from_static("session=1"))];
        let plain = vec![(
            HeaderName::from_static("x-trace"),
            HeaderValue::from_static("abc"),
        )];
        // A fetcher whose mirror list holds one cleartext entry among https
        // ones. The credential is the request's, so the construction check
        // over the list has nothing to say about it.
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

    /// A handshake verifies the server certificate against a trust anchor, so
    /// a fetch of a TLS origin is refused before admission when the fetcher
    /// holds none, and the origin is named. The fetcher that carries the flag
    /// clear is one built on a host whose trust store holds nothing, which is
    /// what the flag is set by hand to stand for here: this host has a CA
    /// bundle, and `TrustRoots::Pem` fails the constructor over a blob that
    /// holds no certificate.
    #[test]
    fn a_tls_destination_needs_a_trust_anchor() {
        rt::block_on(async {
            let mut fetcher = Fetcher::new(FetcherOptions::new("http://cleartext.example/repo"))
                .await
                .unwrap();
            Arc::get_mut(&mut fetcher.inner)
                .expect("the one handle on this fetcher")
                .has_trust_anchors = false;

            // Nothing listens on port 1 of the loopback, so an attempt would
            // fail its connect and be retried through every round and every
            // backoff. The refusal is definitive and takes no attempt, so it
            // resolves at once.
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
}
