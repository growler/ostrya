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
//! and reused once the previous body has been read to the end. The pool key
//! holds three terms: the endpoint the connection is open to, whether the
//! connection presents the configured client certificate, and whether it is a
//! proxy connection carrying absolute-form requests. The endpoint is the origin
//! for a direct connection and for a tunnel, whose TLS reaches the origin
//! itself, and it is the proxy for a proxied cleartext connection. So a URL
//! target shares a connection with a mirror at the same origin, and one proxy
//! connection carries requests for any cleartext origin.
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
//! A credential is withheld from no destination a route names, so credentials
//! and cleartext are refused together. A redirect hop names an origin of the
//! server's choosing, and the redirect paragraph below states what a credential
//! does there. [`basic_auth`](FetcherOptions::basic_auth), or an
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
//! trust store is empty, and a fetch that would consult them there is refused
//! with the origin named: a request naming an `https` URL of its own is refused
//! before admission, and a redirect hop onto a TLS origin ends the attempt
//! definitively.
//!
//! A proxy carries the request where one applies to the origin.
//! [`proxy`](FetcherOptions::proxy) states which one:
//! [`Proxy::None`] reaches every origin directly, [`Proxy::Environment`] reads
//! `http_proxy`, `https_proxy`, `all_proxy`, and `no_proxy` out of the process
//! environment once, at construction, [`Proxy::Variables`] states those same
//! variables in the options instead of in the process, and [`Proxy::Url`] names
//! one proxy for every origin. `http_proxy` serves `http` origins, `https_proxy`
//! serves `https` ones, and `all_proxy` serves either where the scheme-specific
//! variable is unset. Each name is read in upper case as well, `HTTP_PROXY`
//! excepted: a CGI gateway hands a request header called `Proxy` on under that
//! name, so a request of a client's own would otherwise pick the proxy the
//! fetcher connects through. Lower case wins over upper case, and an empty
//! value counts as unset. Nothing re-reads the environment per request.
//!
//! A proxy URL is `http://host[:port]`, port 80 by default, with no path other
//! than `/`, no query, and no fragment. Userinfo is percent-decoded and sent to
//! the proxy as `Proxy-Authorization: Basic`. Anything else -- an `https://` or
//! a `socks5://` proxy among them -- fails [`Fetcher::new`] with
//! [`Error::Unsupported`](crate::Error::Unsupported), whether the options or the
//! environment named it, and the message names the value with any userinfo left
//! out.
//!
//! `no_proxy` states the origins the two environment forms exempt, as a
//! comma-separated list. An entry holds a host text, one leading `.` where it
//! is written with one, and `:port` where it names a port; space around an
//! entry is ignored, and an entry left naming no host -- an empty one, `.`, and
//! `:8080` among them -- exempts nothing. `*` as a whole entry exempts every
//! host, and it is the one wildcard the list reads: `*.example.com` is a host
//! text, which no origin holds. An entry matches an origin when it equals the
//! host or the host ends with a `.` and the entry; one leading `.` on the entry
//! is stripped first, so `.example.com` and `example.com` both exempt
//! `a.example.com`, and a second `.` belongs to the host text the entry names.
//! An entry carrying `:port` matches that port alone. The match is made against
//! the host text of the URL, ASCII case ignored, and never against the address
//! the host resolves to: `localhost` exempts no origin written as `127.0.0.1`,
//! and an entry that is an IP literal matches that text alone. An entry in CIDR
//! notation names no network here, which is where this parts from curl 7.86 and
//! later; it is read as a host text, which no origin holds. An empty `no_proxy`
//! value exempts nothing, and [`Proxy::Url`] reads no exemptions at all, naming
//! the one proxy every origin is reached through.
//!
//! A cleartext origin behind a proxy is reached over a connection to the proxy,
//! and the request carries the absolute-form target -- the whole
//! `http://host/path` URL -- together with the origin's own `Host` header. Such
//! a connection speaks HTTP/1.1, cleartext HTTP/2 needing prior knowledge or an
//! upgrade, and it pools under the proxy rather than under the origin, one
//! proxy connection carrying requests for any cleartext origin. The pool key
//! states that a connection is a proxy's, so a direct connection to an endpoint
//! that happens to be the proxy's own is never handed to a proxied request, nor
//! the other way about: the two request forms differ, and a server answers the
//! form it was not expecting with a 404.
//!
//! A TLS origin behind a proxy is reached over a `CONNECT` tunnel. The request
//! names the target as `host:port`, with the port always written and an IPv6
//! literal keeping its brackets, and carries the same `Proxy-Authorization`
//! where the proxy URL held userinfo. On a 2xx the tunneled socket comes back
//! and the TLS handshake, the ALPN protocol selection, and the connection pool
//! entry are the ones a direct connection to that origin gets. A byte that
//! arrives before the client has spoken fails the connect: nothing follows a
//! `CONNECT` response. A non-2xx answer is a retryable failure and a 407 is a
//! definitive one, both [`Error::Fetch`](crate::Error::Fetch) naming the proxy.
//! [`connect_timeout`](FetcherOptions::connect_timeout) bounds the whole of it:
//! the connect to the proxy, the `CONNECT` exchange, the TLS handshake, and the
//! HTTP handshake together.
//!
//! The proxy credential belongs to the connection layer. It reaches the proxy
//! on a proxied cleartext request and on a `CONNECT`, and it reaches no origin:
//! it is no part of the merged header list, so neither the cleartext credential
//! check nor the redirect scoping reads it, and a tunnel carries nothing of it.
//! A `Proxy-Authorization` header a caller sets keeps the meaning it has
//! without a proxy: it is a credential in the merged list, refused for a
//! cleartext destination the way the other two are. On a proxied cleartext
//! request it replaces the fetcher's own proxy credential, two values for one
//! header being two answers to one question; over a tunnel the two never meet,
//! the caller's reaching the origin and the fetcher's the proxy.
//!
//! The proxy decision is made per hop, from that hop's origin, so a redirect
//! onto another origin is served the way a route naming that origin would be.
//! A proxy changes nothing about the cleartext rule: a cleartext origin is
//! cleartext however it is reached.
//!
//! A redirect is followed. A 301, 302, 303, 307, or 308 sends the attempt on
//! to the URL its `Location` header names, up to
//! [`max_redirects`](FetcherOptions::max_redirects) times; every request the
//! fetcher makes is a GET, so no status among the five changes the method of
//! the hop that follows it. A limit of zero follows nothing, and each of those
//! statuses is then a definitive answer of its own. An attempt that has
//! followed the limit and is sent on to another URL fails definitively with
//! [`Error::RedirectLimit`](crate::Error::RedirectLimit).
//!
//! `Location` is resolved against the URL of the response that carried it, so
//! it reads as an absolute URL, a relative one (`/other/path`, `sibling`), or
//! a scheme-relative one (`//host/path`). The resolution normalizes what it
//! produces: a dot segment is resolved away, a backslash reads as a path
//! separator, a tab and a newline are removed, a character a path or a query
//! may not carry is percent-encoded, an IPv4 or an IPv6 host is canonicalized,
//! and a fragment is dropped, which is what the HTTP specification prescribes
//! for a redirect. A [`Target::Url`] reaches the wire as the caller wrote it,
//! so one string named as a URL target and named as a `Location` reaches the
//! server as two different request targets. Two hops are refused definitively
//! with [`Error::Fetch`](crate::Error::Fetch) naming both the URL that
//! redirected and the URL it named: a scheme other than `http` or `https`, and
//! a hop from `https` to `http`. A hop onto a TLS origin is refused the same
//! way on a fetcher that holds no trust anchors. A hop from `http` to `https`
//! is followed. A response carrying one of the five statuses and no `Location`
//! the resolution reads a URL out of -- no header at all, an empty value, a
//! value that is not text, or a value the resolution cannot read -- is reported
//! as the status it answered, whatever the hop count.
//!
//! `Authorization`, `Proxy-Authorization`, and `Cookie`, from either layer,
//! reach the origin the route named and a hop at that same origin -- the same
//! scheme, host, and port -- and are dropped for a hop at any other origin. A
//! credential dropped once stays dropped for the rest of that attempt, a
//! redirect back to the named origin included: the other origin's operator has
//! the request by then. Every other header reaches every hop, the `User-Agent`
//! and the `Accept-Encoding` the fetcher sets included. A configured client
//! certificate is presented to the origin the route named and to no other, so
//! the connection pool holds the connections opened with it apart from the ones
//! opened without.
//!
//! The body of an intermediate response is discarded the way the body of an
//! unsuccessful one is, so one whose declared length is at or below 64 KiB
//! returns its HTTP/1.1 connection to the pool and a chain that stays on one
//! origin travels over one connection; a chain whose intermediate responses
//! declare more than that, or declare nothing, opens a connection per hop.
//! [`max_size`](FetchRequest::max_size) is compared against the final
//! response's `Content-Length` and enforced while the final body streams; an
//! intermediate response is not measured against it. The validators reach every
//! hop, since they describe the resource, and a 304 from any hop is the caller's
//! answer. Every diagnostic names the URL of the response that answered, which
//! after a redirect is the last hop's.
//!
//! What a fetch does when something goes wrong. A path target is served under
//! every mirror, in the mirror order, and its destination is resolved at the
//! attempt that uses it; a URL target has the one destination the URL names.
//! The hop count belongs to one attempt, so a retryable status on a hop makes
//! the whole attempt retryable, and the round that repeats it starts again from
//! the destination the route named.
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
//! absent object. Every such read one attempt makes shares one
//! [`progress_timeout`](FetcherOptions::progress_timeout) window, whatever the
//! number of hops: a peer that declares a short body on every hop and sends
//! fewer bytes than it declared spends that window once, and the reads after it
//! close their connections without waiting.
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
use std::time::{Duration, Instant};

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
use tls::{ClientConfigs, client_config};
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

/// The variables [`Proxy::Environment`] reads, in the order a lookup prefers
/// them: the lower-case name of each, and the upper-case name where one is
/// read. `HTTP_PROXY` is read by nothing. A CGI gateway hands a request header
/// called `Proxy` on to the program under that name, so a request of a client's
/// own would otherwise name the proxy the fetcher connects through.
const PROXY_VARIABLES: [&str; 7] = [
    "http_proxy",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
];

/// The scheme a proxy URL is named under, which is the one scheme a proxy
/// connection is opened with.
const PROXY_SCHEME: &str = "http://";

/// The statuses a redirect is followed at. Every request the fetcher makes is
/// a GET, so none of the five changes the method of the hop that follows it,
/// and the ones that part over the method are one case here.
const REDIRECTS: [StatusCode; 5] = [
    StatusCode::MOVED_PERMANENTLY,
    StatusCode::FOUND,
    StatusCode::SEE_OTHER,
    StatusCode::TEMPORARY_REDIRECT,
    StatusCode::PERMANENT_REDIRECT,
];

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

/// Which proxy a [`Fetcher`] reaches an origin through.
///
/// The module documentation states the variables the two environment forms
/// read, the shape of a proxy URL, and the exemptions `no_proxy` lists. Every
/// form is resolved once, by [`Fetcher::new`], which is what refuses a proxy
/// URL the fetcher cannot connect through.
///
/// The [`Debug`] rendering leaves the userinfo of a proxy URL out, so a struct
/// that carries proxy credentials is logged without them.
#[derive(Clone, Default)]
pub enum Proxy {
    /// Connect directly, whatever the environment says.
    None,
    /// Read `http_proxy`, `https_proxy`, `all_proxy`, and `no_proxy` from the
    /// process environment, once, at construction.
    #[default]
    Environment,
    /// The same variables, stated as name and value pairs rather than read from
    /// the process. A name the environment forms do not read is ignored here as
    /// well, and among two entries of one name the first with a value is the one
    /// read.
    Variables(Vec<(String, String)>),
    /// One `http://` proxy URL for every origin, whose userinfo is sent as
    /// `Proxy-Authorization: Basic`. No origin is exempt: the environment is
    /// read for neither the proxy nor the exemptions.
    Url(String),
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Proxy::None => f.write_str("None"),
            Proxy::Environment => f.write_str("Environment"),
            Proxy::Variables(variables) => {
                let held = variables
                    .iter()
                    .map(|(name, value)| (name, without_userinfo(value)));
                f.debug_tuple("Variables")
                    .field(&held.collect::<Vec<_>>())
                    .finish()
            }
            Proxy::Url(url) => f.debug_tuple("Url").field(&without_userinfo(url)).finish(),
        }
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
    /// Extra headers sent with every request, to every destination and on to
    /// every redirect hop. A request header of the same name replaces one of
    /// these. The fetcher itself sets `User-Agent` and
    /// `Accept-Encoding: identity`, and an entry of one of those names
    /// replaces the value the fetcher sets. An `Authorization`,
    /// `Proxy-Authorization`, or `Cookie` header is refused at construction
    /// when any mirror is cleartext `http`, since its value is a secret
    /// whatever it holds, and it reaches the origin a route named and a
    /// redirect hop at that same origin alone. A `Host` header, and a header
    /// the connection layer sets -- the framing and hop-by-hop names -- is
    /// refused at construction as well. Any other header is sent as written.
    pub headers: Vec<(String, String)>,
    /// Credentials for `Authorization: Basic`, sent with every request to
    /// every destination and to a redirect hop at the origin the route named,
    /// and replaced for one request by
    /// [`FetchRequest::basic_auth`]. Every mirror must be `https`: a cleartext
    /// one is refused at construction rather than sent the credentials in the
    /// clear. An `Authorization` entry in
    /// [`headers`](FetcherOptions::headers) alongside these is refused at
    /// construction, both of them setting the same header.
    pub basic_auth: Option<BasicAuth>,
    /// Trust anchors and the client certificate, for `https` mirrors.
    pub tls: TlsOptions,
    /// Which proxy an origin is reached through, which defaults to the one the
    /// process environment names. The value is resolved by [`Fetcher::new`],
    /// which refuses a proxy URL that is not `http://host[:port]`; nothing
    /// re-reads it per request.
    pub proxy: Proxy,
    /// Whether to offer HTTP/2 in ALPN. With this false the fetcher speaks
    /// HTTP/1.1 even against a server that supports HTTP/2.
    pub http2: bool,
    /// How many times a round of destinations is repeated after a retryable
    /// failure.
    pub max_retries: u32,
    /// How many redirects one attempt against one destination follows. A 301,
    /// 302, 303, 307, or 308 is followed while the attempt has followed fewer
    /// than this many; the next one that names a URL fails the attempt
    /// definitively with [`Error::RedirectLimit`], and one that names none
    /// reports its own status. Zero follows nothing, and each of those statuses
    /// is then a definitive answer of its own. The count belongs to one attempt,
    /// so a repeated round counts again from the destination the route named.
    pub max_redirects: u32,
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
            proxy: Proxy::default(),
            http2: true,
            max_retries: 5,
            max_redirects: 10,
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
    /// [`io::ErrorKind::FileTooLarge`](std::io::ErrorKind::FileTooLarge). The
    /// cap is compared against the response that answers, so an intermediate
    /// redirect response is not measured against it.
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
    ///
    /// A redirect hop carries a credential to no cleartext origin of its own:
    /// the credential is dropped for a hop at another origin, and a hop from
    /// `https` to `http` is refused.
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
    /// by together with the client identity the connection presents.
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

/// A connection endpoint.
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

/// What the connection pool is keyed by: an endpoint, which of the two client
/// configurations opened the connection, and whether it is a proxy's.
///
/// A connection presents the client certificate for every request it carries,
/// so one opened with the certificate is never handed to a hop that must not
/// present it, and one opened without it is never handed to the origin the
/// route named. The flag sits here rather than in [`Origin`], which states the
/// identity of a network endpoint and is what the cleartext and trust-anchor
/// checks read.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PoolKey {
    origin: Origin,
    /// Whether the connection presents the configured client certificate.
    identity: bool,
    /// Whether the connection goes to a proxy and carries absolute-form
    /// requests. Such a connection is pooled under the proxy endpoint, which a
    /// cleartext origin of the same host and port is pooled under as well, and
    /// the two carry different request forms: the flag is what keeps one from
    /// being handed to the other's request.
    proxied: bool,
}

/// One proxy the fetcher connects through, resolved from a proxy URL.
#[derive(Debug)]
struct ProxyEndpoint {
    /// Where the connection goes. A proxy is reached over cleartext, so this
    /// origin is never TLS.
    endpoint: Origin,
    /// The `Proxy-Authorization` value the proxy URL's userinfo builds, where
    /// it carried any.
    credential: Option<HeaderValue>,
    /// How a diagnostic names this proxy, which is its URL with the userinfo
    /// left out.
    named: String,
}

/// One `no_proxy` entry: a host text, and the port it is qualified by where it
/// named one.
#[derive(Debug)]
struct Exemption {
    /// The host the entry names, in ASCII lower case, with one leading `.`
    /// stripped. This is never empty: an entry naming no host exempts nothing
    /// and reaches no list.
    host: String,
    /// The port the entry matches, where it named a readable one.
    port: Option<u16>,
}

impl Exemption {
    /// Whether this entry exempts `origin`.
    ///
    /// The comparison is made byte by byte, ASCII case ignored, so a host that
    /// is not ASCII is compared without the slicing a character boundary would
    /// fault on.
    fn matches(&self, origin: &Origin) -> bool {
        if self.port.is_some_and(|port| port != origin.port) {
            return false;
        }
        let host = origin.host.as_bytes();
        let entry = self.host.as_bytes();
        if host.eq_ignore_ascii_case(entry) {
            return true;
        }
        // The host is a name under the entry, which the `.` before the entry is
        // what states: `notexample.com` is no part of `example.com`.
        host.len() > entry.len()
            && host[host.len() - entry.len() - 1] == b'.'
            && host[host.len() - entry.len()..].eq_ignore_ascii_case(entry)
    }
}

/// Which proxy each scheme is reached through, and what is exempt from both.
#[derive(Debug, Default)]
struct Proxies {
    /// The proxy a cleartext origin is reached through.
    http: Option<Arc<ProxyEndpoint>>,
    /// The proxy a TLS origin is reached through. One proxy URL serving both
    /// schemes is held here and in `http` as one endpoint.
    https: Option<Arc<ProxyEndpoint>>,
    /// Whether `no_proxy` listed `*`, which exempts every host.
    exempt_all: bool,
    /// The hosts `no_proxy` listed.
    exempt: Vec<Exemption>,
}

impl Proxies {
    /// How a hop at `origin` is reached. This reads the resolved state and
    /// allocates nothing, so the decision costs a fetch one walk of the
    /// exemption list.
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

/// How one hop reaches its origin.
#[derive(Clone, Copy, Debug)]
enum Via<'a> {
    /// Straight to the origin.
    Direct,
    /// Over a connection to the proxy carrying absolute-form requests, which is
    /// how a cleartext origin behind a proxy is reached.
    Absolute(&'a ProxyEndpoint),
    /// Over a `CONNECT` tunnel through the proxy, which is how a TLS origin
    /// behind a proxy is reached.
    Tunnel(&'a ProxyEndpoint),
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

/// The connections pooled under one [`PoolKey`].
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
    tls: ClientConfigs,
    /// Whether a handshake has what it needs to verify the peer. A store with
    /// no anchor reaches here for a fetcher whose mirrors are all cleartext,
    /// which opens no handshake to consult them, and a TLS destination is
    /// refused there. A bypass variant of [`TrustRoots`] reads no store and
    /// reports true, because its handshake consults no anchor and completes.
    has_trust_anchors: bool,
    /// Whether a client certificate is configured, which is what makes the two
    /// client configurations differ. With none configured every connection is
    /// opened over one configuration and the pool holds one entry per origin.
    client_identity: bool,
    /// Which proxy each scheme is reached through, resolved at construction.
    proxies: Proxies,
    max_retries: u32,
    max_redirects: u32,
    connect_timeout: Duration,
    progress_timeout: Duration,
    fetch_timeout: Option<Duration>,
    gate: Arc<Gate>,
    h2_connection_window: u32,
    pool: Mutex<HashMap<PoolKey, PoolEntry>>,
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
    /// `Authorization` header; when a proxy URL, from the options or from the
    /// environment, is not `http://host[:port]`; or when the TLS material does
    /// not parse.
    ///
    /// This is async because [`TrustRoots::System`](crate::TrustRoots::System),
    /// the default, reads the host trust store, which goes to the blocking
    /// pool. The TLS configuration is built whatever the mirrors' scheme is, so
    /// a cleartext-only fetcher reads it too; under
    /// [`TrustRoots::Pem`](crate::TrustRoots::Pem) the work is all in memory and
    /// the constructor never yields. A system store holding no certificate
    /// fails the constructor when at least one mirror is `https`, and when the
    /// mirror list is empty, since a request may then name an `https` URL; a
    /// host without a CA bundle still reaches a cleartext remote. Under either
    /// bypass variant of [`TrustRoots`](crate::TrustRoots) no store is read at
    /// all, so the constructor never yields and an empty host store is fatal
    /// for no mirror scheme.
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
        let proxies = resolve_proxy(&options.proxy)?;
        let max_outstanding = options.max_outstanding.max(1);
        // A fetcher with no mirror serves the URLs its requests name, any of
        // which may be `https`, so it has to hold trust anchors: an empty
        // system store is as fatal there as it is for an `https` mirror.
        let https = mirrors.is_empty() || mirrors.iter().any(|mirror| mirror.origin.tls);
        let tls = client_config(&options.tls, options.http2, https).await?;
        Ok(Fetcher {
            inner: Arc::new(Inner {
                mirrors,
                headers,
                has_trust_anchors: tls.has_trust_anchors,
                client_identity: options.tls.client_identity.is_some(),
                proxies,
                tls,
                max_retries: options.max_retries,
                max_redirects: options.max_redirects,
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

    /// Refuse a fetch whose route names a TLS destination on a fetcher that
    /// holds no trust anchors.
    ///
    /// A handshake verifies the server certificate against an anchor, so a
    /// fetcher with none reaches no TLS origin. What arrives here is a request
    /// naming an `https` URL of its own on a fetcher whose mirrors are all
    /// cleartext, since every other combination of route and anchors fails
    /// [`Fetcher::new`]. The handshake reports it as an unknown issuer, a
    /// retryable failure that spends every round and every backoff before it
    /// names anything, so the refusal is made here instead, before admission.
    ///
    /// This reads the destinations of the route. A redirect hop names an origin
    /// of the server's choosing, which the attempt refuses where it is TLS,
    /// under the message [`no_trust_anchors`] writes for both.
    fn check_trust_anchors(&self, route: &Route<'_>) -> Result<()> {
        if self.inner.has_trust_anchors {
            return Ok(());
        }
        let Some(origin) = self.matching_origin(route, |origin| origin.tls) else {
            return Ok(());
        };
        Err(no_trust_anchors(origin))
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

    /// One request against one destination, following the redirects it meets.
    ///
    /// The hop state of an attempt is three locals: the destination, borrowed
    /// from the route until a redirect names another one; the header list,
    /// which is the caller's slice until a hop crosses an origin and a
    /// credential has to come out of it; and the count of redirects followed.
    /// A first response that answers the request leaves all three as they
    /// start, so it builds no URL, copies no header list, and allocates no
    /// bookkeeping.
    async fn attempt(
        &self,
        destination: &Destination,
        request: &FetchRequest<'_>,
        headers: &[(HeaderName, HeaderValue)],
    ) -> std::result::Result<Attempted, Failure> {
        // The origin the route named, which is the one a credential and the
        // client certificate are scoped to.
        let named = &destination.origin;
        let mut hop = Cow::Borrowed(destination);
        let mut headers = Cow::Borrowed(headers);
        let mut followed = 0u32;
        let progress_timeout = self.inner.progress_timeout;
        // One progress window covers every drain this attempt makes, however
        // many hops it follows. A peer that answers each hop with a short
        // declared body and then stops sending spends the window on the first
        // drain, and every drain after it drops its connection rather than
        // waiting again. An attempt that follows no redirect drains once and
        // has the whole window for it.
        let drain_until = Instant::now() + progress_timeout;
        loop {
            // The proxy decision is this hop's own, and a cleartext hop behind
            // a proxy is pooled under the proxy endpoint rather than under the
            // origin: one such connection carries requests for any cleartext
            // origin.
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
            let (response, protocol, reuse) = self.send(&hop, &key, via, request, &headers).await?;
            let status = response.status();
            if status == StatusCode::NOT_MODIFIED {
                // A 304 carries no body, so the connection is immediately
                // reusable. The validators describe the resource, so a 304 a
                // hop answers is the caller's answer as much as one the
                // destination the route named answers.
                if let Some(sender) = reuse {
                    self.inner.put_h1(&key, sender);
                }
                return Ok(Attempted::NotModified);
            }
            // A limit of zero follows nothing, which leaves every redirect
            // status a definitive answer of its own.
            if is_redirect(status) && self.inner.max_redirects > 0 {
                let location = response
                    .headers()
                    .get(hyper::header::LOCATION)
                    .and_then(|value| resolve_location(url, value));
                let Some(location) = location else {
                    // There is nothing to follow, so the status the hop
                    // answered is the answer the attempt reports, whatever the
                    // hop count is by then.
                    let failure = classify(status, url);
                    self.discard(&key, response, reuse, drain_until).await;
                    return Err(failure);
                };
                // The limit stops the attempt at a URL it would otherwise
                // follow, so it is read once the `Location` names one.
                if followed >= self.inner.max_redirects {
                    self.discard(&key, response, reuse, drain_until).await;
                    return Err(Failure::Fatal(Error::RedirectLimit {
                        url: url.to_string(),
                        hops: followed,
                    }));
                }
                let next = redirect_destination(&hop, &location);
                // The intermediate body is discarded the way an unsuccessful
                // one is, so a short one returns its HTTP/1.1 connection to the
                // pool and the next hop at this origin travels over it.
                self.discard(&key, response, reuse, drain_until).await;
                let next = next.map_err(Failure::Fatal)?;
                // A handshake verifies the server certificate against an
                // anchor, so a hop onto a TLS origin is refused where the
                // fetcher holds none. The handshake would otherwise fail
                // retryably, spending every round and every backoff on a
                // message about the peer.
                if next.origin.tls && !self.inner.has_trust_anchors {
                    return Err(Failure::Fatal(no_trust_anchors(next.origin_url())));
                }
                // A credential is in the hands of the operator of the origin
                // the request reaches, so it is left out for a hop at any
                // origin other than the one the route named. Once left out it
                // stays out for the rest of the attempt, a redirect back to the
                // named origin included: by the time that request is made the
                // other operator holds the credential already.
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
                self.discard(&key, response, reuse, drain_until).await;
                return Err(failure);
            }
            // A coded body holds bytes other than the ones the remote stores,
            // so the declared length says nothing about the object either: the
            // coding is refused before the cap is compared. A refusal that
            // names the coding is what a checksum mismatch cannot say. The
            // refusal is definitive, another attempt against the same
            // destination being answered the same way.
            if let Some(encoding) = declared_coding(response.headers()) {
                let url = url.to_string();
                self.discard(&key, response, reuse, drain_until).await;
                return Err(Failure::Fatal(Error::ContentEncoded { url, encoding }));
            }
            let validators = read_validators(response.headers());
            let content_length = content_length(response.headers());
            // The cap is the caller's bound on the object, so it is compared
            // against the response that carries it and against no redirect on
            // the way there.
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
                key,
                reuse,
                permit: None,
                done: false,
                failed: None,
                deadline: rt::Deadline::new(progress_timeout),
                waiting: false,
            }));
        }
    }

    /// Take or open a connection for one hop and send the request over it.
    ///
    /// What comes back is the response, the protocol that carried it, and the
    /// HTTP/1.1 connection the response holds, which returns to the pool once
    /// the response has been read to its end.
    async fn send(
        &self,
        hop: &Destination,
        key: &PoolKey,
        via: Via<'_>,
        request: &FetchRequest<'_>,
        headers: &[(HeaderName, HeaderValue)],
    ) -> std::result::Result<(Response<Incoming>, Protocol, Option<H1Sender>), Failure> {
        let url = hop.url();
        let origin = &key.origin;
        let connect_timeout = self.inner.connect_timeout;
        let progress_timeout = self.inner.progress_timeout;
        let sender = match self.inner.take_conn(key) {
            Some(sender) => sender,
            None => {
                // Opening a connection is by far the largest state a fetch
                // holds -- the TLS handshake and hyper's own -- and it is the
                // rarest, taken only when the pool has nothing for this origin.
                // Boxing it keeps that state off the fetch future, which every
                // caller nests inside its own: a fetch is ten times smaller
                // this way, and a pull that wraps several helpers around one
                // multiplies what it saves.
                let opened = within(connect_timeout, Box::pin(self.connect(key, via))).await;
                match opened {
                    Some(result) => result?,
                    None => {
                        // The window covers the connect to whichever endpoint
                        // the hop is opened to, so a proxied hop names the
                        // proxy: the origin behind it is reached over that
                        // connection and is contacted by nothing until it is
                        // open.
                        return Err(Failure::Retry(Error::Fetch(match via {
                            Via::Direct => format!(
                                "connect to {}:{} timed out after {connect_timeout:?}",
                                origin.host, origin.port
                            ),
                            Via::Absolute(proxy) | Via::Tunnel(proxy) => format!(
                                "connect to the proxy {} timed out after {connect_timeout:?}",
                                proxy.named
                            ),
                        })));
                    }
                }
            }
        };
        match sender {
            Sender::H1(mut sender) => {
                let http_request = self
                    .build_request(hop, request, headers, Protocol::Http11, via)
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
                Ok((response, Protocol::Http11, Some(sender)))
            }
            Sender::H2(mut sender) => {
                let http_request = self
                    .build_request(hop, request, headers, Protocol::Http2, via)
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

    /// Whether a connection to `hop` presents the configured client
    /// certificate: one is configured, the hop is the origin the route named,
    /// and that origin is TLS, a cleartext connection presenting no
    /// certificate at all. With none configured this is false everywhere, so
    /// the pool holds one entry per origin.
    fn presents_identity(&self, hop: &Origin, named: &Origin) -> bool {
        self.inner.client_identity && hop.tls && hop == named
    }

    /// End an attempt whose response is not the one the caller asked for.
    ///
    /// A response that declares a body of at most [`DRAIN_LIMIT`] bytes is read
    /// to the end, which frees its HTTP/1.1 connection for the next request; a
    /// larger declared body, or one with no declared length, is dropped, closing
    /// the connection, since the rest of the response is still in flight. An
    /// HTTP/2 stream carries no such cost -- its connection stays pooled
    /// whatever the stream did -- so there is nothing to drain.
    ///
    /// `drain_until` bounds every read one attempt makes here: it is one
    /// progress window from the moment the attempt began, and they share it. A
    /// read that reaches the end of that window drops what is left of the
    /// response, and one that finds the budget spent drops the connection
    /// without reading.
    async fn discard(
        &self,
        key: &PoolKey,
        response: Response<Incoming>,
        reuse: Option<H1Sender>,
        drain_until: Instant,
    ) {
        let Some(sender) = reuse else { return };
        if content_length(response.headers()).is_none_or(|length| length > DRAIN_LIMIT) {
            return;
        }
        let budget = drain_until.saturating_duration_since(Instant::now());
        if budget.is_zero() {
            return;
        }
        let mut body = response.into_body();
        // The drain runs under what is left of the attempt's window, so a peer
        // that declares a short body and then stops sending costs the attempt
        // no more than a stalled body would, whatever the hop count.
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

    /// Assemble the GET for `request` against `destination`, sending `headers`.
    ///
    /// An HTTP/1.1 request carries the origin-form target and a `Host` header,
    /// which is what an origin server expects; the absolute form belongs to
    /// proxy requests, and a plain static-file server answers 404 to it. An
    /// HTTP/2 request carries the absolute URL, from which hyper fills the
    /// `:scheme` and `:authority` pseudo-headers.
    ///
    /// A request that travels to a cleartext origin over a proxy connection
    /// carries the absolute form, which is what tells the proxy where to send
    /// it, and the `Host` header of the origin rather than of the proxy. It
    /// carries the proxy's own credential as well, where the merged headers
    /// hold none of that name: a `Proxy-Authorization` header the caller set
    /// states what the proxy is to be sent, and two values of one name would
    /// give the proxy two answers to one question. A `CONNECT` tunnel carries
    /// the fetcher's proxy credential on the `CONNECT` alone, so the request
    /// that travels over the tunnel is the one a direct connection sends.
    fn build_request(
        &self,
        destination: &Destination,
        request: &FetchRequest<'_>,
        headers: &[(HeaderName, HeaderValue)],
        protocol: Protocol,
        via: Via<'_>,
    ) -> Result<Request<NoBody>> {
        let absolute = protocol == Protocol::Http2 || matches!(via, Via::Absolute(_));
        let url = if absolute {
            destination.url()
        } else {
            destination.target()
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
        if let Via::Absolute(proxy) = via
            && let Some(credential) = &proxy.credential
            && !headers
                .iter()
                .any(|(name, _)| *name == hyper::header::PROXY_AUTHORIZATION)
        {
            builder = builder.header(hyper::header::PROXY_AUTHORIZATION, credential);
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

    /// Open a connection for `key`, negotiating the protocol over ALPN when
    /// the origin is TLS.
    ///
    /// The key states which client configuration the handshake runs under, so a
    /// connection that presents the client certificate and one that presents
    /// none are two pool entries and neither is handed to the other's hop.
    ///
    /// `via` states what the connection reaches. A proxied cleartext origin is
    /// keyed by the proxy endpoint already, so the socket goes where the key
    /// names it and the requests that travel over it carry the absolute form. A
    /// tunneled TLS origin is keyed by the origin, so the socket goes to the
    /// proxy and the `CONNECT` exchange is what the handshake then runs over.
    ///
    /// A failure here says whether another attempt may find something else. A
    /// proxy that refuses the tunnel with 407 refuses the credential the
    /// fetcher holds, which no round of retries changes; every other failure is
    /// retryable.
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
            // Cleartext HTTP/2 needs prior knowledge or an upgrade; neither is
            // used, so a cleartext origin speaks HTTP/1.1, over a proxy as
            // over a direct connection.
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

    /// Ask `proxy` to tunnel to `origin` and hand back the socket the tunnel
    /// runs over.
    ///
    /// The `CONNECT` goes over hyper's HTTP/1.1 client, which is what reads the
    /// answer and hands the socket back: a 2xx to a `CONNECT` is an upgrade,
    /// and the upgraded I/O is the stream the handshake was opened with. The
    /// connection future is what delivers it, so it is driven in its own task
    /// and ends with the upgrade.
    ///
    /// Bytes buffered behind the response fail the connect. Nothing follows a
    /// `CONNECT` response before the client speaks, so a proxy that sent
    /// something is not speaking the protocol the tunnel needs, and the TLS
    /// handshake would read the stream from after those bytes.
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
        let request = builder.body(NoBody).map_err(|e| {
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
        // The upgrade is delivered by the connection future, so it runs beside
        // the request. It ends with the upgrade, and the task with it.
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
            // A 407 refuses the credential the fetcher holds, or the absence of
            // one, which every round of retries would offer again.
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

    /// Complete an HTTP/1.1 handshake and drive the connection in its own task.
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
    /// A pooled connection for `key`, if one is still usable.
    fn take_conn(&self, key: &PoolKey) -> Option<Sender> {
        let mut pool = self.pool.lock().expect("fetcher pool mutex");
        let entry = pool.get_mut(key)?;
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
    ///
    /// The entry an origin already has is reached by reference. Building one
    /// takes a key of the pool's own, and the host string it holds is an
    /// allocation the warm path of every object fetch would otherwise pay.
    fn put_h1(&self, key: &PoolKey, sender: H1Sender) {
        if sender.is_closed() {
            return;
        }
        let mut pool = self.pool.lock().expect("fetcher pool mutex");
        if let Some(entry) = pool.get_mut(key) {
            entry.h1.push(sender);
            return;
        }
        pool.entry(key.clone()).or_default().h1.push(sender);
    }

    /// Record the origin's HTTP/2 connection, keeping a usable one already
    /// pooled.
    ///
    /// Two concurrent connects to one origin each complete a handshake. The
    /// connection that loses the race would otherwise replace a pooled entry
    /// other requests are already multiplexing over, and stay alive unreferenced
    /// until its own senders drop; instead it serves only the request that
    /// opened it and closes with that request.
    ///
    /// The entry an origin already has is reached by reference, the way
    /// [`Inner::put_h1`] reaches it.
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
    /// The pool entry the connection carrying this body came from, which is
    /// where it goes back.
    key: PoolKey,
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
                        me.inner.put_h1(&me.key, sender);
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

/// Resolve the proxy configuration into the state a fetch reads.
///
/// Every form is resolved once, here, so a fetch reads no environment and
/// parses no URL. A proxy URL the fetcher cannot connect through fails the
/// constructor, whether the options named it or the environment did: a value
/// read under a meaning of the port's own would send the request somewhere the
/// caller did not name.
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

/// The proxy variables the process environment holds.
///
/// An empty value counts as unset, so it is left out here and the lookup below
/// has one rule to apply.
fn environment() -> Vec<(String, String)> {
    PROXY_VARIABLES
        .iter()
        .filter_map(|name| {
            let value = std::env::var(name).ok()?;
            (!value.is_empty()).then(|| ((*name).to_owned(), value))
        })
        .collect()
}

/// Resolve the variable forms of [`Proxy`] into the state a fetch reads.
fn resolve_variables(variables: &[(String, String)]) -> Result<Proxies> {
    let all = variable(variables, "all_proxy", Some("ALL_PROXY"));
    let http = variable(variables, "http_proxy", None);
    let https = variable(variables, "https_proxy", Some("HTTPS_PROXY"));
    // Every variable holding a value is parsed, and the selection below is made
    // from what parsed: a proxy url the fetcher cannot connect through is
    // refused where the caller named it, and `all_proxy` beside both
    // scheme-specific variables is named and read by no fetch. One URL serving
    // both schemes is parsed once and held as one endpoint, so the pool key of
    // a proxy connection is the same whichever variable named it.
    let mut endpoints: Vec<(&str, Arc<ProxyEndpoint>)> = Vec::new();
    for url in [all, http, https].into_iter().flatten() {
        if !endpoints.iter().any(|(named, _)| *named == url) {
            endpoints.push((url, Arc::new(parse_proxy(url)?)));
        }
    }
    let parsed = |url: Option<&str>| {
        url.and_then(|url| endpoints.iter().find(|(named, _)| *named == url))
            .map(|(_, endpoint)| endpoint.clone())
    };
    let (http, https) = (parsed(http.or(all)), parsed(https.or(all)));
    let mut exempt_all = false;
    let mut exempt = Vec::new();
    for entry in variable(variables, "no_proxy", Some("NO_PROXY"))
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

/// The value of one proxy variable: the lower-case name first, then the
/// upper-case name where one is read.
///
/// An empty value counts as unset, and among two entries of one name the first
/// with a value is the one read.
fn variable<'a>(
    variables: &'a [(String, String)],
    lower: &str,
    upper: Option<&str>,
) -> Option<&'a str> {
    let held = |name: &str| {
        variables
            .iter()
            .find(|(held, value)| held == name && !value.is_empty())
            .map(|(_, value)| value.as_str())
    };
    held(lower).or_else(|| upper.and_then(held))
}

/// Read one `no_proxy` entry, or `None` where it names no host.
///
/// An IPv6 literal carries colons of its own, so a port is read off the
/// bracketed form and off an entry holding one colon; an unbracketed entry with
/// more colons than that is an address rather than a host and a port. A port
/// text that is not a number from 0 to 65535 leaves the whole entry as one host
/// text, which no origin host holds, so such an entry exempts nothing.
///
/// An entry left with no host once its leading `.` and its port are taken off
/// -- `.` and `:8080` are the two spellings of it -- exempts nothing and is
/// dropped here: an empty host text is the suffix of every host, and keeping it
/// would exempt every origin.
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
    // One leading `.` states the suffix match the comparison makes anyway, so
    // it is stripped and the two spellings of one entry are one entry. A second
    // `.` is part of the host text the entry names, which no origin host holds.
    let named = |host: &str| host.strip_prefix('.').unwrap_or(host).to_ascii_lowercase();
    let (host, port) = match port.map(str::parse::<u16>) {
        Some(Ok(port)) => (named(host), Some(port)),
        Some(Err(_)) => (named(entry), None),
        None => (named(host), None),
    };
    (!host.is_empty()).then_some(Exemption { host, port })
}

/// Read a proxy URL into the endpoint a connection is opened to.
///
/// A proxy is asked for an origin by the request that travels to it, so the URL
/// names an endpoint and nothing else: a path other than `/`, a query, or a
/// fragment states something the request has no place to carry, and it is
/// refused rather than dropped. The scheme is `http`, which is the one scheme a
/// proxy connection is opened with here.
///
/// Userinfo is the proxy's credential. It is percent-decoded and sent as
/// `Proxy-Authorization: Basic`, which is what a proxy that works under another
/// client expects. Every refusal names the URL with the userinfo left out, a
/// userinfo holding a password.
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
    if let Some(query) = uri.query() {
        return Err(refused(&format!(
            "a proxy url carries no query string, and this one carries ?{query}"
        )));
    }
    if !matches!(uri.path(), "" | "/") {
        return Err(refused(&format!(
            "a proxy url carries no path, and this one carries {}",
            uri.path()
        )));
    }
    // `Uri::host` holds an IPv6 literal in brackets, which belong to the
    // authority and not to the address: a connect resolves the bracketed form
    // to nothing.
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
    // `Uri` accepts an authority whose port it cannot read and reports no port
    // for it, so the port text is read from the authority and refused rather
    // than served from the default.
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

/// The `Proxy-Authorization` value one proxy URL's userinfo builds.
///
/// The two fields are percent-decoded, since that is the encoding a URL states
/// a `:` or an `@` in a credential under. `None` says the userinfo holds
/// something else: an escape that is not two hexadecimal digits, or a field
/// whose bytes are not text.
fn proxy_credential(userinfo: &str) -> Option<HeaderValue> {
    let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let field = |text: &str| String::from_utf8(percent_decode(text)?).ok();
    basic_auth_value(&BasicAuth {
        user: field(user)?,
        password: field(password)?,
    })
    .ok()
}

/// Percent-decode one field of a proxy URL's userinfo.
///
/// `%` starts an escape of exactly two hexadecimal digits. `None` says the
/// field holds one that is not, which is refused rather than sent as the bytes
/// the caller wrote: a credential the proxy reads differently from the one the
/// caller meant answers 407 and names nothing.
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

/// The `host:port` a `CONNECT` names its target by.
///
/// The port is always written, whatever the scheme's default is: what the proxy
/// opens is a TCP connection, which names a port and reads no scheme. An IPv6
/// literal keeps the brackets that separate the address from the port.
fn connect_authority(origin: &Origin) -> String {
    if origin.host.contains(':') {
        format!("[{}]:{}", origin.host, origin.port)
    } else {
        format!("{}:{}", origin.host, origin.port)
    }
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
            // A password holding a `?` or a `#` ends the authority before the
            // `@`, so the userinfo check above passes and this message is one a
            // URL carrying userinfo still reaches.
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

/// How a message names a URL whose authority the parse has not reached, which
/// is a URL whose userinfo has not been refused yet. Userinfo holds a password,
/// so the part of the authority before the `@` is left out.
///
/// The password arrives as the caller wrote it, and one holding a `/`, a `?`,
/// or a `#` puts the end of the authority after the `@` rather than before it:
/// where the authority ends is readable once the userinfo is found and not
/// before. So an `@` anywhere past the scheme states that there is a userinfo,
/// and everything up to the last one is left out, which keeps a password of
/// any spelling out of the message. A URL carrying an `@` in its path and no
/// userinfo costs the message its host that way, which is what a redaction
/// that reads no well-formed authority costs.
fn without_userinfo(url: &str) -> Cow<'_, str> {
    let start = url.find("://").map_or(0, |at| at + 3);
    match url[start..].rfind('@') {
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

/// Whether a response at this status sends the attempt on to another URL.
fn is_redirect(status: StatusCode) -> bool {
    REDIRECTS.contains(&status)
}

/// The URL a `Location` header names, resolved against `from`, the URL of the
/// response that carried it.
///
/// A `Location` reads as an absolute URL, as one relative to the response's
/// own URL, or as a scheme-relative one, and the resolution is the one the URL
/// specification states. A fragment the result carries is dropped: a fragment
/// names a part of a representation and reaches no request, and the HTTP
/// specification has a redirect drop it rather than refuse it.
///
/// The resolution normalizes what it produces, where a [`Target::Url`] reaches
/// the wire as the caller wrote it:
/// a dot segment is resolved away (`/deep/../root` becomes `/root`, `/./p`
/// becomes `/p`), a backslash reads as a path separator (`/a\b` becomes
/// `/a/b`), a tab and a newline are removed, a character a path or a query may
/// not carry is percent-encoded (`?q='x'` becomes `?q=%27x%27`), and an IPv4 or
/// an IPv6 host is canonicalized (`2130706433` and `0177.0.0.1` both become
/// `127.0.0.1`). A request target the caller signed reaches the server
/// re-encoded where its signature covers one of those characters, which the
/// server reads as a target of its own and answers 403 to.
///
/// `None` says the header holds no URL a request can be sent to, which covers
/// a value that is not text, an empty value, and one the resolution cannot
/// read. A value the resolution reads as the URL of the response itself -- a
/// fragment alone, `#frag` -- is a hop of its own and spends one of the hops
/// the attempt is allowed.
fn resolve_location(from: &str, location: &HeaderValue) -> Option<String> {
    let location = location.to_str().ok()?;
    // An empty value resolves to the URL of the response that carried it, so
    // the attempt would follow the hop it just made.
    if location.is_empty() {
        return None;
    }
    let mut resolved = url::Url::parse(from).ok()?.join(location).ok()?;
    resolved.set_fragment(None);
    Some(resolved.into())
}

/// Read the URL a redirect named into the destination of the next hop.
///
/// Two hops are refused, and both refusals name the URL that redirected and
/// the URL it named: a scheme other than `http` or `https`, which the fetcher
/// serves nothing under, and a hop from `https` to `http`, which would put a
/// request the caller made over TLS on the wire in the clear. A hop from
/// `http` to `https` is followed.
///
/// What arrives is the resolved URL, normalized by [`resolve_location`]. This
/// parse reads it the way it reads a [`Target::Url`], so userinfo and a port
/// the URL parser cannot read are refused by that parse, under the message it
/// writes. A userinfo holds a password, so the two refusals made here name the
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

/// What a fetch of a TLS origin is told on a fetcher that holds no trust
/// anchors, whether the route named that origin or a redirect hop did.
fn no_trust_anchors(origin: &str) -> Error {
    Error::Fetch(format!(
        "the certificate of the tls origin {origin} has nothing to verify against: the \
         fetcher holds no trust anchors, so set TlsOptions::roots"
    ))
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
            let mut options = direct_options("http://example.com");
            options.headers = vec![("not a header".into(), "v".into())];
            let err = Fetcher::new(options).await.unwrap_err();
            assert!(err.to_string().contains("invalid header name"), "{err}");

            // The host header comes from the url the request is sent to, so a
            // caller-supplied one would collide with it.
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
            let fetcher = Fetcher::new(direct_options("http://example.com/r"))
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
                    Via::Direct,
                )
                .unwrap();
            assert_eq!(request.uri(), "/r/refs/heads/a");
        });
    }

    /// A `Location` is resolved against the URL of the response that carried
    /// it, so it reads as an absolute URL, a relative one, or a
    /// scheme-relative one. A fragment names a part of a representation and
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
            // A fragment is dropped rather than refused.
            ("/other/path#frag", "https://example.com/other/path"),
            ("http://other.example/p#frag", "http://other.example/p"),
            // A scheme the fetcher serves nothing under resolves here; the hop
            // check is what refuses it.
            ("file:///srv/repo", "file:///srv/repo"),
        ] {
            assert_eq!(resolved(value).as_deref(), Some(hop), "{value}");
        }

        // A value the resolution cannot read holds no URL a request can be
        // sent to, and neither does an empty one, which resolves to the URL of
        // the response itself.
        assert_eq!(resolved("http://"), None);
        assert_eq!(resolved(""), None);

        // A fragment alone resolves to the URL of the response itself, which is
        // a hop of its own.
        assert_eq!(
            resolved("#frag").as_deref(),
            Some("https://example.com/repo/objects/summary?x=1")
        );

        // The resolution normalizes what it produces: a dot segment is resolved
        // away, a backslash reads as a path separator, a tab is removed, a
        // character a query may not carry is percent-encoded, and an IPv4 host
        // is canonicalized.
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

    /// A hop is read the way a URL target is, and two hops are refused with
    /// both URLs named: a scheme the fetcher serves nothing under, and a hop
    /// from `https` to `http`. A hop from `http` to `https` is followed.
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

        // A scheme the fetcher serves nothing under, named the same way.
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

    /// Which statuses send an attempt on to another URL. Every request is a
    /// GET, so the ones that part over the method are one case.
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
    /// A test that is not about the proxy states this, so the proxy variables
    /// the host running the suite holds decide nothing: the default form reads
    /// them, and a fetcher built under one would travel to a proxy no test
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

        // A password holding a `/`, a `?`, or a `#` puts the end of the
        // authority behind the `@`, and the userinfo is left out all the same.
        for password in ["pa#ss", "pa?ss", "p/ss"] {
            let url = format!("https://alice:{password}@example.com/p");
            let message = parse_url(&url).unwrap_err().to_string();
            assert!(!message.contains(password), "{password}: {message}");
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
            ..direct_options("https://example.com")
        };
        let rendered = format!("{options:?}");
        assert!(!rendered.contains("sup3rs3cret"), "{rendered}");
    }

    /// The origin of one absolute URL, which is what a proxy decision reads.
    fn origin_of(url: &str) -> Origin {
        parse_url(url).unwrap().origin
    }

    /// How a hop at `url` is reached: the proxy it names, and whether the
    /// request travels in absolute form or through a tunnel.
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

    /// A proxy is named by an endpoint and nothing else: a path, a query, a
    /// fragment, or a scheme other than `http` states something a proxy
    /// connection has no place to carry, and every one of them is refused at
    /// construction.
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
            // Surrounding space is what an environment variable carries; the
            // endpoint is read without it.
            (
                " http://proxy.example:3128 ",
                "proxy.example",
                3128,
                "http://proxy.example:3128",
            ),
            // An IPv6 literal keeps its brackets in the authority and is held
            // without them, the connect resolving the bracketed form to nothing.
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

        // Userinfo is the proxy's credential, percent-decoding included:
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

    /// `http_proxy` serves cleartext origins and `https_proxy` serves TLS ones,
    /// `all_proxy` serves either where the scheme-specific variable is unset,
    /// lower case wins over upper case, an empty value counts as unset, and
    /// `HTTP_PROXY` is read by nothing.
    #[test]
    fn the_proxy_variables_are_read_per_scheme() {
        let cleartext = "http://origin.example/summary";
        let tls = "https://origin.example/summary";
        let absolute = |named: &str| Some((named.to_owned(), false));
        let tunnel = |named: &str| Some((named.to_owned(), true));

        // Each scheme is served by its own variable, and the request form
        // follows the origin: absolute over a proxy connection for cleartext, a
        // tunnel for TLS.
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

        // The upper-case name is read for every variable but `http_proxy`: a
        // CGI gateway hands a request header called `Proxy` on under that name.
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

        // Lower case wins over upper case, and an empty value counts as unset,
        // which leaves the upper-case name the one that is read.
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
        // A variable the selection passes over is parsed too: an `all_proxy`
        // beside both scheme-specific variables is read by no fetch, and one
        // holding a value the fetcher cannot connect through fails the
        // resolution where the caller named it.
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
        // A host under a listed domain, whichever of the two spellings the
        // entry uses, and a name that merely ends with the same letters.
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
        // An IP literal matches that text and nothing else, so a name is not
        // exempted by the address it resolves to and an address is not exempted
        // by a name.
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
        // An entry left naming no host exempts nothing, a host written with a
        // trailing `.` included.
        for entry in [".", ":8080", ".:8080"] {
            assert!(proxied(entry, "http://a.example./p"), "{entry}");
            assert!(proxied(entry, "http://a.example:8080/p"), "{entry}");
        }
        // One leading `.` is stripped, so a second belongs to the host text the
        // entry names.
        assert!(proxied("..example.com", "http://a.example.com/p"));
        // `*` as a whole entry is the one wildcard the list reads: every other
        // form holding one is a host text.
        assert!(proxied("*.example.com", "http://a.example.com/p"));
        assert!(proxied("*.example.com", "http://example.com/p"));
    }

    /// A proxy URL's userinfo holds a password, so it reaches neither a
    /// rendering of the options nor a refusal the constructor writes.
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

        // Every refusal, whichever part of the URL the parse was reading.
        for tail in ["/squid", "/?upstream=1", "/#frag", ":99999"] {
            let err = parse_proxy(&url(tail)).unwrap_err();
            let message = err.to_string();
            assert!(!message.contains("sup3rs3cret"), "{tail}: {message}");
        }
        let err = parse_proxy("socks5://alice:sup3rs3cret@proxy.example:1080").unwrap_err();
        assert!(!err.to_string().contains("sup3rs3cret"), "{err}");

        // A password holding a `/`, a `?`, or a `#` puts the end of the
        // authority behind the `@`, and the userinfo is left out all the same.
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

    /// A `CONNECT` names its target by host and port, the port always written:
    /// what the proxy opens is a TCP connection, which reads no scheme.
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
    /// origin's own `Host` header, and the proxy's credential where the merged
    /// headers hold none of that name. A direct request and the request that
    /// travels over a tunnel carry the origin form and nothing of the proxy's.
    #[test]
    fn a_proxied_cleartext_request_carries_the_absolute_form() {
        rt::block_on(async {
            let fetcher = Fetcher::new(FetcherOptions {
                proxy: Proxy::Url("http://alice:s3cret@proxy.example:3128".into()),
                ..tls_options("http://origin.example/r")
            })
            .await
            .unwrap();
            let destination = fetcher.inner.mirrors[0].destination("refs/heads/a");
            let request = FetchRequest::path("refs/heads/a");
            let built = |via: Via<'_>, headers: &[(HeaderName, HeaderValue)]| {
                fetcher
                    .build_request(&destination, &request, headers, Protocol::Http11, via)
                    .unwrap()
            };
            let proxy_credential = |request: &Request<NoBody>| {
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

            // A `Proxy-Authorization` header the caller set states what the
            // proxy is to be sent, so the fetcher's own credential is left out
            // rather than joined to it.
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

            // A direct hop, and the request that travels over a tunnel, carry
            // the origin form and nothing of the proxy's.
            for via in [Via::Direct, Via::Tunnel(proxy)] {
                let direct = built(via, &fetcher.inner.headers);
                assert_eq!(direct.uri(), "/r/refs/heads/a");
                assert_eq!(proxy_credential(&direct), None);
            }
        });
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
                ..direct_options("http://example.com")
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

        // Two entries of one name both reach the wire, the entry the fetcher
        // sets having been replaced by the first of them.
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
        // A name the fetcher sets nothing under keeps both entries as well.
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
            let mut fetcher = Fetcher::new(direct_options("http://cleartext.example/repo"))
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

    /// A redirect names an origin of the server's choosing, so a hop onto a TLS
    /// origin meets the refusal a route naming one meets: the fetcher holds
    /// nothing to verify the certificate against, and the handshake would fail
    /// retryably under a message about the peer, spending every round and every
    /// backoff on it. The flag is set by hand here for the reason the check
    /// above states.
    ///
    /// The two peers are raw sockets: one answers a redirect to the other, and
    /// the other reports how many connections reached it.
    #[test]
    fn a_redirect_to_a_tls_origin_needs_a_trust_anchor() {
        use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
        use std::sync::atomic::{AtomicUsize, Ordering};

        rt::block_on(async {
            // The origin the redirect names. Nothing connects to it, which is
            // what the count reports.
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
            // run for over five seconds, so a refusal that ends the attempt is
            // what resolves inside this window.
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
}
