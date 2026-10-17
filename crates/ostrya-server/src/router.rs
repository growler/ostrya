//! The HTTP mapping of the archive view, the identification of the client of
//! a read, and the routing to the receive endpoint and to the ref listing.

use std::sync::Arc;

use hyper::body::{Bytes, Incoming};
use hyper::header::{ALLOW, CACHE_CONTROL, CONTENT_LENGTH, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use ostrya::access::ReadAccess;
use ostrya::{ArchiveAnswer, ArchiveHead, ArchiveView, Repo};

use crate::auth::{GroupAuth, peer_of};
use crate::body::{ReceiveBody, ServeBody};
use crate::endpoint::ReceiveEndpoint;
use crate::event::StaleSummaries;
use crate::receive_auth::Refusal;
use crate::refs::Listings;
use crate::stall::Stall;
use crate::{receive, refs};

/// How a server identifies the client of a request.
pub(crate) enum Clients {
    /// The client groups of the repository identify the client of each
    /// request. The receive endpoint serves the pushes of the groups.
    Groups(Arc<ReceiveEndpoint<GroupAuth>>),
    /// The server identifies no client and has no receive endpoint. Each
    /// read has these rights.
    Anonymous(ReadAccess),
}

impl Clients {
    /// Returns the receive endpoint, or `None`.
    pub(crate) fn endpoint(&self) -> Option<&Arc<ReceiveEndpoint<GroupAuth>>> {
        match self {
            Clients::Groups(endpoint) => Some(endpoint),
            Clients::Anonymous(_) => None,
        }
    }

    /// Returns the read rights of the client of `req`, or the refusal of the
    /// request.
    pub(crate) fn read_access<B>(&self, req: &Request<B>) -> Result<ReadAccess, Refusal> {
        match self {
            Clients::Groups(endpoint) => endpoint
                .auth()
                .identify_read(req.headers(), &peer_of(req.extensions())),
            Clients::Anonymous(access) => Ok(access.clone()),
        }
    }
}

/// Returns the response to a refused identification: the status and the
/// headers of `refusal`, and an empty body. The server does not send the
/// message of the refusal.
pub(crate) fn refused(refusal: Refusal) -> Response<ServeBody> {
    let mut response = empty(refusal.status);
    for (name, value) in refusal.headers {
        response.headers_mut().append(name, value);
    }
    response
}

/// Returns the response to one request. The function records a stream body
/// in `stall`, the deadline of its connection. `listings` holds the ref
/// listings in flight in the server. `stale` records the stale summaries
/// that the server reported.
///
/// With a receive endpoint, a request under its raw path prefix with a
/// method other than `GET` and `HEAD` goes to the endpoint. A `GET` or a
/// `HEAD` there goes to the view, which finds nothing. A request of the raw
/// path [`refs::PATH`] goes to the ref listing of `repo`, with each method.
/// Each other request goes to the view.
///
/// A request to the view gets 405 for a method other than `GET` and `HEAD`.
/// Then `clients` identifies the client, and a refusal gets its response.
/// Then a path that does not decode gets 404. The view answers with the read
/// rights of the client. A stale summary gets 404, and `stale` reports it.
/// A 200 and a 404 of `summary` and `summary.sig` carry
/// `Cache-Control: private`, because the body depends on the client.
pub(crate) async fn handle(
    view: &ArchiveView,
    repo: &Repo,
    listings: &Listings,
    stale: &StaleSummaries,
    clients: &Clients,
    stall: &Arc<Stall>,
    req: Request<Incoming>,
) -> Response<ServeBody> {
    if let Some(receive) = clients.endpoint() {
        let read = matches!(*req.method(), Method::GET | Method::HEAD);
        if !read && req.uri().path().starts_with(receive::PREFIX) {
            return receive.handle(req).await.map(ReceiveBody::into_serve);
        }
    }
    if req.uri().path() == refs::PATH {
        let identify = || clients.read_access(&req);
        return refs::handle(
            repo,
            listings,
            req.method(),
            req.uri().query(),
            stall,
            identify,
        )
        .await;
    }
    let head = match *req.method() {
        Method::GET => false,
        Method::HEAD => true,
        _ => {
            let mut response = empty(StatusCode::METHOD_NOT_ALLOWED);
            response
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
            return response;
        }
    };
    let access = match clients.read_access(&req) {
        Ok(access) => access,
        Err(refusal) => return refused(refusal),
    };
    let Some(path) = decode_path(req.uri().path()) else {
        return empty(StatusCode::NOT_FOUND);
    };
    let response = if head {
        let answer = view.head(&path, &access).await;
        if matches!(answer, Ok(ArchiveHead::StaleSummary)) {
            stale.report(access.item());
        }
        respond_head(answer)
    } else {
        let answer = view.get(&path, &access).await;
        if let Ok(ArchiveAnswer::StaleSummary { item }) = &answer {
            stale.report(item);
        }
        respond(answer, stall)
    };
    private_summary(&path, response)
}

/// Returns `response` with `Cache-Control: private` when `path` is
/// `summary` or `summary.sig` and the status is 200 or 404.
fn private_summary(path: &str, mut response: Response<ServeBody>) -> Response<ServeBody> {
    let summary = matches!(path, "summary" | "summary.sig");
    let status = response.status();
    if summary && (status == StatusCode::OK || status == StatusCode::NOT_FOUND) {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("private"));
    }
    response
}

/// Returns the response for an answer of the view to a `GET`. A not-found
/// and a refusal take one path, so their responses are the same bytes.
fn respond(answer: ostrya::Result<ArchiveAnswer>, stall: &Arc<Stall>) -> Response<ServeBody> {
    let (len, body) = match answer {
        Ok(ArchiveAnswer::Bytes(bytes)) => (
            Some(bytes.len() as u64),
            ServeBody::Full(Some(Bytes::from(bytes))),
        ),
        Ok(ArchiveAnswer::Stream { len, body }) => {
            (len, ServeBody::stream(body, len, stall.track()))
        }
        Ok(
            ArchiveAnswer::NotFound | ArchiveAnswer::Refused | ArchiveAnswer::StaleSummary { .. },
        ) => {
            return empty(StatusCode::NOT_FOUND);
        }
        Err(_) => return empty(StatusCode::INTERNAL_SERVER_ERROR),
    };
    with_length(Response::new(body), len)
}

/// Returns the response for an answer of the view to a `HEAD`. It has the
/// status and the `Content-Length` that a `GET` gives, and no body.
fn respond_head(answer: ostrya::Result<ArchiveHead>) -> Response<ServeBody> {
    match answer {
        Ok(ArchiveHead::Found { len }) => with_length(Response::new(ServeBody::Empty), len),
        Ok(ArchiveHead::NotFound | ArchiveHead::Refused | ArchiveHead::StaleSummary) => {
            empty(StatusCode::NOT_FOUND)
        }
        Err(_) => empty(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Returns `response` with a `Content-Length` of `len`. If `len` is `None`,
/// the response gets no `Content-Length`.
pub(crate) fn with_length(
    mut response: Response<ServeBody>,
    len: Option<u64>,
) -> Response<ServeBody> {
    if let Some(len) = len {
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from(len));
    }
    response
}

/// Returns a response of `status` with an empty body and a `Content-Length`
/// of 0.
pub(crate) fn empty(status: StatusCode) -> Response<ServeBody> {
    let mut response = Response::new(ServeBody::Empty);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from(0u64));
    response
}

/// Returns the repository path of a request path. It removes the leading `/`
/// and decodes the rest with [`percent_decode`]. If the path has no leading
/// `/`, it returns `None`.
fn decode_path(raw: &str) -> Option<String> {
    percent_decode(raw.strip_prefix('/')?)
}

/// Returns `raw` with each percent escape decoded. An escape takes hex digits
/// in either case. Each other byte, `+` included, stays as it is. If `raw`
/// has a bad escape, or if the result holds a NUL or bytes that are not
/// UTF-8, the function returns `None`.
pub(crate) fn percent_decode(raw: &str) -> Option<String> {
    let raw = raw.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            let hi = hex_digit(*raw.get(i + 1)?)?;
            let lo = hex_digit(*raw.get(i + 2)?)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    if out.contains(&0) {
        return None;
    }
    String::from_utf8(out).ok()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyper::body::Body;
    use ostrya_rt::block_on;

    use super::*;
    use crate::body::tests::frames;

    fn stall() -> Arc<Stall> {
        Stall::new(Duration::from_secs(3600))
    }

    #[test]
    fn paths_are_percent_decoded() {
        assert_eq!(decode_path("/config").as_deref(), Some("config"));
        assert_eq!(
            decode_path("/refs%2Fheads/a%20b").as_deref(),
            Some("refs/heads/a b")
        );
        assert_eq!(decode_path("/").as_deref(), Some(""));
        for bad in ["config", "*", "/a%2", "/a%zz", "/a%00b", "/%ff"] {
            assert_eq!(decode_path(bad), None, "{bad}");
        }
        assert_eq!(percent_decode("a%2fb+c").as_deref(), Some("a/b+c"));
        assert_eq!(percent_decode("").as_deref(), Some(""));
    }

    /// A `HEAD` keeps the length that a `GET` sends and has no body. A refusal
    /// and a not-found give one response, and an error gives 500.
    #[test]
    fn a_head_has_the_length_and_no_body() {
        for len in [Some(42), None] {
            let response = respond_head(Ok(ArchiveHead::Found { len }));
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(CONTENT_LENGTH),
                len.map(HeaderValue::from).as_ref()
            );
            let body = response.into_body();
            assert!(body.is_end_stream());
            assert!(block_on(frames(body)).unwrap().is_empty());
        }
        let parts = |answer| {
            let (parts, _) = respond_head(answer).into_parts();
            (parts.status, format!("{:?}", parts.headers))
        };
        assert_eq!(
            parts(Ok(ArchiveHead::Refused)),
            parts(Ok(ArchiveHead::NotFound))
        );
        assert_eq!(parts(Ok(ArchiveHead::NotFound)).0, StatusCode::NOT_FOUND);
        assert_eq!(
            parts(Err(ostrya::Error::InvalidFormat("x".into()))).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// A refusal and a not-found give the same response.
    #[test]
    fn a_refusal_and_a_not_found_are_one_answer() {
        let parts = |answer| {
            let response = respond(Ok(answer), &stall());
            let (parts, body) = response.into_parts();
            (
                parts.status,
                format!("{:?}", parts.headers),
                block_on(frames(body)).unwrap(),
            )
        };
        let refused = parts(ArchiveAnswer::Refused);
        assert_eq!(refused, parts(ArchiveAnswer::NotFound));
        assert_eq!(refused.0, StatusCode::NOT_FOUND);
        assert!(refused.2.is_empty());
        let error = respond(Err(ostrya::Error::InvalidFormat("x".into())), &stall());
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn bytes_carry_their_length() {
        let response = respond(Ok(ArchiveAnswer::Bytes(b"abc".to_vec())), &stall());
        assert_eq!(
            response.headers().get(CONTENT_LENGTH),
            Some(&HeaderValue::from(3u64))
        );
        assert_eq!(
            block_on(frames(response.into_body())).unwrap().concat(),
            b"abc"
        );
    }
}
