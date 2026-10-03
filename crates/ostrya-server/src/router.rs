//! The HTTP mapping of the archive view, and the routing to the receive
//! endpoint.

use std::sync::Arc;

use hyper::body::{Bytes, Incoming};
use hyper::header::{ALLOW, CONTENT_LENGTH, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use ostrya::{ArchiveAnswer, ArchiveHead, ArchiveView};

use crate::auth::Peer;
use crate::body::ServeBody;
use crate::receive::{self, Receive};
use crate::stall::Stall;

/// The response to one request. A stream body is recorded in `stall`, the
/// deadline of its connection.
///
/// With a receive endpoint, a request under its raw path prefix with a
/// method other than `GET` and `HEAD` goes to the endpoint. A `GET` or a
/// `HEAD` there goes to the view, which finds nothing.
pub(crate) async fn handle(
    view: &ArchiveView,
    receive: Option<&Receive>,
    peer: &Peer,
    stall: &Arc<Stall>,
    req: Request<Incoming>,
) -> Response<ServeBody> {
    if let Some(receive) = receive {
        let read = matches!(*req.method(), Method::GET | Method::HEAD);
        if !read && req.uri().path().starts_with(receive::PREFIX) {
            return receive.handle(peer, req).await;
        }
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
    let Some(path) = decode_path(req.uri().path()) else {
        return empty(StatusCode::NOT_FOUND);
    };
    if head {
        respond_head(view.head(&path).await)
    } else {
        respond(view.get(&path).await, stall)
    }
}

/// The response for an answer of the view to a `GET`. A not-found and a
/// refusal take one path, so their responses are the same bytes.
fn respond(answer: ostrya::Result<ArchiveAnswer>, stall: &Arc<Stall>) -> Response<ServeBody> {
    let (len, body) = match answer {
        Ok(ArchiveAnswer::Bytes(bytes)) => (
            Some(bytes.len() as u64),
            ServeBody::Full(Some(Bytes::from(bytes))),
        ),
        Ok(ArchiveAnswer::Stream { len, body }) => {
            (len, ServeBody::stream(body, len, stall.track()))
        }
        Ok(ArchiveAnswer::NotFound | ArchiveAnswer::Refused) => {
            return empty(StatusCode::NOT_FOUND);
        }
        Err(_) => return empty(StatusCode::INTERNAL_SERVER_ERROR),
    };
    with_length(Response::new(body), len)
}

/// The response for an answer of the view to a `HEAD`: the status and the
/// `Content-Length` a `GET` gives, and no body.
fn respond_head(answer: ostrya::Result<ArchiveHead>) -> Response<ServeBody> {
    match answer {
        Ok(ArchiveHead::Found { len }) => with_length(Response::new(ServeBody::Empty), len),
        Ok(ArchiveHead::NotFound | ArchiveHead::Refused) => empty(StatusCode::NOT_FOUND),
        Err(_) => empty(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// `response` with a `Content-Length` of `len`, when it is known.
fn with_length(mut response: Response<ServeBody>, len: Option<u64>) -> Response<ServeBody> {
    if let Some(len) = len {
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from(len));
    }
    response
}

/// A response of `status` with an empty body.
pub(crate) fn empty(status: StatusCode) -> Response<ServeBody> {
    let mut response = Response::new(ServeBody::Empty);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from(0u64));
    response
}

/// The repository path of a request path: the leading `/` taken off and the
/// percent escapes decoded. A path with no leading `/`, a bad escape, a NUL,
/// or bytes that are not UTF-8 gives `None`.
fn decode_path(raw: &str) -> Option<String> {
    let raw = raw.strip_prefix('/')?.as_bytes();
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
    }

    /// A `HEAD` keeps the length a `GET` sends and has no body. A refusal
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
