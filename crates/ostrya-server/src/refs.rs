//! The ref listing: the refs of the repository under a set of prefixes.
//!
//! A `GET` of [`PATH`] gets the bytes of [`Repo::build_ref_listing`], built
//! for each request. Each pair of the query is `prefix=VALUE`. The value is
//! percent-decoded, and [`Repo::build_ref_listing`] checks that it is a ref
//! name. No query is an empty prefix list, which takes all refs.
//!
//! A listing is whole in memory from its build until its body drops. The
//! server holds at most [`MAX_LISTINGS`] listings at the same time, over all
//! connections.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use futures_io::AsyncRead;
use futures_lite::io::Cursor;
use hyper::header::{ALLOW, HeaderValue, RETRY_AFTER};
use hyper::{Method, Response, StatusCode};
use ostrya::{MAX_REF_PREFIXES, Repo};

use crate::body::ServeBody;
use crate::router::{empty, percent_decode, with_length};
use crate::stall::Stall;

/// The path of the listing. No repository layout uses it.
pub(crate) const PATH: &str = "/_ostrya/refs/v1";

/// The key of each pair of the query.
const PREFIX_KEY: &str = "prefix";

/// The most listings that the server holds at the same time, over all
/// connections. A listing holds its slot from the start of its build until
/// its body drops.
const MAX_LISTINGS: usize = 4;

/// Returns the response to a request of [`PATH`] with `method` and the raw
/// `query`. The function records the body in `stall`, the deadline of its
/// connection. `listings` is the count of listings in flight in the server.
///
/// A method other than `GET` gets 405 with `Allow: GET`. A bad query gets
/// 400. If [`MAX_LISTINGS`] listings are in flight, the request gets 503 with
/// `Retry-After: 1`. These checks come in this order, before the build. A
/// prefix that is not a ref name gets 400. The listing is built in the
/// request task.
pub(crate) async fn handle(
    repo: &Repo,
    listings: &Arc<AtomicUsize>,
    method: &Method,
    query: Option<&str>,
    stall: &Arc<Stall>,
) -> Response<ServeBody> {
    let (prefixes, slot) = match admit(method, query, listings) {
        Ok(admitted) => admitted,
        Err(status) => return refusal(status),
    };
    let prefixes: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    match repo.build_ref_listing(&prefixes).await {
        Ok(bytes) => {
            let len = bytes.len() as u64;
            let reader = Box::new(Listing {
                bytes: Cursor::new(bytes),
                _slot: slot,
            });
            let body = ServeBody::stream(reader, Some(len), stall.track());
            with_length(Response::new(body), Some(len))
        }
        Err(e) => empty(status_of(&e)),
    }
}

/// Returns the prefixes of the request and a slot of `listings`, or the
/// status that refuses the request.
///
/// A method other than `GET` gets 405. Then a bad query gets 400. Then, if
/// no slot is free, the request gets 503.
fn admit(
    method: &Method,
    query: Option<&str>,
    listings: &Arc<AtomicUsize>,
) -> Result<(Vec<String>, Slot), StatusCode> {
    if method != Method::GET {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    let prefixes = parse_query(query).ok_or(StatusCode::BAD_REQUEST)?;
    let slot = Slot::take(listings).ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((prefixes, slot))
}

/// Returns the response of a refusal of [`admit`] with `status`, with an
/// empty body. A 405 carries `Allow: GET`, and a 503 carries
/// `Retry-After: 1`.
fn refusal(status: StatusCode) -> Response<ServeBody> {
    let mut response = empty(status);
    let header = match status {
        StatusCode::METHOD_NOT_ALLOWED => Some((ALLOW, "GET")),
        StatusCode::SERVICE_UNAVAILABLE => Some((RETRY_AFTER, "1")),
        _ => None,
    };
    if let Some((name, value)) = header {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}

/// One of the [`MAX_LISTINGS`] places of a listing in flight. The slot
/// leaves the count when it drops.
struct Slot {
    listings: Arc<AtomicUsize>,
}

impl Slot {
    /// Adds a slot to `listings` and returns it. If [`MAX_LISTINGS`] slots
    /// are in the count, the function returns `None` and changes nothing.
    fn take(listings: &Arc<AtomicUsize>) -> Option<Slot> {
        listings
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_LISTINGS).then_some(n + 1)
            })
            .ok()?;
        Some(Slot {
            listings: listings.clone(),
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.listings.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The bytes of a listing to send, with the slot that the listing holds.
/// The slot drops with the body.
struct Listing {
    bytes: Cursor<Vec<u8>>,
    _slot: Slot,
}

impl AsyncRead for Listing {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().bytes).poll_read(cx, buf)
    }
}

/// Returns the status of an error of the build. A bad prefix is 400, and
/// each other error is 500.
fn status_of(error: &ostrya::Error) -> StatusCode {
    match error {
        ostrya::Error::InvalidRefspec(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Returns the prefixes of the raw `query`, in the order of the query. No
/// query and an empty query give an empty list.
///
/// Each pair of the query is `prefix=VALUE`, and `&` separates two pairs.
/// The key must be the raw bytes `prefix`. The value is percent-decoded with
/// [`percent_decode`], so `+` stays `+`. A prefix given two times stays two
/// times. If a pair is empty, has no `=`, has another key, or has a value
/// that does not decode, the function returns `None`. If the query has more
/// than [`MAX_REF_PREFIXES`] pairs, the function returns `None` before it
/// decodes the pair after the limit. The function does not check the ref
/// name: [`Repo::build_ref_listing`] checks each prefix before it reads the
/// repository.
fn parse_query(query: Option<&str>) -> Option<Vec<String>> {
    let query = match query {
        None | Some("") => return Some(Vec::new()),
        Some(query) => query,
    };
    let mut prefixes = Vec::new();
    for pair in query.split('&') {
        if prefixes.len() == MAX_REF_PREFIXES {
            return None;
        }
        let (key, value) = pair.split_once('=')?;
        if key != PREFIX_KEY {
            return None;
        }
        prefixes.push(percent_decode(value)?);
    }
    Some(prefixes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefixes(query: &str) -> Option<Vec<String>> {
        parse_query(Some(query))
    }

    #[test]
    fn no_query_is_an_empty_prefix_list() {
        assert_eq!(parse_query(None), Some(Vec::new()));
        assert_eq!(prefixes(""), Some(Vec::new()));
    }

    #[test]
    fn each_pair_gives_one_decoded_prefix() {
        assert_eq!(
            prefixes("prefix=a%2Fb&prefix=main"),
            Some(vec!["a/b".to_owned(), "main".to_owned()])
        );
        assert_eq!(prefixes("prefix=a/b%2fc").unwrap(), ["a/b/c"]);
        assert_eq!(prefixes("prefix=a%2Bb").unwrap(), ["a+b"]);
        assert_eq!(prefixes("prefix=a+b").unwrap(), ["a+b"]);
        assert_eq!(prefixes("prefix=a=b").unwrap(), ["a=b"]);
        assert_eq!(prefixes("prefix=").unwrap(), [""]);
        assert_eq!(prefixes("prefix=a%2F%2Fb").unwrap(), ["a//b"]);
        assert_eq!(prefixes("prefix=x&prefix=x").unwrap(), ["x", "x"]);
    }

    #[test]
    fn bad_pairs_are_refused() {
        for bad in [
            "&",
            "prefix=a&",
            "&prefix=a",
            "prefix=a&&prefix=b",
            "prefix",
            "prefix=a&prefix",
            "x=1",
            "Prefix=a",
            "prefix%3Da",
            "pre%66ix=a",
            "prefix =a",
            "prefix=a%zz",
            "prefix=a%2",
            "prefix=a%00",
            "prefix=%ff",
        ] {
            assert_eq!(prefixes(bad), None, "{bad}");
        }
    }

    /// A query takes at most 256 prefixes, duplicates counted.
    #[test]
    fn a_query_takes_at_most_256_prefixes() {
        let query = |count: usize| vec!["prefix=a"; count].join("&");
        assert_eq!(prefixes(&query(MAX_REF_PREFIXES)).unwrap().len(), 256);
        assert_eq!(prefixes(&query(MAX_REF_PREFIXES + 1)), None);
    }

    /// A slot counts while it lives, and leaves the count when it drops. No
    /// slot is free while the count is full.
    #[test]
    fn a_slot_counts_until_it_drops() {
        let listings = Arc::new(AtomicUsize::new(0));
        let mut slots: Vec<Slot> = (0..MAX_LISTINGS)
            .map(|_| Slot::take(&listings).unwrap())
            .collect();
        assert_eq!(listings.load(Ordering::Acquire), 4);
        assert!(Slot::take(&listings).is_none());
        assert_eq!(listings.load(Ordering::Acquire), 4);
        slots.pop();
        assert_eq!(listings.load(Ordering::Acquire), 3);
        slots.push(Slot::take(&listings).unwrap());
        drop(slots);
        assert_eq!(listings.load(Ordering::Acquire), 0);
    }

    /// The body of a listing holds its slot until the body drops.
    #[test]
    fn the_body_holds_its_slot() {
        let listings = Arc::new(AtomicUsize::new(0));
        let reader = Box::new(Listing {
            bytes: Cursor::new(vec![7u8; 100_000]),
            _slot: Slot::take(&listings).unwrap(),
        });
        let body = ServeBody::stream(reader, Some(100_000), crate::body::tests::tracker());
        assert_eq!(listings.load(Ordering::Acquire), 1);
        let frames = ostrya_rt::block_on(crate::body::tests::frames(body)).unwrap();
        assert_eq!(frames.concat(), vec![7u8; 100_000]);
        assert_eq!(listings.load(Ordering::Acquire), 0);
    }

    /// The method comes first, then the query, then the count. A full count
    /// gives 503 with `Retry-After: 1` and an empty body.
    #[test]
    fn a_full_count_gives_503() {
        let listings = Arc::new(AtomicUsize::new(MAX_LISTINGS));
        let refused = |method: Method, query: &str| {
            let Err(status) = admit(&method, Some(query), &listings) else {
                panic!("{method} {query} is admitted");
            };
            status
        };
        assert_eq!(refused(Method::HEAD, "x"), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(refused(Method::GET, "x"), StatusCode::BAD_REQUEST);
        assert_eq!(
            refused(Method::GET, "prefix=a"),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(listings.load(Ordering::Acquire), MAX_LISTINGS);

        let response = refusal(StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[RETRY_AFTER], "1");
        assert_eq!(response.headers()[hyper::header::CONTENT_LENGTH], "0");
        assert!(matches!(response.body(), ServeBody::Empty));
        let response = refusal(StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[ALLOW], "GET");
        assert!(
            refusal(StatusCode::BAD_REQUEST)
                .headers()
                .get(RETRY_AFTER)
                .is_none()
        );

        listings.store(MAX_LISTINGS - 1, Ordering::Release);
        let Ok((prefixes, slot)) = admit(&Method::GET, Some("prefix=a"), &listings) else {
            panic!("a free slot is refused");
        };
        assert_eq!(prefixes, ["a"]);
        assert_eq!(listings.load(Ordering::Acquire), MAX_LISTINGS);
        drop(slot);
        assert_eq!(listings.load(Ordering::Acquire), MAX_LISTINGS - 1);
    }

    #[test]
    fn a_bad_prefix_is_400_and_other_errors_are_500() {
        assert_eq!(
            status_of(&ostrya::Error::InvalidRefspec("a/".into())),
            StatusCode::BAD_REQUEST
        );
        let limit = ostrya::remote::Error::LimitExceeded("listing".into());
        assert_eq!(
            status_of(&ostrya::Error::Remote(limit)),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            status_of(&ostrya::Error::InvalidFormat("x".into())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
