//! The ref listing: the refs of the repository that two lists of ref
//! patterns select.
//!
//! A `GET` of [`PATH`] gets the bytes of [`Repo::build_ref_listing`], built
//! for each request with the read rights of its client. Each pair of the
//! query is `pattern=VALUE`, an entry of the local refs, or
//! `collection=VALUE`, an entry of the collection refs. The value is
//! percent-decoded, and it is one entry of a [`RefSelector`]: a ref pattern
//! with an optional leading `!`. An entry has at most
//! [`MAX_REF_ENTRY_PARTS`] parts and [`MAX_REF_ENTRY_LEN`] bytes. The server
//! parses the entries before it takes a slot, so a bad entry gets 400 also
//! when the slots are busy. No `pattern` pair is an empty list, which selects
//! all local refs. No `collection` pair asks for no collection ref.
//!
//! A listing is whole in memory from its build until its body drops. The
//! server holds at most [`MAX_LISTINGS`] listings at the same time, over all
//! connections.
//!
//! The server reports each directory under `refs/mirrors/` whose name fails
//! the collection-id rule one time, as a [`ServerEvent::InvalidCollectionDir`].

use std::collections::HashSet;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use futures_io::AsyncRead;
use futures_lite::io::Cursor;
use hyper::header::{ALLOW, HeaderValue, RETRY_AFTER};
use hyper::{Method, Response, StatusCode};
use ostrya::access::ReadAccess;
use ostrya::{MAX_REF_ENTRY_LEN, MAX_REF_ENTRY_PARTS, MAX_REF_PATTERNS, RefSelector, Repo};

use crate::body::ServeBody;
use crate::event::{EventSink, ServerEvent};
use crate::receive_auth::Refusal;
use crate::router::{empty, percent_decode, refused, with_length};
use crate::stall::Stall;

/// The path of the listing. No repository layout uses it.
pub(crate) const PATH: &str = "/_ostrya/refs/v1";

/// The key of each pair of the query that holds an entry of the local refs.
const PATTERN_KEY: &str = "pattern";

/// The key of each pair of the query that holds an entry of the collection
/// refs.
const COLLECTION_KEY: &str = "collection";

/// The most listings that the server holds at the same time, over all
/// connections. A listing holds its slot from the start of its build until
/// its body drops.
const MAX_LISTINGS: usize = 4;

/// The ref listings of one server: the count of the listings in flight over
/// all connections, and the warnings of the listings.
pub(crate) struct Listings {
    /// The count of the listings in flight.
    in_flight: Arc<AtomicUsize>,
    /// The names of the invalid collection directories that the server
    /// reported.
    warned: Mutex<HashSet<String>>,
    /// The callback of the events of the server.
    on_event: Option<EventSink>,
}

impl Listings {
    /// Returns the listings of a server with no listing in flight, which
    /// report their events to `on_event`.
    pub(crate) fn new(on_event: Option<EventSink>) -> Listings {
        Listings {
            in_flight: Arc::new(AtomicUsize::new(0)),
            warned: Mutex::new(HashSet::new()),
            on_event,
        }
    }

    /// Reports each name of `names` that the server did not report before
    /// as a [`ServerEvent::InvalidCollectionDir`].
    fn report(&self, names: Vec<String>) {
        let Some(on_event) = &self.on_event else {
            return;
        };
        let mut new = Vec::new();
        {
            let mut warned = self.warned.lock().unwrap_or_else(PoisonError::into_inner);
            for name in names {
                if !warned.contains(&name) {
                    warned.insert(name.clone());
                    new.push(name);
                }
            }
        }
        for name in new {
            on_event(&ServerEvent::InvalidCollectionDir { name });
        }
    }
}

/// Returns the response to a request of [`PATH`] with `method` and the raw
/// `query`. The function records the body in `stall`, the deadline of its
/// connection. `listings` holds the count of listings in flight in the
/// server, and reports the invalid collection directories of the listing.
/// `identify` gives the read rights of the client, or the refusal of the
/// request.
///
/// A method other than `GET` gets 405 with `Allow: GET`. Then `identify`
/// runs. Then a bad query gets 400. If [`MAX_LISTINGS`] listings are in
/// flight, the request gets 503 with `Retry-After: 1`. These checks come in
/// this order, before the build. A query entry that is not a ref pattern, or
/// that is over the limits of one entry, is a bad query. The listing is
/// built in the request task, and holds the refs that the client reads.
pub(crate) async fn handle(
    repo: &Repo,
    listings: &Listings,
    method: &Method,
    query: Option<&str>,
    stall: &Arc<Stall>,
    identify: impl FnOnce() -> Result<ReadAccess, Refusal>,
) -> Response<ServeBody> {
    if method != Method::GET {
        return refusal(StatusCode::METHOD_NOT_ALLOWED);
    }
    let access = match identify() {
        Ok(access) => access,
        Err(rejected) => return refused(rejected),
    };
    let ((refs, collections), slot) = match admit(query, &listings.in_flight) {
        Ok(admitted) => admitted,
        Err(status) => return refusal(status),
    };
    match repo
        .build_ref_listing(&refs, collections.as_ref(), &access)
        .await
    {
        Ok(listing) => {
            listings.report(listing.invalid_collection_dirs);
            let len = listing.bytes.len() as u64;
            let reader = Box::new(Listing {
                bytes: Cursor::new(listing.bytes),
                _slot: slot,
            });
            let body = ServeBody::stream(reader, Some(len), stall.track());
            with_length(Response::new(body), Some(len))
        }
        Err(_) => empty(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// The selectors of a request: the selector of the local refs, and the
/// selector of the collection refs, or `None`.
type Selectors = (RefSelector, Option<RefSelector>);

/// Returns the selectors of the request and a slot of `listings`, or the
/// status that refuses the request.
///
/// A bad query gets 400, also for an entry that is not a ref pattern. Then,
/// if no slot is free, the request gets 503.
fn admit(
    query: Option<&str>,
    listings: &Arc<AtomicUsize>,
) -> Result<(Selectors, Slot), StatusCode> {
    let selector = parse_query(query).ok_or(StatusCode::BAD_REQUEST)?;
    let slot = Slot::take(listings).ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((selector, slot))
}

/// Returns the response of a refusal of [`handle`] or [`admit`] with
/// `status`, with an empty body. A 405 carries `Allow: GET`, and a 503 carries
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

/// Returns the selectors of the raw `query`. No query and an empty query
/// give the selector with no entry and no selector of the collection refs.
///
/// Each pair of the query is `pattern=VALUE` or `collection=VALUE`, and `&`
/// separates two pairs. The key must be the raw bytes `pattern` or
/// `collection`. The value is percent-decoded with [`percent_decode`], so
/// `+` stays `+`, and it is one entry of [`RefSelector::parse`]. The
/// `pattern` entries give the selector of the local refs. The `collection`
/// entries give the selector of the collection refs, which is `Some` when the
/// query has one or more `collection` pairs. If a pair is empty, has no `=`,
/// has another key, has a value over three times [`MAX_REF_ENTRY_LEN`]
/// bytes, which the function refuses before it decodes, has a value that
/// does not decode, or has an entry over [`MAX_REF_ENTRY_PARTS`] parts or
/// [`MAX_REF_ENTRY_LEN`] bytes, the function returns `None`. The limits of an
/// entry come before the parse. If the query has more than
/// [`MAX_REF_PATTERNS`] pairs of the two keys together, the function returns
/// `None` before it decodes the pair after the limit. If the parse refuses
/// an entry, the function returns `None`. A server keeps each entry and
/// drops an entry that a pair of the same key repeats exactly.
fn parse_query(query: Option<&str>) -> Option<Selectors> {
    let query = match query {
        None | Some("") => return Some((RefSelector::parse([]).ok()?, None)),
        Some(query) => query,
    };
    let mut refs: Vec<String> = Vec::new();
    let mut collections: Option<Vec<String>> = None;
    for (index, pair) in query.split('&').enumerate() {
        if index == MAX_REF_PATTERNS {
            return None;
        }
        let (key, value) = pair.split_once('=')?;
        let entries = match key {
            PATTERN_KEY => &mut refs,
            COLLECTION_KEY => collections.get_or_insert_default(),
            _ => return None,
        };
        if value.len() > 3 * MAX_REF_ENTRY_LEN {
            return None;
        }
        let entry = percent_decode(value)?;
        if entry.len() > MAX_REF_ENTRY_LEN || entry.split('/').count() > MAX_REF_ENTRY_PARTS {
            return None;
        }
        if !entries.contains(&entry) {
            entries.push(entry);
        }
    }
    let parse = |entries: &[String]| RefSelector::parse(entries.iter().map(String::as_str)).ok();
    let collections = match collections {
        Some(entries) => Some(parse(&entries)?),
        None => None,
    };
    Some((parse(&refs)?, collections))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selector(query: &str) -> Option<RefSelector> {
        let (refs, collections) = parse_query(Some(query))?;
        assert_eq!(collections, None, "{query}");
        Some(refs)
    }

    fn both(query: &str) -> Option<Selectors> {
        parse_query(Some(query))
    }

    fn parsed(entries: &[&str]) -> RefSelector {
        RefSelector::parse(entries.iter().copied()).unwrap()
    }

    #[test]
    fn no_query_is_an_empty_selector() {
        assert_eq!(parse_query(None), Some((parsed(&[]), None)));
        assert_eq!(selector(""), Some(parsed(&[])));
    }

    /// The `collection` pairs give the selector of the collection refs, in
    /// any order with the `pattern` pairs. An exact repeat is dropped within
    /// each key, and one entry in the two keys stays in each.
    #[test]
    fn collection_pairs_give_the_second_selector() {
        assert_eq!(
            both("collection=org.a%2F%2A%2A"),
            Some((parsed(&[]), Some(parsed(&["org.a/**"]))))
        );
        assert_eq!(
            both("collection=%2A%2Fmain&pattern=a&collection=%21org.b%2F%2A%2A&pattern=a"),
            Some((parsed(&["a"]), Some(parsed(&["*/main", "!org.b/**"]))))
        );
        assert_eq!(
            both("pattern=x&collection=x&collection=x"),
            Some((parsed(&["x"]), Some(parsed(&["x"]))))
        );
        assert_eq!(
            both("collection=%2A%2A"),
            Some((parsed(&[]), Some(parsed(&["**"]))))
        );
        for bad in [
            "collection=",
            "collection=a%2F%2Fb",
            "collection=%21%21a",
            "pattern=a&collection=a%2A",
            "Collection=a",
            "collections=a",
            "collection",
            "collection=a&",
            &format!("collection={}", "a".repeat(MAX_REF_ENTRY_LEN + 1)),
            &format!(
                "collection={}",
                vec!["a"; MAX_REF_ENTRY_PARTS + 1].join("%2F")
            ),
        ] {
            assert_eq!(both(bad), None, "{bad}");
        }
    }

    /// The limit of 256 pairs counts the pairs of the two keys together,
    /// repeats included.
    #[test]
    fn the_two_keys_share_the_limit_of_pairs() {
        let mixed = |count: usize| {
            (0..count)
                .map(|n| {
                    if n % 2 == 0 {
                        format!("pattern=r{n}")
                    } else {
                        format!("collection=c{n}%2Fx")
                    }
                })
                .collect::<Vec<_>>()
                .join("&")
        };
        let (refs, collections) = both(&mixed(MAX_REF_PATTERNS)).unwrap();
        assert_eq!(refs.positive().len(), MAX_REF_PATTERNS / 2);
        assert_eq!(collections.unwrap().positive().len(), MAX_REF_PATTERNS / 2);
        assert_eq!(both(&mixed(MAX_REF_PATTERNS + 1)), None);
        let repeats = vec!["collection=a%2Fb"; MAX_REF_PATTERNS + 1].join("&");
        assert_eq!(both(&repeats), None);
    }

    #[test]
    fn each_pair_gives_one_decoded_entry() {
        assert_eq!(
            selector("pattern=a%2Fb&pattern=main"),
            Some(parsed(&["a/b", "main"]))
        );
        assert_eq!(selector("pattern=a/b%2fc"), Some(parsed(&["a/b/c"])));
        assert_eq!(selector("pattern=a%2F%2A"), Some(parsed(&["a/*"])));
        assert_eq!(selector("pattern=a%2f**"), Some(parsed(&["a/**"])));
        assert_eq!(selector("pattern=%21a%2Fb"), Some(parsed(&["!a/b"])));
        assert_eq!(
            selector("pattern=a%2F%2A%2Fc&pattern=%21a%2Fx%2F%2A%2A"),
            Some(parsed(&["a/*/c", "!a/x/**"]))
        );
    }

    /// An entry that an exact repeat gives is dropped. Entries that overlap
    /// stay.
    #[test]
    fn an_exact_repeat_is_dropped() {
        assert_eq!(
            selector("pattern=x&pattern=x&pattern=x%2F%2A"),
            Some(parsed(&["x", "x/*"]))
        );
        assert_eq!(selector("pattern=%21x&pattern=%21x"), Some(parsed(&["!x"])));
    }

    /// An entry that `RefSelector::parse` refuses makes the query bad.
    #[test]
    fn a_bad_entry_is_refused() {
        for bad in [
            "pattern=",
            "pattern=%2F",
            "pattern=a%2F%2Fb",
            "pattern=a%2F",
            "pattern=%2Fa",
            "pattern=a%2A",
            "pattern=%2A%2Ax",
            "pattern=%2A%2A%2A",
            "pattern=%21%21a",
            "pattern=%21",
            "pattern=a%21",
            "pattern=a+b",
            "pattern=a=b",
            "pattern=a%2B",
            "pattern=main&pattern=a%2F%2Fb",
            "pattern=..",
            "pattern=-a",
        ] {
            assert_eq!(selector(bad), None, "{bad}");
        }
    }

    #[test]
    fn bad_pairs_are_refused() {
        for bad in [
            "&",
            "pattern=a&",
            "&pattern=a",
            "pattern=a&&pattern=b",
            "pattern",
            "pattern=a&pattern",
            "x=1",
            "prefix=a",
            "collections=a",
            "pattern=a&prefix=b",
            "Pattern=a",
            "pattern%3Da",
            "pat%74ern=a",
            "pattern =a",
            "pattern=a%zz",
            "pattern=a%2",
            "pattern=a%00",
            "pattern=%ff",
        ] {
            assert_eq!(selector(bad), None, "{bad}");
        }
    }

    /// A query takes at most 256 pairs, duplicates counted. The limit comes
    /// before the decode and the parse of the pair after it.
    #[test]
    fn a_query_takes_at_most_256_pairs() {
        let query = |count: usize| vec!["pattern=a"; count].join("&");
        assert_eq!(selector(&query(MAX_REF_PATTERNS)), Some(parsed(&["a"])));
        assert_eq!(selector(&query(MAX_REF_PATTERNS + 1)), None);
        let distinct: Vec<String> = (0..MAX_REF_PATTERNS)
            .map(|n| {
                if n % 2 == 0 {
                    format!("pattern=r{n}")
                } else {
                    format!("pattern=%21r{n}")
                }
            })
            .collect();
        let distinct = distinct.join("&");
        let both = selector(&distinct).unwrap();
        assert_eq!(
            both.positive().len() + both.negative().len(),
            MAX_REF_PATTERNS
        );
        assert_eq!(both.negative().len(), MAX_REF_PATTERNS / 2);
        assert_eq!(selector(&format!("{distinct}&pattern=%21z")), None);
        assert_eq!(selector(&format!("{distinct}&pattern=%zz")), None);
    }

    /// An entry has at most 256 parts and 4096 bytes. The limit comes before
    /// the parse, so an entry over it is refused whatever its text.
    #[test]
    fn an_entry_takes_at_most_256_parts_and_4096_bytes() {
        let parts = |count: usize| vec!["a"; count].join("%2F");
        assert!(selector(&format!("pattern={}", parts(MAX_REF_ENTRY_PARTS))).is_some());
        assert_eq!(
            selector(&format!("pattern={}", parts(MAX_REF_ENTRY_PARTS + 1))),
            None
        );
        let len = |count: usize| "a".repeat(count);
        assert!(selector(&format!("pattern={}", len(MAX_REF_ENTRY_LEN))).is_some());
        assert_eq!(
            selector(&format!("pattern={}", len(MAX_REF_ENTRY_LEN + 1))),
            None
        );
        // The bytes of a `!` count.
        assert_eq!(
            selector(&format!("pattern=%21{}", len(MAX_REF_ENTRY_LEN))),
            None
        );
        // The `!` adds no part: 256 parts pass, 257 do not.
        assert!(selector(&format!("pattern=%21{}", parts(MAX_REF_ENTRY_PARTS))).is_some());
        assert_eq!(
            selector(&format!("pattern=%21{}", parts(MAX_REF_ENTRY_PARTS + 1))),
            None
        );
        // An entry over the limit with a bad text gets the same refusal.
        assert_eq!(selector(&format!("pattern={}", "%2F".repeat(300))), None);
    }

    /// A raw value over three times the byte limit of an entry is refused
    /// before the decode. A raw value at the limit is decoded.
    #[test]
    fn a_raw_value_over_the_limit_is_refused() {
        let limit = 3 * MAX_REF_ENTRY_LEN;
        let value = |len: usize| "%61".repeat(len / 3);
        assert_eq!(value(limit).len(), limit);
        assert!(selector(&format!("pattern={}", value(limit))).is_some());
        assert_eq!(selector(&format!("pattern={}a", value(limit))), None);
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

    /// The listings report each name one time over all requests, and drop
    /// each name with no callback.
    #[test]
    fn the_listings_report_each_name_one_time() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let listings = Listings::new(Some(Arc::new(move |event: &ServerEvent| {
            sink.lock().unwrap().push(event.clone());
        })));
        listings.report(vec!["a..b".to_owned(), "bad".to_owned()]);
        listings.report(vec!["bad".to_owned(), "1a.b".to_owned()]);
        let names: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|event| match event {
                ServerEvent::InvalidCollectionDir { name } => name.clone(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(names, ["a..b", "bad", "1a.b"]);
        Listings::new(None).report(vec!["bad".to_owned()]);
    }

    /// The query comes first, then the count. A full count gives 503 with
    /// `Retry-After: 1` and an empty body.
    #[test]
    fn a_full_count_gives_503() {
        let listings = Arc::new(AtomicUsize::new(MAX_LISTINGS));
        let refused = |query: &str| {
            let Err(status) = admit(Some(query), &listings) else {
                panic!("{query} is admitted");
            };
            status
        };
        assert_eq!(refused("x"), StatusCode::BAD_REQUEST);
        // A bad entry gets 400 also when no slot is free.
        assert_eq!(refused("pattern=a%2F%2Fb"), StatusCode::BAD_REQUEST);
        assert_eq!(refused("pattern=a%2A"), StatusCode::BAD_REQUEST);
        assert_eq!(refused("pattern=a"), StatusCode::SERVICE_UNAVAILABLE);
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
        let Ok(((selector, collections), slot)) = admit(Some("pattern=a"), &listings) else {
            panic!("a free slot is refused");
        };
        assert_eq!(selector, parsed(&["a"]));
        assert_eq!(collections, None);
        assert_eq!(listings.load(Ordering::Acquire), MAX_LISTINGS);
        drop(slot);
        assert_eq!(listings.load(Ordering::Acquire), MAX_LISTINGS - 1);
    }
}
