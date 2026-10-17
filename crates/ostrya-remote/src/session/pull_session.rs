//! The session of a pull over either transport: the HTTP fetcher or a stream
//! session.

use std::io;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::AsyncReadExt;
use ostrya_core::RefSelector;
use ostrya_fetch::{FetchRequest, Fetched, Fetcher, Priority};

use super::pull::{PullBody, StreamSession, StreamSessionOptions, wire_entries};
use crate::error::{Error, Result};
use crate::proto::{ListRefsRequest, MAX_REF_LISTING};

/// The cap on the `summary` and the `summary.sig` that
/// [`PullSession::fetch_summary`] reads: 64 MiB.
const MAX_SUMMARY_FILE: u64 = 64 * 1024 * 1024;

/// The largest chunk of one read of a body: 128 KiB.
const READ_CHUNK: usize = 128 * 1024;

/// The path of the summary at the repository root.
const SUMMARY_FILE: &str = "summary";

/// The path of the signature of the summary at the repository root.
const SUMMARY_SIG_FILE: &str = "summary.sig";

/// The path of the ref listing of an ostrya server, under the base URL of
/// each mirror.
const REFS_PATH: &str = "_ostrya/refs/v1";

/// The longest request target of a ref listing that the client sends:
/// 16 KiB.
///
/// The target is [`REFS_PATH`], `?`, and the encoded query. The base path of
/// the mirror comes before it on the wire, so the target that the server
/// gets is longer.
///
/// An HTTP/2 server of ostrya takes a header list of at most 32 KiB. The list
/// counts the base path, the other header fields, and 32 bytes for each
/// field. A target that the client accepts fits in this list, with 16 KiB
/// left for the base path and the other fields.
const MAX_REFS_TARGET: usize = 16 * 1024;

/// The key of each pair of the query of a ref listing that holds an entry of
/// the local refs.
const PATTERN_KEY: &str = "pattern=";

/// The key of each pair of the query of a ref listing that holds an entry of
/// the collection refs.
const COLLECTION_KEY: &str = "collection=";

/// The session of a pull: the HTTP fetcher of a remote, or a stream session.
///
/// [`connect`](PullSession::connect) opens a session to an
/// [`Endpoint`](crate::transport::Endpoint), and
/// [`over_stream`](PullSession::over_stream) opens one over a pair of byte
/// streams. The session is `Send + Sync`.
/// [`fetch_summary`](PullSession::fetch_summary) and
/// [`fetch_refs`](PullSession::fetch_refs) take `&self`, so the session stays
/// usable after the read.
///
/// To read a raw file of the remote, a caller matches on the variant and
/// uses the call of that variant: [`Fetcher::fetch`] for
/// [`Http`](PullSession::Http), and [`StreamSession::get`] for
/// [`Stream`](PullSession::Stream).
///
/// # Ref patterns
///
/// [`fetch_refs`](PullSession::fetch_refs) and [`StreamSession::list_refs`]
/// send the entries of two [`RefSelector`] values. [`RefSelector`] and
/// [`RefPattern`] give the pattern language.
///
/// - The first selector selects the local refs by name. In field 0, the
///   listing holds the local refs that it selects, so a selector with no
///   entry lists all local refs.
/// - The second selector selects the collection refs by `ID/NAME`, for
///   example `org.example.Os/stable` or `org.example.Os/**`. The listing
///   holds the collection refs that it selects under
///   `ostree.summary.collection-map`. A selector with no entry lists all
///   collection refs. `None` asks for no collection ref, and the listing
///   then has the bytes of a listing of the first selector alone.
///
/// The server leaves out each ref that the client cannot read. A caller
/// reads the collection refs of a listing with
/// `Summary::parse(&listing)?.collection_map()` of the `ostrya` crate.
///
/// Each of the two methods sends the entries by these rules, over both
/// transports:
///
/// - In each list, the positive entries come first, then the negative
///   entries, each with its `!`.
/// - The method removes each exact duplicate of one kind in one list and
///   keeps the first appearance, so `["a", "!b", "a"]` sends `["a", "!b"]`.
///   An entry of the two lists stays in each list.
/// - The method removes no entry because another entry covers it. A positive
///   `a` and a negative `!a` both stay, and `a` and `a/b` both stay.
/// - At most [`MAX_REF_PATTERNS`] entries can stay, positive and negative
///   entries of the two lists together.
/// - Over HTTP, `Some` of a second selector with no entry goes on the wire
///   as one `**` entry, and that entry counts toward the limit. Thus
///   [`MAX_REF_PATTERNS`] distinct entries in the first selector and `Some`
///   of an empty second selector are refused over HTTP, and accepted over
///   a stream session.
/// - An entry has at most [`MAX_REF_ENTRY_LEN`] bytes, with its `!` counted
///   as one byte. It has at most [`MAX_REF_ENTRY_PARTS`] parts, and the `!`
///   adds no part.
///
/// # Reads
///
/// [`fetch_summary`](PullSession::fetch_summary) and
/// [`fetch_refs`](PullSession::fetch_refs) read each body whole into one
/// buffer. The buffer gets the size that the remote states for the body,
/// within the cap of the method. Each read goes into a chunk of at most
/// 128 KiB. Over HTTP, if a body fails in transit, the method fetches it
/// again by the rules of [`Fetcher::refetching`].
///
/// [`RefPattern`]: ostrya_core::RefPattern
/// [`MAX_REF_PATTERNS`]: crate::proto::MAX_REF_PATTERNS
/// [`MAX_REF_ENTRY_LEN`]: crate::proto::MAX_REF_ENTRY_LEN
/// [`MAX_REF_ENTRY_PARTS`]: crate::proto::MAX_REF_ENTRY_PARTS
pub enum PullSession {
    /// The fetcher of an HTTP remote.
    Http(Fetcher),
    /// A stream session, over ssh or over a pair of byte streams.
    Stream(StreamSession),
}

/// The open of a session over a pair of byte streams, and the calls of the
/// session.
impl PullSession {
    /// Opens a stream session over a pair of byte streams.
    ///
    /// The call is [`StreamSession::over_stream`], and the result is
    /// [`PullSession::Stream`].
    ///
    /// # Errors
    ///
    /// - The [`Error`] variant of the code of an `Error` message from the
    ///   server.
    /// - [`Error::VersionUnsupported`] if the server states a version out of
    ///   `1..=PULL_PROTOCOL_VERSION`.
    /// - [`Error::Protocol`] if the reply is a message of another kind, or if
    ///   the codec refuses a frame of the reply.
    /// - [`Error::Protocol`] if `agent` holds a NUL byte.
    /// - [`Error::LimitExceeded`] if the `PullHello` frame or a frame of the
    ///   reply is longer than [`MIN_FRAME_LIMIT`].
    /// - [`Error::Io`] if a read or a write of a stream fails.
    ///
    /// [`StreamSession::over_stream`] gives the conditions in full.
    ///
    /// [`MIN_FRAME_LIMIT`]: crate::proto::MIN_FRAME_LIMIT
    pub async fn over_stream<R, W>(
        input: R,
        output: W,
        opts: StreamSessionOptions,
    ) -> Result<PullSession>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        StreamSession::over_stream(input, output, opts)
            .await
            .map(PullSession::Stream)
    }

    /// Reads the `summary` and the `summary.sig` of the remote.
    ///
    /// The call returns the bytes of `summary` and of `summary.sig`, in this
    /// order. If the remote does not serve a file, the call gives `None` for
    /// that file. Each file has a cap of 64 MiB. The call reads each file by
    /// the rules of [Reads](PullSession#reads).
    ///
    /// # Order
    ///
    /// Over HTTP, the call asks for `summary.sig` first and for `summary`
    /// second, at [`Priority::High`]. This is the order of the `ostree`
    /// command. A 404 reply means that the remote does not serve the file.
    ///
    /// Over a stream session, the two `Get` calls are in flight together, in
    /// the same order.
    ///
    /// # Errors
    ///
    /// - [`Error::Fetch`] over HTTP if a request fails after its retries, or
    ///   if the remote answers with a status other than 200 and 404. For a
    ///   stated length over the cap, the inner error of the fetcher is
    ///   [`FetchTooLarge`](ostrya_fetch::Error::FetchTooLarge). For a 304
    ///   reply, the inner error is [`Fetch`](ostrya_fetch::Error::Fetch).
    /// - [`Error::Io`] over HTTP if the read of a body fails and no refetch
    ///   applies. If a body grows past the cap, the kind is
    ///   [`FileTooLarge`](std::io::ErrorKind::FileTooLarge), and the call does
    ///   not fetch the body again.
    /// - Each error of [`StreamSession::get`] over a stream session. A stated
    ///   length over the cap is [`Error::LimitExceeded`].
    /// - Over a stream session, the error of the session if the read of a
    ///   body fails, as [`PullBody`] states:
    ///   - [`Error::LimitExceeded`] for a body over the cap
    ///   - [`Error::Protocol`] for a body whose length is different from its
    ///     stated length
    ///   - the variant of an `Error` message from the server after the abandon
    ///     marker
    ///   - [`Error::Io`] for a failed read
    ///   - the repeat of an earlier failure of the session
    pub async fn fetch_summary(&self) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        match self {
            PullSession::Http(fetcher) => {
                let signature = fetch_optional(
                    fetcher,
                    FetchRequest::path(SUMMARY_SIG_FILE),
                    MAX_SUMMARY_FILE,
                )
                .await?;
                let summary =
                    fetch_optional(fetcher, FetchRequest::path(SUMMARY_FILE), MAX_SUMMARY_FILE)
                        .await?;
                Ok((summary, signature))
            }
            PullSession::Stream(session) => {
                let (signature, summary) = futures_lite::future::zip(
                    read_optional(session, SUMMARY_SIG_FILE),
                    read_optional(session, SUMMARY_FILE),
                )
                .await;
                Ok((summary?, signature?))
            }
        }
    }

    /// Reads the ref listing of `refs` and `collections` from the remote.
    ///
    /// The listing is a summary of the local refs that `refs` selects and of
    /// the collection refs that `collections` selects. `None` asks for no
    /// collection ref. The server builds the listing for this request. The
    /// listing has a cap of [`MAX_REF_LISTING`] bytes. No signature covers
    /// the listing, and the call verifies none.
    ///
    /// The call sends the entries of the two selectors by the rules of
    /// [Ref patterns](PullSession#ref-patterns). It reads the listing by the
    /// rules of [Reads](PullSession#reads).
    ///
    /// # HTTP
    ///
    /// The call sends a `GET` of `_ostrya/refs/v1` under the base URL of each
    /// mirror, at [`Priority::High`]. Each entry of `refs` that stays goes
    /// into the query as one `pattern=VALUE` pair. Then each entry of
    /// `collections` that stays goes into the query as one `collection=VALUE`
    /// pair. `&` separates the pairs. With no entry and with `None`, the call
    /// sends no query. `Some` of a selector with no entry goes into the query
    /// as the one pair `collection=**`, which selects each collection ref and
    /// counts toward the limit of entries.
    ///
    /// The value is the entry with each byte outside `A-Z`, `a-z`, `0-9`,
    /// `-`, `.`, `_`, and `~` written as `%XX`. For example, `/` is `%2F`,
    /// `!` is `%21`, and `*` is `%2A`.
    ///
    /// The request target that the call builds, from `_ostrya/refs/v1` to the
    /// end of the query, is at most 16 KiB. The base path of the mirror comes
    /// before it on the wire. An ostrya server over HTTP/2 takes a header list
    /// of at most 32 KiB. The other 16 KiB are for the base path and the other
    /// header fields.
    ///
    /// A 404 reply comes from a remote that serves no ref listing, for example
    /// a static file server. The call then returns `None`.
    ///
    /// # Busy server
    ///
    /// An ostrya server answers 503 while it builds too many listings. The
    /// fetcher retries a 503 with its backoff and does not read
    /// `Retry-After`. If a 503 stays after the retries, the call returns
    /// [`Error::Fetch`].
    ///
    /// If the mirrors are a static mirror and a busy ostrya server:
    ///
    /// - The fetcher keeps the 404 of the static mirror from the first round,
    ///   and asks only the busy server again.
    /// - If the busy server answers 200 in a later round, the call returns
    ///   `Some`.
    /// - The call returns `None` only if the busy server answers 503 to each
    ///   retry. It then returns `None` after the full backoff, because a 404
    ///   has priority over a 503.
    ///
    /// # Stream session
    ///
    /// The call is [`StreamSession::list_refs`], in the pipeline with the
    /// `get` calls. It returns `Some` with the bytes of the listing.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if the entries break a limit of
    ///   [Ref patterns](PullSession#ref-patterns). The call sends no request.
    /// - [`Error::InvalidInput`] over HTTP if the request target is longer
    ///   than 16 KiB. The call sends no request.
    /// - [`Error::Fetch`] over HTTP if a request fails after its retries, or
    ///   if the remote answers with a status other than 200 and 404. For a
    ///   stated length over the cap, the inner error of the fetcher is
    ///   [`FetchTooLarge`](ostrya_fetch::Error::FetchTooLarge). For a 304
    ///   reply, the inner error is [`Fetch`](ostrya_fetch::Error::Fetch).
    /// - [`Error::Fetch`] over HTTP if the server refuses the request. The
    ///   inner error is [`HttpStatus`](ostrya_fetch::Error::HttpStatus). For
    ///   example, the status is 400 for a pattern that the server refuses, or
    ///   for a `collection` pair that a server without collection refs in its
    ///   listing does not know, and
    ///   414 or 431 for a target that is too long for it. A server that stays
    ///   busy gives 503. An ostrya server gives 500 for a listing over
    ///   [`MAX_REF_LISTING`] bytes.
    /// - [`Error::Io`] over HTTP if the read of the body fails and no refetch
    ///   applies. If the body grows past the cap, the kind is
    ///   [`FileTooLarge`](std::io::ErrorKind::FileTooLarge), and the call does
    ///   not fetch the body again.
    /// - Each error of [`StreamSession::list_refs`] over a stream session. A
    ///   stated length over the cap is [`Error::LimitExceeded`]. If the server
    ///   refuses the listing for its cap, the error is also
    ///   [`Error::LimitExceeded`].
    /// - Over a stream session, the error of the session if the read of the
    ///   body fails, as [`fetch_summary`](PullSession::fetch_summary) lists.
    pub async fn fetch_refs(
        &self,
        refs: &RefSelector,
        collections: Option<&RefSelector>,
    ) -> Result<Option<Vec<u8>>> {
        match self {
            PullSession::Http(fetcher) => {
                // A query with no `collection` pair asks for no collection
                // ref, so a list with no entry goes as the entry `**`.
                let every;
                let collections = match collections {
                    Some(selector)
                        if selector.positive().is_empty() && selector.negative().is_empty() =>
                    {
                        every = RefSelector::parse(["**"]).expect("`**` is a selector entry");
                        Some(&every)
                    }
                    other => other,
                };
                let request = wire_entries(refs, collections)?;
                let query = refs_query(&request)?;
                let request = match &query {
                    Some(query) => FetchRequest::path_query(REFS_PATH, query),
                    None => FetchRequest::path(REFS_PATH),
                };
                fetch_optional(fetcher, request, MAX_REF_LISTING).await
            }
            PullSession::Stream(session) => {
                let body = session
                    .list_refs(refs, collections, MAX_REF_LISTING)
                    .await?;
                read_body(body, MAX_REF_LISTING).await.map(Some)
            }
        }
    }

    /// Returns the most requests that the session keeps in flight at one time.
    ///
    /// The value is at least 1. For HTTP, it is [`Fetcher::max_outstanding`].
    /// For a stream session, it is the
    /// [`StreamSessionOptions::max_outstanding`] of the open, or 8 if that
    /// field is `None`.
    pub fn max_outstanding(&self) -> usize {
        match self {
            PullSession::Http(fetcher) => fetcher.max_outstanding(),
            PullSession::Stream(session) => session.max_outstanding(),
        }
    }

    /// Ends the session.
    ///
    /// For HTTP, the call returns `Ok(())`. For a stream session, it is
    /// [`StreamSession::finish`].
    ///
    /// # Errors
    ///
    /// Over a stream session, the errors of [`StreamSession::finish`]:
    ///
    /// - The repeat of the first failure, if the session failed.
    /// - [`Error::InvalidInput`] if the body of a reply is not read to its
    ///   end.
    /// - [`Error::Transport`] if the ssh client exited with a failure status
    ///   and the error of the session is [`Error::Io`].
    pub async fn finish(self) -> Result<()> {
        match self {
            PullSession::Http(_) => Ok(()),
            PullSession::Stream(session) => session.finish().await,
        }
    }
}

/// Returns the query of a ref listing of `request`, or `None` for a request
/// with no entry.
///
/// Each entry of the local refs is one `pattern=VALUE` pair. Then each entry
/// of the collection refs is one `collection=VALUE` pair. `&` separates the
/// pairs. The value is the entry with each byte outside the unreserved set
/// of URIs written as `%XX`, in upper case.
///
/// # Errors
///
/// [`Error::InvalidInput`] if the request target, [`REFS_PATH`] with `?` and
/// the query, is longer than [`MAX_REFS_TARGET`]. The function measures the
/// target before it builds the query.
fn refs_query(request: &ListRefsRequest) -> Result<Option<String>> {
    let collections = request.collections.as_deref().unwrap_or_default();
    let pairs = || {
        let refs = request.refs.iter().map(|entry| (PATTERN_KEY, entry));
        refs.chain(collections.iter().map(|entry| (COLLECTION_KEY, entry)))
    };
    let count = request.refs.len() + collections.len();
    if count == 0 {
        return Ok(None);
    }
    let len = pairs()
        .map(|(key, entry)| key.len() + encoded_len(entry))
        .sum::<usize>()
        + count
        - 1;
    let target = REFS_PATH.len() + 1 + len;
    if target > MAX_REFS_TARGET {
        return Err(Error::InvalidInput(format!(
            "the request target of the ref listing is {target} bytes, over the limit of \
             {MAX_REFS_TARGET}: ask for fewer or shorter patterns"
        )));
    }
    let mut query = String::with_capacity(len);
    for (n, (key, entry)) in pairs().enumerate() {
        if n > 0 {
            query.push('&');
        }
        query.push_str(key);
        encode(entry, &mut query);
    }
    Ok(Some(query))
}

/// Returns `true` if `byte` is in the unreserved set of URIs, which a query
/// value carries without an escape.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Returns the length of `value` after [`encode`].
fn encoded_len(value: &str) -> usize {
    value
        .bytes()
        .map(|byte| if is_unreserved(byte) { 1 } else { 3 })
        .sum()
}

/// Writes `value` to `out`, with each byte outside the unreserved set of URIs
/// written as `%XX`, in upper case.
fn encode(value: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if is_unreserved(byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0xf)]));
        }
    }
}

/// Fetches `request` whole under `cap` bytes, or returns `None` if the remote
/// answers 404.
async fn fetch_optional(
    fetcher: &Fetcher,
    request: FetchRequest<'_>,
    cap: u64,
) -> Result<Option<Vec<u8>>> {
    match fetch_whole(fetcher, request, cap).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::Fetch(ostrya_fetch::Error::HttpStatus { status: 404, .. })) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Fetches `request` whole under `cap` bytes, at [`Priority::High`].
///
/// The fetcher refuses a stated `Content-Length` over the cap before it reads
/// the body, and it stops a body that passes the cap. If a body fails in
/// transit, the function fetches it again from the start, into a new buffer,
/// while the retry count of the fetcher has a repeat left.
async fn fetch_whole(fetcher: &Fetcher, request: FetchRequest<'_>, cap: u64) -> Result<Vec<u8>> {
    let target = request.target;
    let mut refetch = fetcher.refetching(FetchRequest {
        priority: Priority::High,
        max_size: Some(cap),
        ..request
    });
    loop {
        let Fetched::Body(body) = refetch.fetch().await.map_err(Error::Fetch)? else {
            return Err(Error::Fetch(ostrya_fetch::Error::Fetch(format!(
                "{target:?}: the remote answered 304 to an unconditional request"
            ))));
        };
        let declared = body.content_length();
        match read_whole(body, declared, cap).await {
            Ok(out) => return Ok(out),
            Err(e) => refetch.retry(Error::Io(e)).await?,
        }
    }
}

/// Reads `path` whole from `session` under [`MAX_SUMMARY_FILE`], or returns
/// `None` if the server does not serve it.
async fn read_optional(session: &StreamSession, path: &str) -> Result<Option<Vec<u8>>> {
    let Some(body) = session.get(path, MAX_SUMMARY_FILE).await? else {
        return Ok(None);
    };
    read_body(body, MAX_SUMMARY_FILE).await.map(Some)
}

/// Reads a stream `body` whole, with a buffer of at most `cap` bytes before
/// the first read.
async fn read_body(body: PullBody, cap: u64) -> Result<Vec<u8>> {
    let declared = body.len();
    // A failed read of a body carries the error of the session.
    read_whole(body, declared, cap)
        .await
        .map_err(|e| e.downcast::<Error>().unwrap_or_else(Error::Io))
}

/// Reads `body` to its end into one buffer.
///
/// The size of the buffer comes from `declared`, the stated length, within
/// `cap`. Each read goes into a chunk of at most [`READ_CHUNK`] bytes, also
/// the read that finds the end of the body, so a buffer filled to its stated
/// length does not grow. With a stated length, the chunk is that length
/// plus 1, held between 4096 and [`READ_CHUNK`] bytes. With no stated length,
/// the chunk is [`READ_CHUNK`] bytes.
///
/// A buffer that must grow doubles its capacity, to at most `cap`. The body
/// stops at its cap, so the capacity of the buffer is never more than `cap`.
async fn read_whole<R: AsyncRead + Unpin>(
    mut body: R,
    declared: Option<u64>,
    cap: u64,
) -> io::Result<Vec<u8>> {
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    let declared = declared.map(|len| usize::try_from(len).unwrap_or(usize::MAX).min(cap));
    let mut out = Vec::with_capacity(declared.unwrap_or(0));
    let chunk_len = declared.map_or(READ_CHUNK, |len| {
        len.saturating_add(1).clamp(4096, READ_CHUNK)
    });
    let mut chunk = vec![0u8; chunk_len];
    loop {
        let n = body.read(&mut chunk).await?;
        if n == 0 {
            return Ok(out);
        }
        let needed = out.len() + n;
        if needed > out.capacity() {
            let grown = out.capacity().saturating_mul(2).min(cap).max(needed);
            out.reserve_exact(grown - out.len());
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body with no stated length grows the buffer by doubling, and the
    /// capacity stops at the cap.
    #[test]
    fn a_buffer_with_no_stated_length_grows_to_the_cap_at_most() {
        for cap in [10_000usize, 4096, 1, 300_000] {
            let bytes: Vec<u8> = (0..cap).map(|n| n as u8).collect();
            let body = futures_lite::io::Cursor::new(bytes.clone());
            let out = ostrya_rt::block_on(read_whole(body, None, cap as u64)).unwrap();
            assert_eq!(out, bytes);
            assert!(out.capacity() <= cap, "{cap}: {}", out.capacity());
        }
    }

    /// Each byte outside the unreserved set is `%XX` in upper case, and the
    /// measured length is the length of the result.
    #[test]
    fn an_entry_is_percent_encoded() {
        let cases = [
            ("a/b", "a%2Fb"),
            ("A-z.0_9~", "A-z.0_9~"),
            ("x y+z", "x%20y%2Bz"),
            ("?#&=%", "%3F%23%26%3D%25"),
            ("é", "%C3%A9"),
            ("!a/*", "%21a%2F%2A"),
            ("a/**", "a%2F%2A%2A"),
        ];
        for (value, encoded) in cases {
            let mut out = String::new();
            encode(value, &mut out);
            assert_eq!(out, encoded);
            assert_eq!(encoded_len(value), encoded.len());
        }
        assert_eq!(refs_query(&request(&[], None)).unwrap(), None);
        assert_eq!(
            refs_query(&request(&["a/b", "main"], None))
                .unwrap()
                .as_deref(),
            Some("pattern=a%2Fb&pattern=main")
        );
        assert_eq!(
            refs_query(&request(&["a/**", "x/*", "!a/b/*", "!z"], None))
                .unwrap()
                .as_deref(),
            Some("pattern=a%2F%2A%2A&pattern=x%2F%2A&pattern=%21a%2Fb%2F%2A&pattern=%21z")
        );
    }

    /// Returns the request of the entries `refs` and `collections`, as
    /// `wire_entries` gives them.
    fn request(refs: &[&str], collections: Option<&[&str]>) -> ListRefsRequest {
        let entries = |list: &[&str]| list.iter().map(|e| (*e).to_owned()).collect();
        ListRefsRequest {
            refs: entries(refs),
            collections: collections.map(entries),
        }
    }

    /// The `collection` pairs come after the `pattern` pairs. A request with
    /// collection entries alone has a query. An empty list of collection
    /// entries adds no pair: `fetch_refs` sends it as the entry `**`.
    #[test]
    fn collection_entries_follow_the_pattern_pairs() {
        assert_eq!(
            refs_query(&request(&["main"], Some(&["org.a/**", "!org.b/x"])))
                .unwrap()
                .as_deref(),
            Some("pattern=main&collection=org.a%2F%2A%2A&collection=%21org.b%2Fx")
        );
        assert_eq!(
            refs_query(&request(&[], Some(&["*/main"])))
                .unwrap()
                .as_deref(),
            Some("collection=%2A%2Fmain")
        );
        assert_eq!(refs_query(&request(&[], Some(&[]))).unwrap(), None);
        assert_eq!(
            refs_query(&request(&["a"], Some(&["**"])))
                .unwrap()
                .as_deref(),
            Some("pattern=a&collection=%2A%2A")
        );
    }

    /// The target limit counts the `collection` pairs, their keys, and the
    /// `&` between the two kinds of pairs.
    #[test]
    fn the_target_limit_counts_the_collection_pairs() {
        let fixed = REFS_PATH.len() + 1 + PATTERN_KEY.len() + 1 + 1 + COLLECTION_KEY.len();
        let fits = "a".repeat(MAX_REFS_TARGET - fixed);
        let query = refs_query(&request(&["a"], Some(&[&fits])))
            .unwrap()
            .unwrap();
        assert_eq!(REFS_PATH.len() + 1 + query.len(), MAX_REFS_TARGET);
        let over = "a".repeat(MAX_REFS_TARGET - fixed + 1);
        let err = refs_query(&request(&["a"], Some(&[&over]))).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    }

    /// The target limit counts `_ostrya/refs/v1`, the `?`, and the query. A
    /// target of exactly the limit passes.
    #[test]
    fn the_target_limit_is_inclusive() {
        let fixed = REFS_PATH.len() + 1 + PATTERN_KEY.len();
        let fits = "a".repeat(MAX_REFS_TARGET - fixed);
        let query = refs_query(&request(&[&fits], None)).unwrap().unwrap();
        assert_eq!(REFS_PATH.len() + 1 + query.len(), MAX_REFS_TARGET);
        assert_eq!(query.capacity(), query.len());
        let over = "a".repeat(MAX_REFS_TARGET - fixed + 1);
        let err = refs_query(&request(&[&over], None)).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    }

    /// A `!` counts in the length of the target. `refs_query` refuses a
    /// negative entry one byte over the limit, and accepts a negative entry at
    /// the limit.
    #[test]
    fn the_target_limit_counts_the_bang() {
        let fixed = REFS_PATH.len() + 1 + PATTERN_KEY.len();
        let fits = format!("!{}", "a".repeat(MAX_REFS_TARGET - fixed - 3));
        let query = refs_query(&request(&[&fits], None)).unwrap().unwrap();
        assert_eq!(REFS_PATH.len() + 1 + query.len(), MAX_REFS_TARGET);
        let over = format!("!{}", "a".repeat(MAX_REFS_TARGET - fixed - 2));
        let err = refs_query(&request(&[&over], None)).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    }
}
