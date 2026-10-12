//! The session of a pull over either transport: the HTTP fetcher or a stream
//! session.

use std::io;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::AsyncReadExt;
use ostrya_fetch::{FetchRequest, Fetched, Fetcher, Priority};

use super::pull::{PullBody, StreamSession, StreamSessionOptions, reduce_prefixes};
use crate::error::{Error, Result};
use crate::proto::MAX_REF_LISTING;

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
/// gets is longer. An HTTP/2 server of ostrya takes a header list of at most
/// 32 KiB. The list counts the base path, the other header fields, and
/// 32 bytes for each field. So a target that the client accepts fits, with
/// 16 KiB left for the base path and the other fields.
const MAX_REFS_TARGET: usize = 16 * 1024;

/// The key of each pair of the query of a ref listing.
const PREFIX_KEY: &str = "prefix=";

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
/// The enum has no common `get`. A caller that reads the raw files of the
/// remote matches on the variant: [`Fetcher::fetch`] for
/// [`Http`](PullSession::Http), and [`StreamSession::get`] for
/// [`Stream`](PullSession::Stream).
pub enum PullSession {
    /// The fetcher of an HTTP remote.
    Http(Fetcher),
    /// A stream session, over ssh or over a pair of byte streams.
    Stream(StreamSession),
}

impl PullSession {
    /// Opens a stream session over a pair of byte streams.
    ///
    /// The call is [`StreamSession::over_stream`], and the result is
    /// [`PullSession::Stream`].
    ///
    /// # Errors
    ///
    /// The errors of [`StreamSession::over_stream`].
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
    /// order. A file that the remote does not serve is `None`. Each file has a
    /// cap of 64 MiB.
    ///
    /// Over HTTP, the call asks for `summary.sig` and then for `summary`, at
    /// [`Priority::High`]. The signature covers the summary that follows it.
    /// In the other order, a summary can pair with the signature of a summary
    /// that the remote replaced before. A 404 is a file that the remote does
    /// not serve. If a body fails in transit, the call fetches it again, by
    /// the rules of [`Fetcher::refetching`].
    ///
    /// Over a stream session, the two `Get` calls are in flight together, in
    /// the same order.
    ///
    /// The buffer of each file gets the size that the remote states for it,
    /// within the cap. Each read goes into a chunk of at most 128 KiB.
    ///
    /// # Errors
    ///
    /// - [`Error::Fetch`] if an HTTP request fails after its retries, or if
    ///   the remote answers with a status other than 200 and 404. A stated
    ///   length over the cap is
    ///   [`FetchTooLarge`](ostrya_fetch::Error::FetchTooLarge), and a 304 is
    ///   [`Fetch`](ostrya_fetch::Error::Fetch).
    /// - [`Error::Io`] if the read of an HTTP body fails.
    /// - The errors of [`StreamSession::get`] over a stream session. A stated
    ///   length over the cap is [`Error::LimitExceeded`].
    /// - The error of the session that a failed read of a stream body
    ///   carries.
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

    /// Reads the ref listing of `prefixes` from the remote.
    ///
    /// The listing is a summary of the refs under `refs/heads` that the
    /// prefixes select, built by the server for this request. Each prefix is
    /// a ref name. A prefix selects the ref of that name and each ref below
    /// it. An empty list selects all refs. The listing has a cap of
    /// [`MAX_REF_LISTING`] bytes.
    ///
    /// Before it sends a request, the call removes duplicate prefixes and each
    /// prefix that another prefix covers, so `a` removes `a/b` and keeps `ab`.
    /// The prefixes that stay keep the order of their first appearance. At
    /// most [`MAX_REF_PREFIXES`](crate::proto::MAX_REF_PREFIXES) prefixes can
    /// stay. These rules apply to both transports.
    ///
    /// Over HTTP, the call sends a `GET` of `_ostrya/refs/v1` under the base
    /// URL of each mirror, at [`Priority::High`]. Each prefix that stays goes
    /// into the query as one `prefix=VALUE` pair, and `&` separates the
    /// pairs. The value is the prefix with each byte outside `A-Z`, `a-z`,
    /// `0-9`, `-`, `.`, `_`, and `~` written as `%XX`, `/` included. An empty
    /// list sends no query. The request target that the call builds, from
    /// `_ostrya/refs/v1` to the end of the query, is at most 16 KiB. The base
    /// path of the mirror comes before it on the wire.
    ///
    /// A 404 is a remote that serves no ref listing, for example a static
    /// file server, and the call returns `None`. If a body fails in transit,
    /// the call fetches it again, by the rules of [`Fetcher::refetching`].
    /// The buffer gets the size that the remote states, within the cap.
    ///
    /// An ostrya server answers 503 while it builds too many listings. The
    /// fetcher retries a 503 with its backoff, and does not read
    /// `Retry-After`. A 503 after the retries is [`Error::Fetch`]. Of a static
    /// mirror beside a busy ostrya server, the fetcher keeps the 404 of the
    /// static mirror from the first round and asks only the busy server
    /// again. If the busy server answers 200 in a later round, the call
    /// returns `Some`. The call gives `None` only if the busy server answers
    /// 503 to each retry, and only after the full backoff, because a 404 has
    /// priority over a 503.
    ///
    /// Over a stream session, the call is [`StreamSession::list_refs`], in
    /// the pipeline with the `get` calls. It returns `Some` with the bytes of
    /// the listing. The buffer gets the size that the server states, within
    /// the cap.
    ///
    /// Each read goes into a chunk of at most 128 KiB. No signature covers
    /// the listing, and the call checks none.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if a prefix is not a ref name, or if more
    ///   than [`MAX_REF_PREFIXES`](crate::proto::MAX_REF_PREFIXES) prefixes
    ///   stay. The call sends no request.
    /// - [`Error::InvalidInput`] over HTTP if the request target is longer
    ///   than 16 KiB. The call sends no request.
    /// - [`Error::Fetch`] over HTTP if a request fails after its retries, or
    ///   if the remote answers with a status other than 200 and 404. A stated
    ///   length over the cap is
    ///   [`FetchTooLarge`](ostrya_fetch::Error::FetchTooLarge). A server that
    ///   refuses the request gives
    ///   [`HttpStatus`](ostrya_fetch::Error::HttpStatus), for example 400 for
    ///   a prefix that it refuses, 414 or 431 for a target that is too long
    ///   for it, and 503 for a server that stays busy.
    /// - [`Error::Io`] over HTTP if the read of the body fails. A body that
    ///   grows past the cap has the kind
    ///   [`FileTooLarge`](std::io::ErrorKind::FileTooLarge).
    /// - The errors of [`StreamSession::list_refs`] over a stream session. A
    ///   stated length over the cap is [`Error::LimitExceeded`], and a listing
    ///   that the server refuses for its cap is also [`Error::LimitExceeded`].
    /// - The error of the session that a failed read of a stream body
    ///   carries.
    pub async fn fetch_refs(&self, prefixes: &[&str]) -> Result<Option<Vec<u8>>> {
        match self {
            PullSession::Http(fetcher) => {
                let prefixes = reduce_prefixes(prefixes)?;
                let query = refs_query(&prefixes)?;
                let request = match &query {
                    Some(query) => FetchRequest::path_query(REFS_PATH, query),
                    None => FetchRequest::path(REFS_PATH),
                };
                fetch_optional(fetcher, request, MAX_REF_LISTING).await
            }
            PullSession::Stream(session) => {
                let body = session.list_refs(prefixes, MAX_REF_LISTING).await?;
                read_body(body, MAX_REF_LISTING).await.map(Some)
            }
        }
    }

    /// Returns the number of requests that the session keeps in flight at one
    /// time, at least 1.
    ///
    /// For HTTP, it is [`Fetcher::max_outstanding`]. For a stream session, it
    /// is [`StreamSessionOptions::max_outstanding`] of its open, 8 if the
    /// options give no number.
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
    /// The errors of [`StreamSession::finish`].
    pub async fn finish(self) -> Result<()> {
        match self {
            PullSession::Http(_) => Ok(()),
            PullSession::Stream(session) => session.finish().await,
        }
    }
}

/// Returns the query of a ref listing of `prefixes`, or `None` for an empty
/// list.
///
/// Each prefix is one `prefix=VALUE` pair, and `&` separates the pairs. The
/// value is the prefix with each byte outside the unreserved set of URIs
/// written as `%XX`, in upper case.
///
/// # Errors
///
/// [`Error::InvalidInput`] if the request target, [`REFS_PATH`] with `?` and
/// the query, is longer than [`MAX_REFS_TARGET`]. The function measures the
/// target before it builds the query.
fn refs_query(prefixes: &[&str]) -> Result<Option<String>> {
    if prefixes.is_empty() {
        return Ok(None);
    }
    let len = prefixes
        .iter()
        .map(|prefix| PREFIX_KEY.len() + encoded_len(prefix))
        .sum::<usize>()
        + prefixes.len()
        - 1;
    let target = REFS_PATH.len() + 1 + len;
    if target > MAX_REFS_TARGET {
        return Err(Error::InvalidInput(format!(
            "the request target of the ref listing is {target} bytes, over the limit of \
             {MAX_REFS_TARGET}: ask for fewer or shorter prefixes"
        )));
    }
    let mut query = String::with_capacity(len);
    for (n, prefix) in prefixes.iter().enumerate() {
        if n > 0 {
            query.push('&');
        }
        query.push_str(PREFIX_KEY);
        encode(prefix, &mut query);
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
/// The fetcher refuses a stated `Content-Length` above the cap before it reads
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
/// the read that finds the end of the body. So a buffer filled to its stated
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
    fn a_prefix_is_percent_encoded() {
        let cases = [
            ("a/b", "a%2Fb"),
            ("A-z.0_9~", "A-z.0_9~"),
            ("x y+z", "x%20y%2Bz"),
            ("?#&=%", "%3F%23%26%3D%25"),
            ("é", "%C3%A9"),
        ];
        for (value, encoded) in cases {
            let mut out = String::new();
            encode(value, &mut out);
            assert_eq!(out, encoded);
            assert_eq!(encoded_len(value), encoded.len());
        }
        assert_eq!(refs_query(&[]).unwrap(), None);
        assert_eq!(
            refs_query(&["a/b", "main"]).unwrap().as_deref(),
            Some("prefix=a%2Fb&prefix=main")
        );
    }

    /// The target limit counts `_ostrya/refs/v1`, the `?`, and the query. A
    /// target of exactly the limit passes.
    #[test]
    fn the_target_limit_is_inclusive() {
        let fixed = REFS_PATH.len() + 1 + PREFIX_KEY.len();
        let fits = "a".repeat(MAX_REFS_TARGET - fixed);
        let query = refs_query(&[fits.as_str()]).unwrap().unwrap();
        assert_eq!(REFS_PATH.len() + 1 + query.len(), MAX_REFS_TARGET);
        assert_eq!(query.capacity(), query.len());
        let over = "a".repeat(MAX_REFS_TARGET - fixed + 1);
        let err = refs_query(&[over.as_str()]).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    }
}
