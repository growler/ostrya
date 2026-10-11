//! The session of a pull over either transport: the HTTP fetcher or a stream
//! session.

use std::io;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::AsyncReadExt;
use ostrya_fetch::{FetchRequest, Fetched, Fetcher, Priority};

use super::pull::{StreamSession, StreamSessionOptions};
use crate::error::{Error, Result};

/// The cap on the `summary` and the `summary.sig` that
/// [`PullSession::fetch_summary`] reads: 64 MiB.
const MAX_SUMMARY_FILE: u64 = 64 * 1024 * 1024;

/// The largest chunk of one read of a body: 128 KiB.
const READ_CHUNK: usize = 128 * 1024;

/// The path of the summary at the repository root.
const SUMMARY_FILE: &str = "summary";

/// The path of the signature of the summary at the repository root.
const SUMMARY_SIG_FILE: &str = "summary.sig";

/// The session of a pull: the HTTP fetcher of a remote, or a stream session.
///
/// [`connect`](PullSession::connect) opens a session to an
/// [`Endpoint`](crate::transport::Endpoint), and
/// [`over_stream`](PullSession::over_stream) opens one over a pair of byte
/// streams. The session is `Send + Sync`.
/// [`fetch_summary`](PullSession::fetch_summary) takes `&self`, so the session
/// stays usable after the read.
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
                let signature = fetch_optional(fetcher, SUMMARY_SIG_FILE).await?;
                let summary = fetch_optional(fetcher, SUMMARY_FILE).await?;
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

/// Fetches `path` whole under [`MAX_SUMMARY_FILE`], or returns `None` if the
/// remote answers 404.
async fn fetch_optional(fetcher: &Fetcher, path: &str) -> Result<Option<Vec<u8>>> {
    match fetch_whole(fetcher, path).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::Fetch(ostrya_fetch::Error::HttpStatus { status: 404, .. })) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Fetches `path` whole under [`MAX_SUMMARY_FILE`].
///
/// The fetcher refuses a stated `Content-Length` above the cap before it reads
/// the body, and it stops a body that passes the cap. If a body fails in
/// transit, the function fetches it again from the start, into a new buffer,
/// while the retry count of the fetcher has a repeat left.
async fn fetch_whole(fetcher: &Fetcher, path: &str) -> Result<Vec<u8>> {
    let mut refetch = fetcher.refetching(FetchRequest {
        priority: Priority::High,
        max_size: Some(MAX_SUMMARY_FILE),
        ..FetchRequest::path(path)
    });
    loop {
        let Fetched::Body(body) = refetch.fetch().await.map_err(Error::Fetch)? else {
            return Err(Error::Fetch(ostrya_fetch::Error::Fetch(format!(
                "{path}: the remote answered 304 to an unconditional request"
            ))));
        };
        let declared = body.content_length();
        match read_whole(body, declared).await {
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
    let declared = body.len();
    match read_whole(body, declared).await {
        Ok(out) => Ok(Some(out)),
        // A failed read of a body carries the error of the session.
        Err(e) => Err(e.downcast::<Error>().unwrap_or_else(Error::Io)),
    }
}

/// Reads `body` to its end into one buffer.
///
/// The size of the buffer comes from `declared`, the stated length, within
/// [`MAX_SUMMARY_FILE`]. Each read goes into a chunk of at most
/// [`READ_CHUNK`] bytes, also the read that finds the end of the body. So a
/// buffer filled to its stated length does not grow.
async fn read_whole<R: AsyncRead + Unpin>(
    mut body: R,
    declared: Option<u64>,
) -> io::Result<Vec<u8>> {
    let declared = usize::try_from(declared.unwrap_or(0).min(MAX_SUMMARY_FILE)).unwrap_or(0);
    let mut out = Vec::with_capacity(declared);
    let mut chunk = vec![0u8; declared.saturating_add(1).clamp(4096, READ_CHUNK)];
    loop {
        let n = body.read(&mut chunk).await?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&chunk[..n]);
    }
}
