//! The two sources of a pull from a remote: an HTTP remote through the
//! fetcher of the pull, or a stream session over ssh or over a pair of
//! streams.
//!
//! Both sources serve the same paths under the same size caps. So the pull
//! driver asks for a file by its path and reads the same bytes from either.
//! If an HTTP request fails with a retryable failure, the HTTP source sends
//! it again. `Repo::pull`, under `# Pull over ssh`, and
//! `PullStats::bytes_transferred` state the rules that a caller sees.
//!
//! The HTTP source of a pull from an `s3://` address also holds a bucket
//! client. It reads `summary.sig`, `summary`, and `config` through the
//! bucket client, which reads the S3 error document of a failed request. So a
//! wrong key, a bucket of another region, and an absent bucket give an S3
//! error, and an absent bucket does not read as a repository with no
//! summary. The bucket client adds the byte count of each body to the
//! counters of the source, as the fetcher of the session does.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use futures_io::AsyncRead;
use ostrya_core::RefSelector;

use crate::error::{Error, Result};
use crate::fetch::{Fetcher, Priority};
#[cfg(feature = "s3")]
use crate::remote::s3::Bucket;
use crate::remote::{self, PullBody, PullSession, StreamSession};
use crate::summary::{SUMMARY_FILE, SUMMARY_SIG_FILE};

use super::http::{CONFIG_FILE, MAX_ROOT_FILE, fetch_optional, read_whole, ref_request_path};

/// The session of a pull, and the bucket client of a pull from an `s3://`
/// address.
pub(crate) struct Connection {
    /// The session.
    pub(crate) session: PullSession,
    /// The client of the bucket repository, which reads the files at the
    /// root of the remote. It is `None` for each other remote.
    #[cfg(feature = "s3")]
    pub(crate) bucket: Option<Bucket>,
}

impl From<PullSession> for Connection {
    /// Returns the connection of `session` with no bucket client.
    fn from(session: PullSession) -> Connection {
        Connection {
            session,
            #[cfg(feature = "s3")]
            bucket: None,
        }
    }
}

/// The remote a pull reads from: the session of the pull, and the counters of
/// the transferred bytes.
pub(crate) struct RemoteSource {
    /// The session. The fetcher of an HTTP session adds the byte count of each
    /// body to the counters itself.
    session: PullSession,
    /// The counters that get the byte count of each body of a stream session.
    transferred: Vec<Arc<AtomicU64>>,
    /// The client of the bucket repository of a pull from an `s3://`
    /// address. It reads `summary.sig`, `summary`, and `config`, and adds the
    /// byte count of each body to the counters of the source itself.
    #[cfg(feature = "s3")]
    bucket: Option<Bucket>,
}

/// The transport of a remote source, for one request.
pub(crate) enum Transfer<'a> {
    /// An HTTP remote, through the counted fetcher of the pull.
    Http(&'a Fetcher),
    /// A stream session, over ssh or over a pair of streams.
    Stream(StreamSource<'a>),
}

/// A stream session, and the counters that get the byte count of each body.
pub(crate) struct StreamSource<'a> {
    session: &'a StreamSession,
    transferred: &'a [Arc<AtomicU64>],
}

/// The files at the root of the remote that a pull reads first.
///
/// The default holds no summary and no signature, and reads the remote
/// `config` on demand.
#[derive(Default)]
pub(crate) struct RootFiles {
    pub(crate) summary: Option<Vec<u8>>,
    pub(crate) signature: Option<Vec<u8>>,
    /// The remote `config`, if the source read it together with the summary.
    config: Option<Option<Vec<u8>>>,
}

impl RootFiles {
    /// Returns the remote `config`, or `None` if the remote serves none.
    ///
    /// The HTTP source reads the `config` here, after the pull checks the
    /// summary.
    pub(crate) async fn config(&mut self, source: &RemoteSource) -> Result<Option<Vec<u8>>> {
        match self.config.take() {
            Some(config) => Ok(config),
            None => source.read_root(CONFIG_FILE).await,
        }
    }
}

impl RemoteSource {
    /// Creates a source over the session of `connection`, which adds the byte
    /// count of each body to each counter in `transferred`.
    ///
    /// An HTTP session gets a handle on its fetcher with the counters. A
    /// stream session adds the count of each body through [`Counted`]. The
    /// bucket client of the connection gets the counters through
    /// `Bucket::counted`.
    pub(crate) fn new(connection: Connection, transferred: Vec<Arc<AtomicU64>>) -> RemoteSource {
        let session = match connection.session {
            PullSession::Http(fetcher) => PullSession::Http(fetcher.counted(transferred.clone())),
            stream => stream,
        };
        RemoteSource {
            session,
            #[cfg(feature = "s3")]
            bucket: connection
                .bucket
                .map(|bucket| bucket.counted(transferred.clone())),
            transferred,
        }
    }

    /// Returns the transport of the source.
    pub(crate) fn transfer(&self) -> Transfer<'_> {
        match &self.session {
            PullSession::Http(fetcher) => Transfer::Http(fetcher),
            PullSession::Stream(session) => Transfer::Stream(StreamSource {
                session,
                transferred: &self.transferred,
            }),
        }
    }

    /// Returns the number of requests that the session keeps in flight at one
    /// time, at least 1.
    pub(crate) fn max_outstanding(&self) -> usize {
        self.session.max_outstanding()
    }

    /// Reads the file at `path` whole, under `cap`, or returns `None` if the
    /// remote does not serve it.
    ///
    /// `priority` sets the order of an HTTP request at the gate of the
    /// fetcher.
    pub(crate) async fn read_optional(
        &self,
        path: &str,
        priority: Priority,
        cap: u64,
    ) -> Result<Option<Vec<u8>>> {
        match self.transfer() {
            Transfer::Http(fetcher) => fetch_optional(fetcher, path, priority, cap).await,
            Transfer::Stream(stream) => stream.read_optional(path, cap).await,
        }
    }

    /// Reads the file at `path` at the root of the remote whole, under
    /// [`MAX_ROOT_FILE`], or returns `None` if the remote does not serve it.
    ///
    /// The bucket client reads the file if the source has one. Else the call
    /// is [`read_optional`](RemoteSource::read_optional) at
    /// [`Priority::High`].
    pub(crate) async fn read_root(&self, path: &str) -> Result<Option<Vec<u8>>> {
        #[cfg(feature = "s3")]
        if let Some(bucket) = &self.bucket {
            let object = bucket.get(path, MAX_ROOT_FILE).await.map_err(http_error)?;
            return Ok(object.map(|object| object.bytes));
        }
        self.read_optional(path, Priority::High, MAX_ROOT_FILE)
            .await
    }

    /// Reads the `summary` and the `summary.sig` of the remote over HTTP.
    ///
    /// The source asks for `summary.sig` first. If the source has a bucket
    /// client, the bucket client reads the two files, and an error of
    /// `summary.sig` stops the read of `summary` and is the error of the call.
    /// If the fetcher also admits two requests at once, the two requests are
    /// in flight together. A source with no bucket client asks for `summary`
    /// after `summary.sig`.
    async fn http_summary_files(&self) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        #[cfg(feature = "s3")]
        if self.bucket.is_some() {
            // The read of `summary` gives its error as a value. So an error of
            // `summary.sig` stops the read of `summary`, and an error of
            // `summary` waits for the result of `summary.sig`.
            let summary = async { Ok::<_, Error>(self.read_root(SUMMARY_FILE).await) };
            let (signature, summary) =
                futures_lite::future::try_zip(self.read_root(SUMMARY_SIG_FILE), summary).await?;
            return Ok((summary?, signature));
        }
        self.session.fetch_summary().await.map_err(http_error)
    }

    /// Reads the `summary.sig` and the `summary` of the remote, and from the
    /// stream source also its `config`.
    ///
    /// An absent file is `None`. The source asks for the files in the order
    /// of the `ostree` command. The stream source keeps the three requests in
    /// flight together. If the fetcher admits two requests at once, the bucket
    /// client keeps the requests of `summary.sig` and `summary` in flight
    /// together.
    pub(crate) async fn root_files(&self) -> Result<RootFiles> {
        match self.transfer() {
            Transfer::Http(_) => {
                let (summary, signature) = self.http_summary_files().await?;
                Ok(RootFiles {
                    summary,
                    signature,
                    config: None,
                })
            }
            Transfer::Stream(stream) => {
                let ((signature, summary), config) = futures_lite::future::zip(
                    futures_lite::future::zip(
                        stream.read_optional(SUMMARY_SIG_FILE, MAX_ROOT_FILE),
                        stream.read_optional(SUMMARY_FILE, MAX_ROOT_FILE),
                    ),
                    stream.read_optional(CONFIG_FILE, MAX_ROOT_FILE),
                )
                .await;
                Ok(RootFiles {
                    signature: signature?,
                    summary: summary?,
                    config: Some(config?),
                })
            }
        }
    }

    /// Reads the `summary` and the `summary.sig` of the remote.
    ///
    /// An absent file is `None`. The source asks for `summary.sig` first, in
    /// the order of the `ostree` command. The stream source keeps the two
    /// requests in flight together. The bucket client does the same if the
    /// fetcher admits two requests at once.
    pub(crate) async fn summary_files(&self) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        match self.transfer() {
            Transfer::Http(_) => self.http_summary_files().await,
            Transfer::Stream(stream) => {
                let (signature, summary) = futures_lite::future::zip(
                    stream.read_optional(SUMMARY_SIG_FILE, MAX_ROOT_FILE),
                    stream.read_optional(SUMMARY_FILE, MAX_ROOT_FILE),
                )
                .await;
                Ok((summary?, signature?))
            }
        }
    }

    /// Reads the ref listing of `refs` and `collections` from the remote, or
    /// returns `None` if the remote serves no ref listing.
    ///
    /// The call is [`PullSession::fetch_refs`], under its cap and its rules.
    /// A stream session always serves the listing.
    pub(crate) async fn ref_listing(
        &self,
        refs: &RefSelector,
        collections: Option<&RefSelector>,
    ) -> Result<Option<Vec<u8>>> {
        self.session
            .fetch_refs(refs, collections)
            .await
            .map_err(http_error)
    }

    /// Returns the path of the remote ref `name`.
    ///
    /// An HTTP request takes the path percent-encoded. The stream source
    /// takes the name as written, because its `Get` carries no escape.
    pub(crate) fn ref_path(&self, name: &str) -> String {
        match self.transfer() {
            Transfer::Http(_) => ref_request_path(name),
            Transfer::Stream(_) => format!("refs/heads/{name}"),
        }
    }

    /// Returns `true` if the source reads the files at the root of the
    /// remote through a bucket client.
    ///
    /// A bucket repository serves no ref listing.
    pub(crate) fn has_bucket(&self) -> bool {
        #[cfg(feature = "s3")]
        return self.bucket.is_some();
        #[cfg(not(feature = "s3"))]
        false
    }

    /// Returns the connection of the source, whose session stays open.
    ///
    /// Over HTTP, the fetcher handle of the session keeps the counters of
    /// the source. The connection keeps the bucket client of the source,
    /// which keeps the counters of the source too. A new source over the
    /// connection adds the counters that its caller gives.
    pub(crate) fn into_connection(self) -> Connection {
        Connection {
            session: self.session,
            #[cfg(feature = "s3")]
            bucket: self.bucket,
        }
    }

    /// Ends the source with `result`, the result of the pull so far.
    ///
    /// The stream source closes the input of the server and, over ssh, waits
    /// for the ssh client. If the pull succeeded and the session end fails,
    /// the function returns that error as [`Error::Remote`].
    ///
    /// A failure of the pull can come from the session. If the session end
    /// then fails too, the function returns the error of the session end.
    /// That error carries the exit status of an ssh client that failed with an
    /// I/O error. The function returns any other failure unchanged.
    pub(crate) async fn finish<T>(self, result: Result<T>) -> Result<T> {
        match self.session {
            PullSession::Http(_) => result,
            PullSession::Stream(session) => {
                let ended = session.finish().await;
                match (result, ended) {
                    (Ok(value), ended) => ended.map(|()| value).map_err(Error::Remote),
                    (Err(Error::Remote(_)), Err(ended)) => Err(Error::Remote(ended)),
                    (Err(e), _) => Err(e),
                }
            }
        }
    }
}

impl<'a> StreamSource<'a> {
    /// Asks for the file at `path`, with a body of at most `cap` bytes.
    ///
    /// The result is `None` if the server does not serve the path.
    pub(crate) async fn get(&self, path: &str, cap: u64) -> Result<Option<Counted<'a>>> {
        Ok(self.session.get(path, cap).await?.map(|body| Counted {
            body,
            sinks: self.transferred,
        }))
    }

    /// Reads the file at `path` whole, under `cap`, or returns `None` if the
    /// server does not serve it.
    ///
    /// The function sizes the buffer from the stated length, which the
    /// session holds to `cap`. A body of its stated length does not grow the
    /// buffer.
    async fn read_optional(&self, path: &str, cap: u64) -> Result<Option<Vec<u8>>> {
        let Some(body) = self.get(path, cap).await? else {
            return Ok(None);
        };
        let declared = body.len();
        let out = read_whole(body, declared, cap)
            .await
            .map_err(|e| session_error(Error::Io(e)))?;
        Ok(Some(out))
    }
}

/// The body of one reply of the stream source.
///
/// The body adds the count of each read to the transferred counts of the
/// pull.
pub(crate) struct Counted<'a> {
    body: PullBody,
    sinks: &'a [Arc<AtomicU64>],
}

impl Counted<'_> {
    /// Returns the length that the server stated for the body.
    pub(crate) fn len(&self) -> Option<u64> {
        self.body.len()
    }
}

impl AsyncRead for Counted<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let n = ready!(Pin::new(&mut me.body).poll_read(cx, buf))?;
        for sink in me.sinks {
            sink.fetch_add(n as u64, Ordering::Relaxed);
        }
        Poll::Ready(Ok(n))
    }
}

/// Returns the error of `ostrya` for an error of an HTTP pull session.
///
/// A fetch error maps as [`From`] maps it, and an I/O error and an invalid
/// input keep their variant. Each other error is [`Error::Remote`].
pub(crate) fn http_error(error: remote::Error) -> Error {
    match error {
        remote::Error::Fetch(e) => Error::from(e),
        remote::Error::Io(e) => Error::Io(e),
        remote::Error::InvalidInput(message) => Error::InvalidInput(message),
        other => Error::Remote(other),
    }
}

/// Returns the session error that a failed body read carries, as
/// [`Error::Remote`].
///
/// If a body fails, it gives an `io::Error` that carries the error of the
/// session. A reader above the body passes that `io::Error` up as its own
/// failure. This function returns any other error unchanged.
pub(crate) fn session_error(error: Error) -> Error {
    match error {
        Error::Io(io) => match io.downcast::<remote::Error>() {
            Ok(e) => Error::Remote(e),
            Err(io) => Error::Io(io),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use futures_lite::io::Cursor;

    use super::*;
    use crate::remote::proto::{
        FrameWriter, GetReply, Message, PULL_PROTOCOL_VERSION, PullHelloReply,
    };

    /// Returns the bytes that a server sends for one found reply of `body`
    /// with its stated length, after the reply to `PullHello`.
    fn served(body: &[u8]) -> Vec<u8> {
        ostrya_rt::block_on(async {
            let mut writer = FrameWriter::new(Cursor::new(Vec::new()));
            writer
                .write_message(&Message::PullHelloReply(PullHelloReply {
                    version: PULL_PROTOCOL_VERSION,
                }))
                .await
                .unwrap();
            writer
                .write_message(&Message::GetReply(GetReply {
                    found: true,
                    len: Some(body.len() as u64),
                }))
                .await
                .unwrap();
            writer.write_object_data(body).await.unwrap();
            writer.end_object().await.unwrap();
            writer.into_inner().into_inner()
        })
    }

    /// A body of its stated length lands in a buffer of exactly that
    /// capacity. The read that finds the end of the body does not grow the
    /// buffer.
    #[test]
    fn a_body_of_its_stated_length_is_not_grown() {
        let body: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
        let input = served(&body);
        let out = ostrya_rt::block_on(async {
            let session = StreamSession::over_stream(
                Cursor::new(input),
                futures_lite::io::sink(),
                Default::default(),
            )
            .await
            .unwrap();
            let source = RemoteSource::new(PullSession::Stream(session).into(), Vec::new());
            source
                .read_optional("summary", Priority::High, 1 << 20)
                .await
                .unwrap()
        })
        .unwrap();
        assert_eq!(out, body);
        assert_eq!(out.capacity(), body.len());
    }
}
