//! The two sources of a pull from a remote: an HTTP remote through the
//! fetcher of the pull, or a pull session over ssh.
//!
//! Both sources serve the same paths under the same size caps. So the pull
//! driver asks for a file by its path and reads the same bytes from either.
//! If an HTTP request fails with a retryable failure, the HTTP source sends
//! it again. `Repo::pull`, under `# Pull over ssh`, and
//! `PullStats::bytes_transferred` state the rules that a caller sees.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use futures_io::AsyncRead;

use crate::error::{Error, Result};
use crate::fetch::{Fetcher, Priority};
use crate::push::{self, PullBody, PullSession};
use crate::summary::{SUMMARY_FILE, SUMMARY_SIG_FILE};

use super::http::{
    CONFIG_FILE, MAX_ROOT_FILE, fetch_optional, fetch_summary, read_whole, ref_request_path,
};

/// The remote a pull reads from.
pub(crate) enum RemoteSource {
    /// An HTTP remote, through the pull's fetcher.
    Http(Fetcher),
    /// A pull session over ssh. The session holds the ssh client, so the
    /// variant boxes it.
    Ssh(Box<SshSource>),
}

/// A pull session over ssh, and the counters that get the byte count of each
/// body.
pub(crate) struct SshSource {
    session: PullSession,
    transferred: Vec<Arc<AtomicU64>>,
}

/// The files at the root of the remote that a pull reads first.
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
            None => {
                source
                    .read_optional(CONFIG_FILE, Priority::High, MAX_ROOT_FILE)
                    .await
            }
        }
    }
}

impl RemoteSource {
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
        match self {
            RemoteSource::Http(fetcher) => fetch_optional(fetcher, path, priority, cap).await,
            RemoteSource::Ssh(ssh) => ssh.read_optional(path, cap).await,
        }
    }

    /// Reads the `summary.sig` and the `summary` of the remote, and over ssh
    /// also its `config`.
    ///
    /// An absent file is `None`. The source asks for the files in the order
    /// of the `ostree` command. The ssh source keeps the three requests in
    /// flight together.
    pub(crate) async fn root_files(&self) -> Result<RootFiles> {
        match self {
            RemoteSource::Http(fetcher) => {
                let (summary, signature) = fetch_summary(fetcher).await?;
                Ok(RootFiles {
                    summary,
                    signature,
                    config: None,
                })
            }
            RemoteSource::Ssh(ssh) => {
                let ((signature, summary), config) = futures_lite::future::zip(
                    futures_lite::future::zip(
                        ssh.read_optional(SUMMARY_SIG_FILE, MAX_ROOT_FILE),
                        ssh.read_optional(SUMMARY_FILE, MAX_ROOT_FILE),
                    ),
                    ssh.read_optional(CONFIG_FILE, MAX_ROOT_FILE),
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
    /// the order of the `ostree` command. The ssh source keeps the two
    /// requests in flight together.
    pub(crate) async fn summary_files(&self) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        match self {
            RemoteSource::Http(fetcher) => fetch_summary(fetcher).await,
            RemoteSource::Ssh(ssh) => {
                let (signature, summary) = futures_lite::future::zip(
                    ssh.read_optional(SUMMARY_SIG_FILE, MAX_ROOT_FILE),
                    ssh.read_optional(SUMMARY_FILE, MAX_ROOT_FILE),
                )
                .await;
                Ok((summary?, signature?))
            }
        }
    }

    /// Returns the path of the remote ref `name`.
    ///
    /// An HTTP request takes the path percent-encoded. The ssh source takes
    /// the name as written, because its `Get` carries no escape.
    pub(crate) fn ref_path(&self, name: &str) -> String {
        match self {
            RemoteSource::Http(_) => ref_request_path(name),
            RemoteSource::Ssh(_) => format!("refs/heads/{name}"),
        }
    }

    /// Ends the source with `result`, the result of the pull so far.
    ///
    /// The ssh source closes the input of the server and waits for the ssh
    /// client. If the pull succeeded and the session end fails, the function
    /// returns that error as [`Error::Push`].
    ///
    /// A failure of the pull can come from the session. If the session end
    /// then fails too, the function returns the error of the session end.
    /// That error carries the exit status of an ssh client that failed with an
    /// I/O error. The function returns any other failure unchanged.
    pub(crate) async fn finish<T>(self, result: Result<T>) -> Result<T> {
        match self {
            RemoteSource::Http(_) => result,
            RemoteSource::Ssh(ssh) => {
                let ended = ssh.session.finish().await;
                match (result, ended) {
                    (Ok(value), ended) => ended.map(|()| value).map_err(Error::Push),
                    (Err(Error::Push(_)), Err(ended)) => Err(Error::Push(ended)),
                    (Err(e), _) => Err(e),
                }
            }
        }
    }
}

impl SshSource {
    /// Creates a source over `session`.
    ///
    /// The source adds the byte count of each body to each counter in
    /// `transferred`.
    pub(crate) fn new(session: PullSession, transferred: Vec<Arc<AtomicU64>>) -> SshSource {
        SshSource {
            session,
            transferred,
        }
    }

    /// Asks for the file at `path`, with a body of at most `cap` bytes.
    ///
    /// The result is `None` if the server does not serve the path.
    pub(crate) async fn get(&self, path: &str, cap: u64) -> Result<Option<Counted<'_>>> {
        Ok(self.session.get(path, cap).await?.map(|body| Counted {
            body,
            sinks: &self.transferred,
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

/// The body of one reply of the ssh source.
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

/// Returns the session error that a failed body read carries, as
/// [`Error::Push`].
///
/// If a body fails, it gives an `io::Error` that carries the error of the
/// session. A reader above the body passes that `io::Error` up as its own
/// failure. This function returns any other error unchanged.
pub(crate) fn session_error(error: Error) -> Error {
    match error {
        Error::Io(io) => match io.downcast::<push::Error>() {
            Ok(e) => Error::Push(e),
            Err(io) => Error::Io(io),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use futures_lite::io::Cursor;

    use super::*;
    use crate::push::proto::{
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
            let session = PullSession::over_stream(
                Cursor::new(input),
                futures_lite::io::sink(),
                Default::default(),
            )
            .await
            .unwrap();
            let source = SshSource::new(session, Vec::new());
            source.read_optional("summary", 1 << 20).await.unwrap()
        })
        .unwrap();
        assert_eq!(out, body);
        assert_eq!(out.capacity(), body.len());
    }
}
