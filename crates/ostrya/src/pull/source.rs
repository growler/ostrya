//! Where a pull from a remote reads its files: an HTTP remote through the
//! pull's fetcher, or a pull session over ssh.
//!
//! Both sources serve the same paths under the same size caps, so the pull
//! driver asks for a file by its path and reads the same bytes from either.
//! An HTTP request that fails retryably is sent again inside the HTTP source.
//! The ssh source never sends a request again: a failure ends its session,
//! and the pull with it.
//!
//! The ssh source counts the payload bytes of each body it reads into the
//! transferred count of the pull, where the fetcher counts the bytes of each
//! response body, so the two counts agree for the same files.

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
    /// A pull session over ssh. The session holds the ssh client, so it is
    /// boxed.
    Ssh(Box<SshSource>),
}

/// A pull session over ssh, with the counters it adds the bytes of each body
/// to.
pub(crate) struct SshSource {
    session: PullSession,
    transferred: Vec<Arc<AtomicU64>>,
}

/// The files at the root of the remote that a pull reads first.
pub(crate) struct RootFiles {
    pub(crate) summary: Option<Vec<u8>>,
    pub(crate) signature: Option<Vec<u8>>,
    /// The remote `config`, where the source read it with the summary.
    config: Option<Option<Vec<u8>>>,
}

impl RootFiles {
    /// The remote `config`, `None` where the remote serves none. The HTTP
    /// source reads it here, after the summary is checked.
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
    /// Read the file at `path` whole, under `cap`, or `None` when the remote
    /// does not serve it. `priority` orders an HTTP request at the gate of
    /// the fetcher.
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

    /// The remote's `summary.sig` and `summary`, and over ssh its `config`
    /// too, an absent one as `None`, in the order the tool asks for them. The
    /// ssh source has the three requests in flight together.
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

    /// The path of the remote ref `name`: percent-encoded for an HTTP
    /// request, and as written for the ssh source, whose `Get` carries no
    /// escape.
    pub(crate) fn ref_path(&self, name: &str) -> String {
        match self {
            RemoteSource::Http(_) => ref_request_path(name),
            RemoteSource::Ssh(_) => format!("refs/heads/{name}"),
        }
    }

    /// End the source with `result`, the result of the pull so far.
    ///
    /// The ssh source closes the input of the server and waits for the ssh
    /// client. A failure of the pull that came from the session takes the
    /// error the end of the session gives, which carries the exit status of
    /// an ssh client that failed under an I/O error. Any other failure stands
    /// as it is.
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
    /// A source over `session`, which adds the bytes of each body to each
    /// counter of `transferred`.
    pub(crate) fn new(session: PullSession, transferred: Vec<Arc<AtomicU64>>) -> SshSource {
        SshSource {
            session,
            transferred,
        }
    }

    /// Ask for the file at `path`, whose body is at most `cap` bytes. `None`
    /// is a path the server does not serve.
    pub(crate) async fn get(&self, path: &str, cap: u64) -> Result<Option<Counted<'_>>> {
        Ok(self.session.get(path, cap).await?.map(|body| Counted {
            body,
            sinks: &self.transferred,
        }))
    }

    /// Read the file at `path` whole, under `cap`, or `None` when the server
    /// does not serve it. The buffer is sized from the stated length, which
    /// the session has held to `cap`, and a body of its stated length does
    /// not grow it.
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

/// The body of one reply of the ssh source, which adds each byte it reads to
/// the transferred count of the pull.
pub(crate) struct Counted<'a> {
    body: PullBody,
    sinks: &'a [Arc<AtomicU64>],
}

impl Counted<'_> {
    /// The length the server stated for the body.
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

/// Take back the error of the session that a read of a body carries.
///
/// A body that fails gives an `io::Error` that carries the error of the
/// session, and a reader above it passes that up as its own failure. This
/// puts the error of the session back as [`Error::Push`]. Any other failure
/// stands as it is.
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

    /// The bytes a server sends for one found reply of `body` with its stated
    /// length, after the reply to `PullHello`.
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
    /// capacity: the read that finds the end of the body does not grow it.
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
