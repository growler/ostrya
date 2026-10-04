//! One push session over a pair of streams: the receive side of the push wire
//! protocol.

use std::io;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::{BufReader, BufWriter};
use ostrya_core::ObjectName;

use super::ReceivePolicy;
use super::core::SessionCore;
use crate::error::{Error, Result};
use crate::push::proto::{CommitRequest, FrameReader, FrameWriter, Hello, Message, ObjectHeader};
use crate::push::{self, RefOutcome};
use crate::repo::Repo;
use crate::transaction::TransactionStats;

/// The buffer size of each direction of the session stream. A read or a write
/// at least this long passes through to the stream with no copy.
pub(super) const STREAM_BUFFER: usize = 64 * 1024;

/// The result of a push session that committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveReport {
    /// One outcome for each ref update, in the order of the `Commit` message.
    pub refs: Vec<RefOutcome>,
    /// The statistics of the session transaction.
    pub stats: TransactionStats,
    /// The steps after the transaction commit that failed. The refs are
    /// written, and the client is not told of these failures.
    pub warnings: Vec<ReceiveWarning>,
}

/// A step after the transaction commit of a session that failed. The step
/// does not undo the commit or the ref writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveWarning {
    /// The step that failed.
    pub step: ReceiveStep,
    /// What failed, for a human.
    pub message: String,
}

/// The steps after the transaction commit of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveStep {
    /// The build of the regenerated summary.
    SummaryBuild,
    /// The signature of the regenerated summary with a key of the policy.
    SummarySign,
    /// The write of the regenerated summary and of its signatures.
    SummaryWrite,
    /// The removal of the partial marker of one commit of the session. Each
    /// commit whose marker stays gets one warning.
    PartialMarker,
    /// The send of `CommitReply` to the client.
    ReplyNotDelivered,
}

/// How a session failed.
pub(super) enum Failure {
    /// A failure with a wire code. The session sends it to the peer, and the
    /// caller gets it as [`Error::Push`].
    Wire(push::Error),
    /// A failure on the server side. The session sends it to the peer as
    /// `internal`, and the caller gets it as it is.
    Internal(Error),
    /// A failure the session does not report to the peer: an error of the
    /// stream, an end of file, or an abort by the client.
    Silent(Error),
}

/// A codec error of the reader: an error of the stream is silent, and every
/// other error carries its wire code.
pub(super) fn codec(error: push::Error) -> Failure {
    match error {
        push::Error::Io(e) => Failure::Silent(Error::Io(e)),
        other => Failure::Wire(other),
    }
}

pub(super) fn aborted() -> Failure {
    Failure::Silent(Error::Push(push::Error::Aborted))
}

pub(super) fn out_of_order(msg: &Message) -> Failure {
    Failure::Wire(push::Error::Protocol(format!(
        "{:?} is out of order",
        msg.kind()
    )))
}

/// The next message of `reader`. An end of file at a frame boundary is silent.
pub(super) async fn next<R: AsyncRead + Unpin>(
    reader: &mut FrameReader<R>,
) -> std::result::Result<Message, Failure> {
    match reader.read_message().await {
        Ok(Some(msg)) => Ok(msg),
        Ok(None) => Err(Failure::Silent(Error::Io(
            io::ErrorKind::UnexpectedEof.into(),
        ))),
        Err(e) => Err(codec(e)),
    }
}

impl Repo {
    /// Run one push session: read the messages of a client from `input`, and
    /// write the replies to `output`.
    ///
    /// The session opens a transaction at `Hello`, which holds the repository
    /// lock shared, under `[core] lock-timeout-secs`, until the session ends. A
    /// repository with `[core] locking=false` refuses the session with the code
    /// `locking-disabled`, and a `bare-split-xattrs` repository with
    /// `mode-refused`. A `bare` repository refuses the session with
    /// `mode-refused` unless the process runs as root, because only root can
    /// store the owner of each file. A `Hello` with `one-way` true is
    /// `protocol`: it opens a one-way stream, which
    /// [`Repo::receive_stream`] reads.
    ///
    /// `Have` gets one bit for each object: whether the repository or the
    /// session holds it. The object stream stages each object in the
    /// transaction after it checks its checksum and the content rules of the
    /// repository mode and of `policy`. An object the repository or the session
    /// already holds is read, checked, and dropped. A detached metadata object
    /// is kept in the session. The detached metadata of the session has one
    /// byte cap for the whole session, [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE),
    /// and the read that takes the session past it is `limit-exceeded`.
    ///
    /// `Commit` runs the checks of the ref updates: the name, the rule, and the
    /// bindings of each update, the completeness of the tree of each commit of
    /// the session, and the signature check of each rule. A detached metadata
    /// object for a commit that is not a commit of the session is `protocol`.
    /// It then makes the staged objects durable, and at the same time it signs
    /// each new commit with each server key of the rules of its updates, each
    /// key once. A key that already signed the commit makes no signature. It
    /// takes the update lock and reads the refs again. A ref that is an
    /// alias, and a ref path that a ref write cannot replace, are `ref-denied`.
    /// It checks each update against the state it expects, for a delete, and
    /// for a fast-forward. It merges the incoming detached metadata into the
    /// stored dicts. Where a stored dict changed since the read before the
    /// lock, it drops each server signature whose key already signed the
    /// commit in the new merged dict. It writes the refs that change, and
    /// commits the transaction under the lock. Where the policy regenerates the summary and a ref changes,
    /// the transaction of a repository with a collection id also writes the
    /// refreshed anchor commit on `ostree-metadata`. The first failed check
    /// ends the session, and nothing is published. The commits of the session
    /// are the commits the session staged and the new commits of the updates.
    /// A commit the client sends that the repository holds already is not
    /// staged, so it is a commit of the session only where an update names it.
    ///
    /// After the commit the partial marker of each commit of the session is
    /// removed. Where the policy regenerates the summary and a ref changed, the
    /// summary is built, signed from the bytes just built with each summary
    /// key, and written, still under the lock. The lock is then released, and
    /// `CommitReply` goes to the client. The call then returns the report. A
    /// step after the commit that fails does not undo the commit: it adds a
    /// [`ReceiveWarning`] to the report, and the client is not told. A
    /// `CommitReply` that cannot be sent is such a step,
    /// [`ReceiveStep::ReplyNotDelivered`], so the call returns `Ok` also when
    /// the client did not get the reply.
    ///
    /// Each failure is sent to the peer as an `Error` message and returned. A
    /// failure with a wire code returns as [`Error::Push`]. A failure on the
    /// server side goes to the peer as `internal` and returns as the error it
    /// is. An error of `input`, an end of file, an `Abort` of the client, and an
    /// abandoned object send nothing. An `Abort` and an abandoned object return
    /// [`push::Error::Aborted`], and an end of file at a frame boundary returns
    /// an [`Error::Io`] of kind `UnexpectedEof`. The call does not close
    /// `output`.
    pub async fn receive<R, W>(
        &self,
        input: R,
        output: W,
        policy: &ReceivePolicy,
    ) -> Result<ReceiveReport>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let mut session = Session {
            repo: self,
            policy,
            reader: FrameReader::new(BufReader::with_capacity(STREAM_BUFFER, input)),
            writer: FrameWriter::new(BufWriter::with_capacity(STREAM_BUFFER, output)),
            core: None,
            buf: Vec::new(),
        };
        let failure = match session.run().await {
            Ok(report) => return Ok(report),
            Err(failure) => failure,
        };
        let error = match failure {
            Failure::Wire(e) => {
                session.send_error(e.to_message()).await;
                Error::Push(e)
            }
            Failure::Internal(e) => {
                let msg = push::Error::Internal(e.to_string()).to_message();
                session.send_error(msg).await;
                e
            }
            Failure::Silent(e) => e,
        };
        // Dropping the transaction removes its staging directory and releases
        // the repository lock.
        drop(session);
        Err(error)
    }
}

struct Session<'a, R, W> {
    repo: &'a Repo,
    policy: &'a ReceivePolicy,
    reader: FrameReader<BufReader<R>>,
    writer: FrameWriter<BufWriter<W>>,
    /// The session, open from `Hello` on.
    core: Option<SessionCore<&'a ReceivePolicy>>,
    /// The chunk buffer of the object stream, shared by every object.
    buf: Vec<u8>,
}

impl<R, W> Session<'_, R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    /// Run the session until it commits or fails.
    async fn run(&mut self) -> std::result::Result<ReceiveReport, Failure> {
        match next(&mut self.reader).await? {
            Message::Hello(hello) => self.hello(hello).await?,
            other => return Err(out_of_order(&other)),
        }
        loop {
            match next(&mut self.reader).await? {
                Message::Have(names) => self.have(names).await?,
                Message::ObjectHeader(header) => self.objects(Some(header)).await?,
                Message::ObjectsEnd => self.objects(None).await?,
                Message::Commit(request) => return self.commit(request).await,
                Message::Abort => return Err(aborted()),
                other => return Err(out_of_order(&other)),
            }
        }
    }

    async fn reply(&mut self, msg: &Message) -> std::result::Result<(), Failure> {
        let sent = match self.writer.write_message(msg).await {
            Ok(()) => self.writer.flush().await,
            Err(e) => Err(e),
        };
        sent.map_err(|e| match e {
            push::Error::Io(e) => Failure::Silent(Error::Io(e)),
            // A reply the codec refuses is a fault of the server, whatever
            // code the codec gives it.
            other => Failure::Wire(push::Error::Internal(other.to_string())),
        })
    }

    /// Send an `Error` message. A failure to send it is ignored, because the
    /// peer can be gone.
    async fn send_error(&mut self, msg: push::proto::ErrorMessage) {
        if self
            .writer
            .write_message(&Message::Error(msg))
            .await
            .is_ok()
        {
            let _ = self.writer.flush().await;
        }
    }

    fn core(&self) -> &SessionCore<&ReceivePolicy> {
        self.core.as_ref().expect("the session is open after Hello")
    }

    async fn hello(&mut self, hello: Hello) -> std::result::Result<(), Failure> {
        let (core, reply) = SessionCore::open(self.repo.clone(), self.policy, 1, hello).await?;
        self.core = Some(core);
        self.reply(&Message::HelloReply(reply)).await
    }

    async fn have(&mut self, names: Vec<ObjectName>) -> std::result::Result<(), Failure> {
        let reply = self.core().have(names).await?;
        self.reply(&Message::HaveReply(reply)).await
    }

    /// Read one object stream and reply `ObjectsReply`. `first` is `None` for
    /// a stream of no object.
    async fn objects(&mut self, first: Option<ObjectHeader>) -> std::result::Result<(), Failure> {
        let Session {
            reader, core, buf, ..
        } = self;
        let core = core.as_ref().expect("the session is open after Hello");
        let reply = core.objects(first, reader, buf).await?;
        self.reply(&Message::ObjectsReply(reply)).await
    }

    /// Commit the session and reply `CommitReply`. A reply that cannot be
    /// sent is a warning of the report.
    async fn commit(
        &mut self,
        request: CommitRequest,
    ) -> std::result::Result<ReceiveReport, Failure> {
        let core = self.core.take().expect("the session is open after Hello");
        let mut report = core.finish(request).await?;
        let reply = Message::CommitReply(report.refs.clone());
        let sent = match self.writer.write_message(&reply).await {
            Ok(()) => self.writer.flush().await,
            Err(e) => Err(e),
        };
        if let Err(e) = sent {
            report.warnings.push(ReceiveWarning {
                step: ReceiveStep::ReplyNotDelivered,
                message: e.to_string(),
            });
        }
        Ok(report)
    }
}

/// The future of a session can run on a thread pool.
const _: fn() = || {
    fn assert_send<T: Send>(_: T) {}
    let _ = |repo: &Repo, policy: &ReceivePolicy| {
        assert_send(repo.receive(futures_lite::io::empty(), futures_lite::io::sink(), policy))
    };
};
