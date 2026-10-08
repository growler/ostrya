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
    /// The steps after the transaction commit that failed.
    ///
    /// These failures do not undo the ref writes, and the session does not
    /// report them to the client.
    pub warnings: Vec<ReceiveWarning>,
}

/// A failure of one step after the transaction commit of a session.
///
/// The failure does not undo the transaction commit or the ref writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveWarning {
    /// The step that failed.
    pub step: ReceiveStep,
    /// A message for a human that states what failed.
    pub message: String,
}

/// The steps after the transaction commit of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveStep {
    /// The build of the regenerated summary.
    SummaryBuild,
    /// The signing of the regenerated summary with a key of the policy.
    SummarySign,
    /// The write of the regenerated summary and of its signatures.
    SummaryWrite,
    /// The removal of the partial marker of one commit of the session.
    ///
    /// Each commit whose marker stays gets one warning.
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
    /// A failure that the session does not report to the peer. It is an error
    /// of the stream, an end of file, or an abort by the client.
    Silent(Error),
}

/// Returns the failure of a codec error of the reader. An error of the
/// stream is silent, and every other error carries its wire code.
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

/// Returns the next message of `reader`. An end of file at a frame boundary
/// is silent.
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

/// Methods that receive a push session.
impl Repo {
    /// Runs one push session that reads `input` and writes the replies to
    /// `output`.
    ///
    /// The session reads `Hello`, then any number of `Have` messages and
    /// object streams, and then `Commit`. A message out of this order is
    /// `protocol`. After the transaction commit, the call returns a
    /// [`ReceiveReport`]. The call does not close `output`.
    ///
    /// # Hello
    ///
    /// A `Hello` with `one-way` true is `protocol`. It opens a one-way stream,
    /// which [`Repo::receive_stream`] reads. Then the session runs the checks
    /// of [`check_hello`](super::ReceiveService::check_hello), in the order
    /// that it states. All these checks run before the transaction opens.
    ///
    /// After the checks, the session opens a transaction. The transaction
    /// holds the repository lock shared until the session ends. The wait for
    /// the lock stops at `[core] lock-timeout-secs`. A `bare` repository is
    /// `mode-refused` unless the process runs as root, because only root can
    /// store the owner of each file.
    ///
    /// # Objects
    ///
    /// The reply to a `Have` has one bit for each object. The bit is set if
    /// neither the repository nor the session holds the object.
    ///
    /// An object stream stages each object in the transaction. Before the
    /// stage, the session verifies the checksum of the object and checks the
    /// content rules of the repository mode and of `policy`. The session reads
    /// and verifies an object that the repository or the session holds
    /// already, and then drops it.
    ///
    /// The session keeps each detached metadata object until `Commit`. All the
    /// detached metadata of the session has one byte cap,
    /// [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE). The read that takes
    /// the session past the cap is `limit-exceeded`.
    ///
    /// # Commit
    ///
    /// `Commit` runs the checks of the ref updates in this order:
    ///
    /// 1. The name of each ref (`invalid-ref`) and the form of the message
    ///    (`protocol`).
    /// 2. The size of `CommitReply` (`limit-exceeded`).
    /// 3. Each detached metadata object belongs to a commit of the session
    ///    (`protocol`).
    /// 4. The rule of each update (`ref-denied`).
    /// 5. Each new commit, and the tree of each commit of the session, is
    ///    complete (`missing-objects`).
    /// 6. The ref binding and the collection binding of each new commit
    ///    (`binding-mismatch`).
    /// 7. The signature verification of each rule (`signature-required`).
    ///
    /// [`ReceiveService::commit`](super::ReceiveService::commit) runs the same
    /// checks. The errors section of its doc states the condition of each code.
    /// The first failed check ends the session, and the session publishes
    /// nothing.
    ///
    /// The commits of the session are the commits that the session staged and
    /// the new commits of the updates. The session does not stage a commit
    /// that the client sends and that the repository holds already. That commit
    /// is a commit of the session only if an update names it.
    ///
    /// After the checks, the session makes the staged objects durable. At the
    /// same time, it signs each new commit with each server key of the rules
    /// of its updates, each key once. A key that already signed the commit
    /// makes no signature.
    ///
    /// # Under the update lock
    ///
    /// The session takes the update lock and reads the refs again. These cases
    /// are `ref-denied`:
    ///
    /// - A ref that is an alias.
    /// - A ref path that a ref write cannot replace.
    /// - Two updates where one update names a directory of the other.
    ///
    /// The session then checks that each ref is in the state that its update
    /// expects (`ref-mismatch`). It checks the delete rule (`delete-denied`)
    /// and the fast-forward rule (`non-fast-forward`).
    ///
    /// The session merges the incoming detached metadata into the stored
    /// dicts. A stored dict can change after the read before the lock. In that
    /// case, the session drops each server signature whose key already signed
    /// the commit in the new merged dict. Then it writes the refs that change
    /// and commits the transaction under the lock.
    ///
    /// The transaction commit is not atomic. A failure in it can leave the
    /// detached metadata and some refs written.
    ///
    /// The policy can regenerate the summary of a repository with a
    /// collection id. If a ref then changes, the transaction also writes the
    /// refreshed anchor commit on `ostree-metadata`.
    ///
    /// # After the transaction commit
    ///
    /// The session removes the partial marker of each commit of the session.
    /// If the policy regenerates the summary and a ref changed, the session
    /// builds the summary. It signs the built bytes with each summary key, and
    /// writes the summary. These steps run under the update lock.
    ///
    /// The session then releases the update lock, sends `CommitReply` to the
    /// client, and returns the report. If a step after the transaction commit
    /// fails, the session adds a [`ReceiveWarning`] to the report. The session
    /// does not send the warning to the client.
    ///
    /// If the send of `CommitReply` fails, the warning has the step
    /// [`ReceiveStep::ReplyNotDelivered`], and the call returns `Ok`.
    ///
    /// # Detached metadata merge
    ///
    /// The session merges each incoming detached metadata dict into the dict
    /// that the repository holds for the same commit. The
    /// `detached-metadata-exclude` filter applies to the incoming dict before
    /// the merge. The merged dict holds the stored keys first, in the stored
    /// order. Then it holds each key that only the incoming dict holds, in the
    /// incoming order.
    ///
    /// - Under `ostree.gpgsigs`, `ostree.sign.ed25519`, `ostree.sign.spki`, and
    ///   `ostree.sign.dummy`, the value is the union of the two lists. The
    ///   union holds the stored blobs in the stored order. Then it holds each
    ///   incoming blob that is not byte-equal to a blob already in the list.
    ///   These four keys are the same in each build, whatever the signing
    ///   engines of the build.
    /// - A duplicate blob in the stored list stays. Two byte-equal incoming
    ///   blobs give one blob.
    /// - In a session with hooks, a stored value stays under the key of a host
    ///   entry with [`keep_existing`](super::HostEntry::keep_existing) set. If
    ///   the stored dict does not hold that key, the merge adds the host entry
    ///   at the end, as for each other new key.
    /// - Under each other key, the incoming value replaces the stored value, at
    ///   the position of the stored key.
    /// - A key that only the stored dict holds stays.
    ///
    /// The object stream refuses an incoming dict as `protocol` in these
    /// cases:
    ///
    /// - The dict is not an `a{sv}`.
    /// - The dict holds one key twice.
    /// - The dict holds a signature value that is not an `aay`.
    ///
    /// A merged dict whose serialized form is over
    /// [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) is `limit-exceeded`.
    ///
    /// # Errors
    ///
    /// Each error ends the session. The session sends a wire code to the
    /// client as an `Error` message, and the call returns it inside
    /// [`Error::Push`]. The session sends each other error as `internal`,
    /// except the errors of the stream, which send nothing.
    ///
    /// - [`push::Error::Protocol`] if a message comes out of order.
    /// - At `Hello`, the errors of
    ///   [`ReceiveService::hello`](super::ReceiveService::hello), other than
    ///   `Error::InvalidInput`. These include [`Error::LockTimeout`] for the
    ///   repository lock.
    /// - [`push::Error::LimitExceeded`] if a `Have` holds more than
    ///   [`MAX_HAVE`](crate::push::proto::MAX_HAVE) entries.
    /// - [`push::Error::ChecksumMismatch`] if the bytes of an object do not
    ///   hash to its checksum.
    /// - [`push::Error::ModeRefused`] if an object breaks the content rules of
    ///   the repository mode or of `policy`.
    /// - [`push::Error::LimitExceeded`] if a metadata object is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), or if the header of
    ///   a content object is larger than its limit.
    /// - [`push::Error::LimitExceeded`] if a read passes one of the
    ///   [metadata budgets](super::ReceiveService#metadata-budgets).
    /// - [`push::Error::Protocol`] if the payload of an object is malformed,
    ///   or if bytes follow the end of an object.
    /// - [`push::Error::Protocol`] if two detached metadata objects name the
    ///   same commit, or if an incoming detached metadata dict is malformed.
    /// - The wire code of the frame decoder, if it refuses a frame.
    /// - [`push::Error::Internal`] if the encoder refuses a reply.
    /// - At `Commit`, the errors of
    ///   [`ReceiveService::commit`](super::ReceiveService::commit), other than
    ///   the errors of steps in flight and of hooks. These include
    ///   [`Error::LockTimeout`] for the update lock and the errors of a stored
    ///   detached metadata dict.
    /// - [`push::Error::Aborted`] if the client sends `Abort` or abandons an
    ///   object. The session sends nothing.
    /// - [`Error::Io`] of kind `UnexpectedEof` if `input` ends at a frame
    ///   boundary before `Commit`. The session sends nothing.
    /// - [`Error::Io`] if a read of `input` or a write to `output` fails before
    ///   `Commit` ends. The session sends nothing.
    /// - An I/O error from the file system, if a step of the transaction
    ///   fails.
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
    /// Runs the session until it commits or fails.
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

    /// Sends an `Error` message. The session ignores a failure to send it,
    /// because the peer can be gone.
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
        let (core, reply) =
            SessionCore::open(self.repo.clone(), self.policy, None, 1, hello).await?;
        self.core = Some(core);
        self.reply(&Message::HelloReply(reply)).await
    }

    async fn have(&mut self, names: Vec<ObjectName>) -> std::result::Result<(), Failure> {
        let reply = self.core().have(names).await?;
        self.reply(&Message::HaveReply(reply)).await
    }

    /// Reads one object stream and replies `ObjectsReply`. `first` is `None`
    /// for a stream of no object.
    async fn objects(&mut self, first: Option<ObjectHeader>) -> std::result::Result<(), Failure> {
        let Session {
            reader, core, buf, ..
        } = self;
        let core = core.as_ref().expect("the session is open after Hello");
        let reply = core.objects(first, reader, buf).await?;
        self.reply(&Message::ObjectsReply(reply)).await
    }

    /// Commits the session and replies `CommitReply`. A reply that the
    /// session cannot send is a warning of the report.
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
