//! The one-way stream of a push: the messages of a session in one direction,
//! with no reply. [`Repo::receive_stream`] reads it.

use futures_io::AsyncRead;
use futures_lite::io::{AsyncBufReadExt, BufReader};

use super::core::SessionCore;
use super::session::{Failure, ReceiveReport, STREAM_BUFFER, next, out_of_order};
use super::{ReceivePolicy, ReceiveRule};
use crate::error::{Error, Result};
use crate::push::proto::{CommitRequest, FrameReader, Message};
use crate::push::{self, Expected};
use crate::repo::Repo;

/// Methods that receive a one-way stream.
impl Repo {
    /// Reads one one-way stream from `input` into one transaction.
    ///
    /// A one-way stream holds the messages of a push session in one direction.
    /// The call sends no message, and returns the result in place of a reply.
    /// The stream holds these messages, in this order:
    ///
    /// 1. One `Hello` with `one-way` true.
    /// 2. Zero or more object streams, each one closed by `ObjectsEnd`.
    /// 3. One `Commit`.
    /// 4. The end of `input`.
    ///
    /// # Hello
    ///
    /// The frame limit and the chunk limit are 1 MiB
    /// ([`MAX_FRAME`](crate::push::proto::MAX_FRAME)). A `bare-split-xattrs`
    /// repository is `mode-refused`. A `bare` repository is `mode-refused`
    /// unless the process runs as root. The call accepts a repository with
    /// `[core] locking=false`.
    ///
    /// The size of a `HelloReply` does not bound the ref names of `Hello`,
    /// because the stream gets no reply.
    ///
    /// # Objects
    ///
    /// The call stages the objects as [`Repo::receive`] does. Before the
    /// stage, it verifies the checksum of each object and checks the content
    /// rules of the repository mode and of `policy`.
    ///
    /// # Locks
    ///
    /// The session transaction holds the repository lock shared from `Hello`
    /// to the end. Under `[core] locking=false`, it holds no lock. The commit
    /// takes the update lock, which ignores `[core] locking`.
    ///
    /// # Commit
    ///
    /// `Commit` runs the checks and the steps of [`Repo::receive`], with three
    /// differences:
    ///
    /// - The call ignores the `signers` of each rule, `summary_signers`, and
    ///   `update_summary` of `policy`. As a result, the commit adds no server
    ///   signature, writes no anchor commit, and does not regenerate the
    ///   summary.
    /// - A ref update whose expected state is [`Expected::Commit`] is
    ///   `protocol`. A ref update with no new commit is also `protocol`.
    /// - The commit checks run only after `input` reaches its end. A byte
    ///   after `Commit` is `protocol`.
    ///
    /// The reply limit of the two-way session also applies to the ref updates
    /// of `Commit`.
    ///
    /// # Errors
    ///
    /// A failure before the transaction commit aborts the transaction, and the
    /// repository does not change. A failure of the transaction commit can
    /// leave the detached metadata and some refs written. The call returns a
    /// wire code inside [`Error::Push`]. It returns each other error as it is.
    ///
    /// - [`push::Error::Protocol`] if the first message is not `Hello`, or if
    ///   `Hello` does not have `one-way` true.
    /// - [`push::Error::Protocol`] if a message comes out of order. `Have` and
    ///   an `Abort` frame between two objects are out of order.
    /// - [`push::Error::VersionUnsupported`] if `Hello` states another
    ///   protocol version.
    /// - [`push::Error::ModeRefused`] if the repository mode is
    ///   `bare-split-xattrs`, or if it is `bare` and the process does not run
    ///   as root.
    /// - [`push::Error::InvalidRef`] if `Hello` names a ref that is not valid.
    /// - The errors of [`Repo::transaction`] if the session transaction cannot
    ///   open. These include [`Error::LockTimeout`] for the repository lock.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if `[core] fsync`,
    ///   `[core] per-object-fsync`, `[ex-integrity] fsverity`, or
    ///   `[archive] zlib-level` is malformed.
    /// - The errors of an object stream that [`Repo::receive`] lists:
    ///   `checksum-mismatch`, `mode-refused`, `limit-exceeded`, `protocol`,
    ///   and the wire code of the frame decoder.
    /// - [`push::Error::Protocol`] if an update of `Commit` expects a commit
    ///   or has no new commit, or if a byte follows `Commit`.
    /// - At `Commit`, the errors of
    ///   [`ReceiveService::commit`](super::ReceiveService::commit), other than
    ///   the errors of steps in flight and of hooks. These include
    ///   [`Error::LockTimeout`] for the update lock.
    /// - [`push::Error::Aborted`] inside [`Error::Push`] if the sender
    ///   abandons an object: the abandon marker and then `Abort` inside the
    ///   object.
    /// - [`Error::Io`] of kind `UnexpectedEof` if `input` ends before
    ///   `Commit` is complete.
    /// - [`Error::Io`] if a read of `input` fails.
    /// - An I/O error from the file system, if a step of the transaction
    ///   fails.
    pub async fn receive_stream<R>(&self, input: R, policy: &ReceivePolicy) -> Result<ReceiveReport>
    where
        R: AsyncRead + Unpin + Send,
    {
        let policy = one_way_policy(policy);
        let reader = FrameReader::new(BufReader::with_capacity(STREAM_BUFFER, input));
        // A failure drops the transaction here, which removes its staging
        // directory and releases the repository lock.
        run(self, &policy, reader)
            .await
            .map_err(|failure| match failure {
                Failure::Wire(e) => Error::Push(e),
                Failure::Internal(e) | Failure::Silent(e) => e,
            })
    }
}

/// Returns a copy of `policy` with no server key and no summary step.
///
/// The `signers` of each rule and `summary_signers` are empty, and
/// `update_summary` is `false`.
fn one_way_policy(policy: &ReceivePolicy) -> ReceivePolicy {
    let rule = |rule: &ReceiveRule| ReceiveRule {
        signers: Vec::new(),
        ..rule.clone()
    };
    ReceivePolicy {
        default_rule: rule(&policy.default_rule),
        rules: policy
            .rules
            .iter()
            .map(|(pattern, r)| (pattern.clone(), rule(r)))
            .collect(),
        allow_privileged: policy.allow_privileged,
        summary_signers: Vec::new(),
        update_summary: false,
        detached_metadata_filter: policy.detached_metadata_filter.clone(),
    }
}

async fn run<R>(
    repo: &Repo,
    policy: &ReceivePolicy,
    mut reader: FrameReader<BufReader<R>>,
) -> std::result::Result<ReceiveReport, Failure>
where
    R: AsyncRead + Unpin + Send,
{
    let core = match next(&mut reader).await? {
        Message::Hello(hello) => SessionCore::open_one_way(repo.clone(), policy, hello).await?,
        other => return Err(out_of_order(&other)),
    };
    let mut buf = Vec::new();
    let request = loop {
        match next(&mut reader).await? {
            Message::ObjectHeader(header) => {
                core.objects(Some(header), &mut reader, &mut buf).await?;
            }
            Message::ObjectsEnd => {
                core.objects(None, &mut reader, &mut buf).await?;
            }
            Message::Commit(request) => break request,
            other => return Err(out_of_order(&other)),
        }
    };
    check_updates(&request)?;
    // Any byte after `Commit` is `protocol`, also bytes that do not make a
    // whole frame.
    let mut rest = reader.into_inner();
    match rest.fill_buf().await {
        Ok([]) => {}
        Ok(_) => {
            return Err(Failure::Wire(push::Error::Protocol(
                "bytes follow Commit in a one-way stream".into(),
            )));
        }
        Err(e) => return Err(Failure::Silent(Error::Io(e))),
    }
    drop(rest);
    drop(buf);
    core.finish(request).await
}

/// Checks that each update of `request` expects its ref absent or takes any
/// state, and sets a new commit.
///
/// A one-way sender cannot learn the current tips of the refs.
fn check_updates(request: &CommitRequest) -> std::result::Result<(), Failure> {
    for update in &request.updates {
        if let Expected::Commit(_) = update.expected {
            return Err(Failure::Wire(push::Error::Protocol(format!(
                "the update of '{}' expects a commit, which a one-way stream cannot state",
                update.name
            ))));
        }
        if update.new.is_none() {
            return Err(Failure::Wire(push::Error::Protocol(format!(
                "the update of '{}' deletes the ref, which a one-way stream cannot do",
                update.name
            ))));
        }
    }
    Ok(())
}

// A compile-time check that the future of a one-way stream is `Send`, so
// that it can run on a thread pool.
const _: fn() = || {
    fn assert_send<T: Send>(_: T) {}
    let _ = |repo: &Repo, policy: &ReceivePolicy| {
        assert_send(repo.receive_stream(futures_lite::io::empty(), policy))
    };
};
