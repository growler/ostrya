//! One one-way stream: the messages of a push session in one direction, with
//! no reply.

use futures_io::AsyncRead;
use futures_lite::io::{AsyncBufReadExt, BufReader};

use super::core::SessionCore;
use super::session::{Failure, ReceiveReport, STREAM_BUFFER, next, out_of_order};
use super::{ReceivePolicy, ReceiveRule};
use crate::error::{Error, Result};
use crate::push::proto::{CommitRequest, FrameReader, Message};
use crate::push::{self, Expected};
use crate::repo::Repo;

impl Repo {
    /// Read one one-way stream from `input` into one transaction: one `Hello`
    /// with `one-way` true, zero or more object streams, each closed by
    /// `ObjectsEnd`, one `Commit`, and the end of `input`. The call sends no
    /// message, and returns the result in place of a reply.
    ///
    /// The frame limit and the chunk limit are 1 MiB. The objects are staged
    /// as in [`Repo::receive`], after the checksum and the content checks of
    /// the repository mode and of `policy`. A `bare-split-xattrs` repository
    /// is `mode-refused`, and so is a `bare` repository unless the process
    /// runs as root. A repository with `[core] locking=false` is accepted.
    ///
    /// The session transaction holds the repository lock shared from `Hello`
    /// to the end, with no lock under `[core] locking=false`. The commit
    /// takes the update lock, which ignores `[core] locking`.
    ///
    /// `Commit` runs the checks and the steps of [`Repo::receive`], with three
    /// differences. The `signers` of each rule, `summary_signers`, and
    /// `update_summary` of `policy` are ignored, so the commit adds no server
    /// signature, writes no anchor commit, and does not regenerate the
    /// summary. A ref update whose expected state is
    /// [`Expected::Commit`], and a ref update with no new commit, are
    /// `protocol`. The commit checks run only after `input` reaches its end,
    /// and a byte after `Commit` is `protocol`. The reply limit of the two-way
    /// session applies to the ref updates of `Commit` as well.
    ///
    /// Each failure aborts the transaction, and the repository does not
    /// change. A failure with a wire code returns as [`Error::Push`]. `Have`,
    /// a `Hello` without `one-way` true, and an `Abort` frame between two
    /// objects are `protocol`. An abandoned object, the abandon marker and
    /// `Abort` inside an object, returns [`push::Error::Aborted`]. An end of
    /// `input` before `Commit` is complete returns an [`Error::Io`] of kind
    /// `UnexpectedEof`, and an error of `input` returns as [`Error::Io`]. A
    /// failure on the receiving side returns as the error it is.
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

/// `policy` with no server key and no summary step: the `signers` of each
/// rule and `summary_signers` are empty, and `update_summary` is false.
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
    // The bytes after `Commit` are not frames: each one is `protocol`, also
    // one that does not make a whole frame.
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

/// A one-way sender cannot learn the current tips, so each update expects
/// its ref absent or takes any state, and sets a new commit.
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

/// The future of a one-way stream can run on a thread pool.
const _: fn() = || {
    fn assert_send<T: Send>(_: T) {}
    let _ = |repo: &Repo, policy: &ReceivePolicy| {
        assert_send(repo.receive_stream(futures_lite::io::empty(), policy))
    };
};
