//! A push session as steps, for a transport that carries each step in a
//! request of its own, for example HTTP.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use futures_io::AsyncRead;
use futures_lite::io::{AsyncReadExt, BufReader};
use ostrya_core::ObjectName;

use super::core::SessionCore;
use super::session::{Failure, ReceiveReport, STREAM_BUFFER, aborted, next, out_of_order};
use super::{ReceiveHooks, ReceivePolicy};
use crate::error::{Error, Result};
use crate::push;
use crate::push::proto::{
    CommitRequest, FrameReader, HaveReply, Hello, HelloReply, MAX_FRAME, Message, ObjectsReply,
};
use crate::repo::Repo;

type Core = SessionCore<Arc<ReceivePolicy>>;

/// A push session as steps, one step for each request of the transport.
///
/// [`hello`](Self::hello) opens the session. [`have`](Self::have),
/// [`objects`](Self::objects), and [`commit`](Self::commit) are its later
/// steps. Each step does what the message of the same name does in
/// [`Repo::receive`](crate::Repo::receive), with the same checks and the same
/// wire codes. The host sends the reply.
///
/// [`hello_with_hooks`](Self::hello_with_hooks) opens a session with the
/// [`ReceiveHooks`] of the host, which [`commit`](Self::commit) calls. The
/// session id, the owner of the session, its idle timeout, and the session
/// limit belong to the host.
///
/// # Concurrency
///
/// Every step takes `&self`, so the host can keep the service in an `Arc` and
/// run steps of one session at the same time:
///
/// - Up to `parallel_uploads` [`objects`](Self::objects) calls run at the
///   same time. They write through the one session transaction. One more
///   call is `limit-exceeded`.
/// - One [`have`](Self::have) runs next to the other steps. It does not count
///   toward `parallel_uploads`. A second `have` while the first is in flight
///   is `limit-exceeded`.
/// - [`commit`](Self::commit) runs only when no other step is in flight. If
///   another step is in flight, `commit` is `protocol`. While `commit` runs,
///   each other step is `protocol`.
///
/// # Metadata budgets
///
/// The detached metadata of the session has one byte cap for the whole
/// session, over every object stream:
/// [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE). The read that takes the
/// session past this cap is `limit-exceeded`.
///
/// The dirtree, dirmeta, and commit objects that the streams read at the same
/// time share a second budget of the same size. Their bytes count from their
/// arrival to their stage step. The read that takes the session past this
/// budget is `limit-exceeded`. The bytes of a detached metadata object count
/// against the first cap alone.
///
/// # End of a session
///
/// A step that fails ends the session with no commit, as one error ends a
/// session over a stream. A refused step also ends the session. An `objects`
/// call in flight then fails at its next read. If a step future is dropped
/// before it completes, the session also ends. If the service is dropped
/// while the session is open, the session ends in the same way.
///
/// When no step holds the session, a task on the blocking pool drops the
/// session transaction. The drop removes the staging directory and releases
/// the repository lock in the background. The call that ends the session does
/// not wait for it. Under the `tokio` backend, a call outside the context of a
/// runtime drops the transaction inline.
///
/// After the end, and after a commit, every step is `protocol`.
///
/// # Failures
///
/// - A failure with a wire code returns as [`Error::Push`].
/// - A failure on the server side returns as the error it is. The host sends
///   it as `internal`.
/// - If the input of `objects` fails with an I/O error that is not an end of
///   file, the step returns [`Error::Io`].
/// - A step of a session that an earlier failure or [`abort`](Self::abort)
///   ended returns [`push::Error::Protocol`] with the message
///   `the session was aborted: CAUSE`.
/// - A step can complete after a failure of another step or
///   [`abort`](Self::abort) ended the session. Then the step drops its result
///   and returns the same `protocol` error.
pub struct ReceiveService {
    state: Mutex<State>,
    signal: AbortSignal,
    parallel_uploads: u32,
}

enum State {
    /// The session takes steps. `uploads` counts the `objects` calls in
    /// flight. `haves` counts the `have` calls in flight, 0 or 1. Each step
    /// in flight holds a clone of `core`.
    Open {
        core: Arc<Core>,
        uploads: u32,
        haves: u32,
    },
    /// `commit` runs and owns the session.
    Committing,
    /// The session ended. `reason` is the message of the `protocol` error of
    /// each later step.
    Closed { reason: String },
}

#[derive(Clone, Copy)]
enum Kind {
    Have,
    Objects,
}

fn protocol(message: impl Into<String>) -> Error {
    Error::Push(push::Error::Protocol(message.into()))
}

/// Returns the error that a step returns for `failure`.
///
/// An `Abort` of the client and an input that ends before its last message
/// get no reply on a stream. Here they are `protocol`, which the host sends.
fn into_error(failure: Failure) -> Error {
    match failure {
        Failure::Wire(e) => Error::Push(e),
        Failure::Internal(e) => e,
        Failure::Silent(Error::Push(push::Error::Aborted)) => {
            protocol("the client aborted the session")
        }
        Failure::Silent(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
            protocol("the object stream ends before ObjectsEnd")
        }
        Failure::Silent(e) => e,
    }
}

impl ReceiveService {
    /// Opens a session: answers `Hello` and opens the session transaction.
    ///
    /// The session transaction holds the repository lock shared until the
    /// session ends. `parallel_uploads` is the value that `HelloReply`
    /// announces. It is also the number of `objects` calls that the session
    /// runs at the same time. The service sets no upper bound, so the host
    /// keeps the value in a range of its own.
    ///
    /// The session has no hooks. The call is
    /// [`hello_with_hooks`](Self::hello_with_hooks) with `None`.
    ///
    /// # Errors
    ///
    /// A wire code returns inside [`Error::Push`].
    ///
    /// - [`Error::InvalidInput`] if `parallel_uploads` is 0.
    /// - [`push::Error::Protocol`] if `Hello` has `one-way` true.
    /// - The errors of [`check_hello`](Self::check_hello).
    /// - The errors of [`Repo::transaction`](crate::Repo::transaction) if the
    ///   session transaction cannot open. These include
    ///   [`Error::LockTimeout`] if the wait for the repository lock passes
    ///   `[core] lock-timeout-secs`.
    /// - [`push::Error::ModeRefused`] if the repository mode is `bare` and the
    ///   process does not run as root.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if `[core] fsync`,
    ///   `[core] per-object-fsync`, `[ex-integrity] fsverity`, or, in an
    ///   archive repository, `[archive] zlib-level` holds a malformed value.
    /// - An I/O error from the file system, if a read of the staging
    ///   directory or of the refs of `Hello` fails.
    pub async fn hello(
        repo: Repo,
        policy: Arc<ReceivePolicy>,
        parallel_uploads: u32,
        hello: Hello,
    ) -> Result<(ReceiveService, HelloReply)> {
        Self::hello_with_hooks(repo, policy, None, parallel_uploads, hello).await
    }

    /// Opens a session as [`hello`](Self::hello) does, with the hooks of the
    /// host.
    ///
    /// [`commit`](Self::commit) calls [`ReceiveHooks::before_update`] of
    /// `hooks` just before the update lock. It calls
    /// [`ReceiveHooks::after_update`] after the release of the update lock.
    /// `None` gives a session with no hooks.
    ///
    /// # Errors
    ///
    /// The errors of [`hello`](Self::hello).
    pub async fn hello_with_hooks(
        repo: Repo,
        policy: Arc<ReceivePolicy>,
        hooks: Option<Arc<dyn ReceiveHooks>>,
        parallel_uploads: u32,
        hello: Hello,
    ) -> Result<(ReceiveService, HelloReply)> {
        if parallel_uploads == 0 {
            return Err(Error::InvalidInput(
                "parallel_uploads must be at least 1".into(),
            ));
        }
        let (core, reply) = SessionCore::open(repo, policy, hooks, parallel_uploads, hello)
            .await
            .map_err(into_error)?;
        let service = ReceiveService {
            state: Mutex::new(State::Open {
                core: Arc::new(core),
                uploads: 0,
                haves: 0,
            }),
            signal: AbortSignal::default(),
            parallel_uploads,
        };
        Ok((service, reply))
    }

    /// Runs the checks of `hello` that every session runs before it opens.
    ///
    /// The checks run in this order:
    ///
    /// 1. The protocol version (`version-unsupported`).
    /// 2. The mode `bare-split-xattrs` (`mode-refused`).
    /// 3. For a `Hello` with `one-way` false, `[core] locking=false`
    ///    (`locking-disabled`).
    /// 4. Each ref name (`invalid-ref`).
    /// 5. For a `Hello` with `one-way` false, the size of the `HelloReply`
    ///    with a commit for each ref, against [`MAX_FRAME`]
    ///    (`limit-exceeded`).
    ///
    /// The call is sync and does no I/O. [`hello`](Self::hello),
    /// [`Repo::receive`](crate::Repo::receive), and
    /// [`Repo::receive_stream`](crate::Repo::receive_stream) run the same
    /// checks. The call does not refuse a `Hello` with `one-way` true, which
    /// [`hello`](Self::hello) refuses.
    ///
    /// A `Hello` that passes can still fail to open. These steps of the open
    /// come after the checks:
    ///
    /// - The open of the session transaction.
    /// - The reads of `[core] fsync`, `[core] per-object-fsync`,
    ///   `[ex-integrity] fsverity`, and `[archive] zlib-level`.
    /// - The refusal of a `bare` repository if the process does not run as
    ///   root.
    ///
    /// # Errors
    ///
    /// A wire code returns inside [`Error::Push`].
    ///
    /// - [`push::Error::VersionUnsupported`] if `hello` names a protocol
    ///   version that the server does not speak.
    /// - [`push::Error::ModeRefused`] if the repository mode is
    ///   `bare-split-xattrs`.
    /// - [`push::Error::LockingDisabled`] if `hello` has `one-way` false and
    ///   the repository sets `[core] locking=false`.
    /// - [`push::Error::InvalidRef`] if a ref name of `hello` is not valid.
    /// - [`push::Error::LimitExceeded`] if `hello` has `one-way` false and
    ///   its `HelloReply` can need a frame over [`MAX_FRAME`].
    /// - [`push::Error::Internal`] if the encoder refuses the `HelloReply`
    ///   with no ref.
    /// - [`Error::Core`] if `[core] locking` is not a boolean.
    pub fn check_hello(repo: &Repo, hello: &Hello) -> Result<()> {
        super::core::check_hello(repo, hello).map_err(into_error)
    }

    /// Answers a `Have`: one bit for each object, set if the object is missing.
    ///
    /// An object is missing if neither the repository nor the session holds
    /// it.
    ///
    /// # Errors
    ///
    /// A wire code returns inside [`Error::Push`]. Each error ends the
    /// session.
    ///
    /// - [`push::Error::LimitExceeded`] if another `have` of the session is in
    ///   flight, or if `names` holds more than
    ///   [`MAX_HAVE`](crate::push::proto::MAX_HAVE) entries.
    /// - [`push::Error::Protocol`] if the session ended or a
    ///   [`commit`](Self::commit) runs.
    /// - An I/O error from the file system, if the check of an object in the
    ///   object store fails.
    pub async fn have(&self, names: Vec<ObjectName>) -> Result<HaveReply> {
        let step = self.enter(Kind::Have)?;
        let result = step.core().have(names).await;
        step.end(result)
    }

    /// Reads one object stream from `input` and stages its objects.
    ///
    /// The stream is a sequence of frames from `ObjectHeader` or `ObjectsEnd`
    /// to `ObjectsEnd`, and then the end of `input`. The counts of
    /// `ObjectsReply` are the counts of this stream. If two streams of the
    /// session send a content, dirtree, dirmeta, or commit object at the same
    /// time, the object can count in both.
    ///
    /// # Errors
    ///
    /// A wire code returns inside [`Error::Push`]. Each error ends the
    /// session.
    ///
    /// - [`push::Error::LimitExceeded`] if `parallel_uploads` calls are in
    ///   flight already, or if a read passes one of the
    ///   [metadata budgets](ReceiveService#metadata-budgets).
    /// - [`push::Error::LimitExceeded`] if one metadata object is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), or if the header
    ///   of a content object is larger than its limit.
    /// - [`push::Error::Protocol`] if a byte follows `ObjectsEnd`, or if
    ///   `input` ends before `ObjectsEnd`.
    /// - [`push::Error::Protocol`] if the client sends an `Abort` frame, or a
    ///   message out of order, or bytes after the end of an object.
    /// - [`push::Error::Protocol`] if two detached metadata objects of the
    ///   session name the same commit, or if a detached metadata dict is
    ///   malformed.
    /// - [`push::Error::Protocol`] if the payload of an object is malformed,
    ///   for example a corrupt DEFLATE stream or a size that does not match
    ///   its header.
    /// - [`push::Error::Protocol`] if the session ended or a
    ///   [`commit`](Self::commit) runs.
    /// - [`push::Error::ChecksumMismatch`] if the bytes of an object do not
    ///   hash to its checksum.
    /// - [`push::Error::ModeRefused`] if an object breaks the content rules of
    ///   the repository mode or of the policy.
    /// - The wire code of the frame decoder, if it refuses a frame.
    /// - [`Error::Io`] if `input` fails with an I/O error that is not an end
    ///   of file.
    /// - An I/O error from the file system, if the stage of an object fails.
    pub async fn objects<R>(&self, input: R) -> Result<ObjectsReply>
    where
        R: AsyncRead + Unpin + Send,
    {
        let step = self.enter(Kind::Objects)?;
        let result = read_objects(step.core(), &self.signal, input).await;
        step.end(result)
    }

    /// Runs `Commit`: the checks of the ref updates, the ref writes, and the
    /// transaction commit.
    ///
    /// The checks and the writes are the ones that
    /// [`Repo::receive`](crate::Repo::receive) runs. The session ends with
    /// the call.
    ///
    /// # Hooks
    ///
    /// In a session with hooks, the call runs [`ReceiveHooks::before_update`]
    /// just before the update lock. It runs [`ReceiveHooks::after_update`]
    /// after the release of the update lock, also when no ref changes.
    /// [`ReceiveHooks`] states when each hook runs, the entries of the host,
    /// the locks, and the result of an error or a panic in a hook.
    ///
    /// # Partial writes
    ///
    /// The transaction commit is not atomic. These failures can leave the
    /// detached metadata and some refs written:
    ///
    /// - a failure of a detached-metadata write
    /// - a failure of a ref write
    /// - a failure of the `fsync` of a ref directory
    ///
    /// The call then returns the error. In a session with hooks, the carried
    /// value drops, and `after_update` does not run.
    ///
    /// # Reply
    ///
    /// The host sends `CommitReply` from the refs of the report. If that send
    /// fails, the host adds a warning of the step
    /// [`ReplyNotDelivered`](super::ReceiveStep::ReplyNotDelivered) to the
    /// report. The report that `after_update` gets never holds this warning.
    ///
    /// # Dropped future
    ///
    /// The call owns the session transaction while it runs. If the `commit`
    /// future is dropped before it completes, the transaction drops inline,
    /// on the thread that drops the future. Each later step is then
    /// `protocol`. A host drops the future only when it drops the commit task,
    /// for example at the shutdown of the runtime.
    ///
    /// The transaction commit writes the detached metadata and the refs on the
    /// blocking pool. If the future is dropped during these writes, the update
    /// lock and the carried value of the hooks drop before the writes end. If
    /// the future is dropped while `after_update` runs, the future of the hook
    /// and the carried value drop, and the refs can be written.
    ///
    /// The host must run each commit to its end, for example in a task that
    /// it joins.
    ///
    /// # Errors
    ///
    /// A wire code returns inside [`Error::Push`]. Each error ends the
    /// session.
    ///
    /// - [`push::Error::Protocol`] if another step of the session is in
    ///   flight, if the session ended, or if another `commit` runs.
    /// - [`push::Error::Protocol`] if the request holds no update, or names a
    ///   ref that `Hello` does not name, or names one ref twice.
    /// - [`push::Error::Protocol`] if a detached metadata dict belongs to a
    ///   commit that is not a commit of the session.
    /// - [`push::Error::Protocol`] if a staged commit or a staged dirtree does
    ///   not parse.
    /// - [`push::Error::InvalidRef`] if a ref name is not valid, or if an
    ///   update writes a commit to a ref name of 64 lowercase hex characters.
    /// - [`push::Error::LimitExceeded`] if the `CommitReply` can need a frame
    ///   over [`MAX_FRAME`], or if a merged detached metadata dict is larger
    ///   than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    /// - [`push::Error::RefDenied`] if a rule refuses an update, or if an
    ///   update names the collection anchor ref of a repository with a
    ///   collection id.
    /// - [`push::Error::RefDenied`] if a ref path fails a check under the
    ///   update lock: a ref is an alias, a ref write cannot replace a path, or
    ///   one update names a directory of another.
    /// - [`push::Error::RefDenied`] or [`push::Error::Internal`] if
    ///   `before_update` refuses with
    ///   [`HookRefusal::denied`](super::HookRefusal::denied) or
    ///   [`HookRefusal::internal`](super::HookRefusal::internal).
    /// - [`push::Error::MissingObjects`] if a new commit, or an object of the
    ///   tree of a commit of the session, is neither staged nor present.
    /// - [`push::Error::BindingMismatch`] if the ref binding or the collection
    ///   binding of a new commit does not name its ref or the repository.
    /// - [`push::Error::SignatureRequired`] if a new commit fails the
    ///   signature verification of a rule.
    /// - [`push::Error::RefMismatch`] if a ref is not in the state that its
    ///   update expects.
    /// - [`push::Error::DeleteDenied`] if an update deletes a ref and the
    ///   policy does not allow it.
    /// - [`push::Error::NonFastForward`] if the new commit does not descend
    ///   from the commit of the ref. If the client sends `force` and the rule
    ///   allows an update that is not a fast-forward, this check does not run.
    /// - [`push::Error::Internal`] if `after_update` returns an error.
    /// - [`Error::InvalidInput`] if the plan of `before_update` breaks a rule
    ///   that [`ReceiveHooks`] states. The host sends it as `internal`.
    /// - [`Error::InvalidFormat`] if a commit or a dirtree that the repository
    ///   holds does not parse.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if a stored detached
    ///   metadata dict is not an `a{sv}` in normal form.
    /// - [`Error::InvalidFormat`] if a stored dict holds a value that is not an
    ///   `aay` under a signature key that the merge extends.
    /// - The error of the signing engine, for example [`Error::Signature`], if
    ///   a server key fails to sign a commit.
    /// - [`Error::LockTimeout`] if the wait for the update lock passes
    ///   `[core] lock-timeout-secs`.
    /// - An I/O error from the file system, if a read of the repository or a
    ///   write of the transaction commit fails.
    pub async fn commit(&self, request: CommitRequest) -> Result<ReceiveReport> {
        let core = {
            let mut state = self.lock();
            match &*state {
                State::Open {
                    uploads: 0,
                    haves: 0,
                    ..
                } => {}
                State::Open { .. } => {
                    let e = push::Error::Protocol(
                        "Commit while another request of the session is in flight".into(),
                    );
                    return Err(self.refuse(state, e));
                }
                other => return Err(refusal(other)),
            }
            let State::Open { core, .. } = std::mem::replace(&mut *state, State::Committing) else {
                unreachable!("the state is open")
            };
            core
        };
        // Each step drops its clone of the core before it leaves the count,
        // so with no step counted the state held the last clone.
        let Ok(core) = Arc::try_unwrap(core) else {
            unreachable!("no step of the session holds the core")
        };
        let mut ending = Ending {
            service: self,
            reason: None,
        };
        let result = core.finish(request).await.map_err(into_error);
        ending.reason = Some(match &result {
            Ok(_) => "the session committed".into(),
            Err(e) => format!("the session was aborted: {e}"),
        });
        result
    }

    /// Ends the session with no commit.
    ///
    /// Each `objects` call in flight fails at its next read, and every later
    /// step is `protocol`. The call returns at once. A task on the blocking
    /// pool removes the staging directory in the background. If a `commit`
    /// runs, the call does not stop it and does nothing to it.
    pub fn abort(&self) {
        let core = close_locked(&mut self.lock(), "the host ended the session");
        self.closed(core);
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("receive service mutex")
    }

    /// Counts one step of `kind` in flight and gives it a clone of the core.
    fn enter(&self, kind: Kind) -> Result<Step<'_>> {
        let mut state = self.lock();
        let (core, uploads, haves) = match &mut *state {
            State::Open {
                core,
                uploads,
                haves,
            } => (core, uploads, haves),
            other => return Err(refusal(other)),
        };
        match kind {
            Kind::Objects if *uploads == self.parallel_uploads => {
                let e = push::Error::LimitExceeded(format!(
                    "an objects request past parallel-uploads {}",
                    self.parallel_uploads
                ));
                return Err(self.refuse(state, e));
            }
            Kind::Have if *haves == 1 => {
                let e = push::Error::LimitExceeded(
                    "a Have request while another Have of the session is in flight".into(),
                );
                return Err(self.refuse(state, e));
            }
            Kind::Objects => *uploads += 1,
            Kind::Have => *haves += 1,
        }
        Ok(Step {
            service: self,
            kind,
            core: Some(core.clone()),
            done: false,
        })
    }

    /// Returns the error of a step that failed.
    ///
    /// A session that is open ends with the error. A session that already
    /// ended gives its own reason, because the end is the cause of the
    /// failure of the step.
    fn fail(&self, failure: Failure) -> Error {
        let mut state = self.lock();
        if let State::Closed { reason } = &*state {
            return protocol(reason.clone());
        }
        let error = into_error(failure);
        let core = close_locked(&mut state, &error.to_string());
        drop(state);
        self.closed(core);
        error
    }

    /// Refuses a step with `error` and ends the open session with it, in the
    /// same hold of the lock that `state` holds.
    fn refuse(&self, mut state: MutexGuard<'_, State>, error: push::Error) -> Error {
        let core = close_locked(&mut state, &error.to_string());
        drop(state);
        self.closed(core);
        Error::Push(error)
    }

    /// Completes the end of a session after the release of the lock.
    ///
    /// The call fires the signal and releases the reference of the state to
    /// the core. `None`, for a session that did not end here, does nothing.
    fn closed(&self, core: Option<Arc<Core>>) {
        if let Some(core) = core {
            self.signal.fire();
            release(core);
        }
    }
}

/// Ends an open session with `cause`, under the lock of the state.
///
/// The call returns the reference of the state to the core.
/// [`ReceiveService::closed`] releases it after the lock. A session that is
/// not open stays as it is, and the call returns `None`.
fn close_locked(state: &mut State, cause: &str) -> Option<Arc<Core>> {
    if !matches!(state, State::Open { .. }) {
        return None;
    }
    let reason = format!("the session was aborted: {cause}");
    match std::mem::replace(state, State::Closed { reason }) {
        State::Open { core, .. } => Some(core),
        _ => unreachable!("the state is open"),
    }
}

/// Drops a reference to the core.
///
/// The last reference drops the session transaction in a detached task on
/// the blocking pool, because the drop removes the staging directory. The
/// caller does not wait for it. Under the `tokio` backend with no runtime,
/// the drop runs inline.
fn release(core: Arc<Core>) {
    if let Some(core) = Arc::into_inner(core) {
        ostrya_rt::unblock_detached(move || drop(core));
    }
}

impl Drop for ReceiveService {
    /// Ends a session that is still open, with no commit.
    ///
    /// Each step borrows the service, so no step is in flight at the drop. A
    /// task on the blocking pool drops the session transaction.
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        let closed = State::Closed {
            reason: String::new(),
        };
        if let State::Open { core, .. } = std::mem::replace(state, closed) {
            release(core);
        }
    }
}

/// Returns the `protocol` error of a step on a session that does not take it.
fn refusal(state: &State) -> Error {
    match state {
        State::Open { .. } => unreachable!("an open session takes steps"),
        State::Committing => protocol("the session is committing"),
        State::Closed { reason } => protocol(reason.clone()),
    }
}

/// Reads one object stream of [`ReceiveService::objects`].
async fn read_objects<R: AsyncRead + Unpin>(
    core: &Core,
    signal: &AbortSignal,
    input: R,
) -> std::result::Result<ObjectsReply, Failure> {
    let input = Abortable {
        inner: input,
        signal,
        id: None,
        waker: None,
    };
    let mut reader = FrameReader::new(BufReader::with_capacity(STREAM_BUFFER, input));
    reader.set_limit(MAX_FRAME);
    let first = match next(&mut reader).await? {
        Message::ObjectHeader(header) => Some(header),
        Message::ObjectsEnd => None,
        Message::Abort => return Err(aborted()),
        other => return Err(out_of_order(&other)),
    };
    let mut buf = Vec::new();
    let reply = core.objects(first, &mut reader, &mut buf).await?;
    let mut rest = reader.into_inner();
    let mut byte = [0u8];
    let n = rest
        .read(&mut byte)
        .await
        .map_err(|e| Failure::Silent(Error::Io(e)))?;
    if n != 0 {
        return Err(Failure::Wire(push::Error::Protocol(
            "bytes follow ObjectsEnd".into(),
        )));
    }
    Ok(reply)
}

/// One step in flight.
///
/// The drop of a step removes it from the count of the session. A step that
/// did not reach [`end`](Self::end) ends the session when it drops.
struct Step<'a> {
    service: &'a ReceiveService,
    kind: Kind,
    core: Option<Arc<Core>>,
    done: bool,
}

impl Step<'_> {
    fn core(&self) -> &Core {
        self.core.as_ref().expect("the step holds the core")
    }

    /// Returns the result of the step.
    ///
    /// A failure ends the session. A step that completes after the session
    /// ended gives the reason of the end.
    fn end<T>(mut self, result: std::result::Result<T, Failure>) -> Result<T> {
        self.done = true;
        match result {
            Ok(value) => match &*self.service.lock() {
                State::Closed { reason } => Err(protocol(reason.clone())),
                _ => Ok(value),
            },
            Err(failure) => Err(self.service.fail(failure)),
        }
    }
}

impl Drop for Step<'_> {
    fn drop(&mut self) {
        // The clone goes before the count, so a commit that counts no step
        // holds the last clone.
        if let Some(core) = self.core.take() {
            release(core);
        }
        // The count and the end of the session change in one hold of the
        // lock, so no commit takes the session between them.
        let core = {
            let mut state = self.service.lock();
            if let State::Open { uploads, haves, .. } = &mut *state {
                match self.kind {
                    Kind::Objects => *uploads -= 1,
                    Kind::Have => *haves -= 1,
                }
            }
            if self.done {
                None
            } else {
                close_locked(
                    &mut state,
                    "a request of the session ended before its reply",
                )
            }
        };
        self.service.closed(core);
    }
}

/// A guard that closes the session when `commit` ends, also when its future
/// is dropped.
struct Ending<'a> {
    service: &'a ReceiveService,
    /// The reason of the end of the session. `None` if the commit did not run
    /// to its end.
    reason: Option<String>,
}

impl Drop for Ending<'_> {
    fn drop(&mut self) {
        let reason = self.reason.take().unwrap_or_else(|| {
            "the session was aborted: the commit ended before its result".into()
        });
        *self.service.lock() = State::Closed { reason };
    }
}

/// A signal that fires once, when the session ends with no commit.
///
/// The signal wakes each object stream that waits for input.
#[derive(Default)]
struct AbortSignal {
    /// The flag of the signal. The signal sets it under the lock of `waiters`
    /// when it fires. Each read reads it with no lock first.
    fired: AtomicBool,
    waiters: Mutex<Waiters>,
}

#[derive(Default)]
struct Waiters {
    next_id: u64,
    /// The waker of each reader that waits, by its id.
    wakers: HashMap<u64, Waker>,
    /// The number of times that a reader stored a waker, for the test of the
    /// reuse.
    #[cfg(test)]
    stores: usize,
}

impl AbortSignal {
    fn fire(&self) {
        let wakers = {
            let mut waiters = self.lock();
            self.fired.store(true, Ordering::Release);
            std::mem::take(&mut waiters.wakers)
        };
        for waker in wakers.into_values() {
            waker.wake();
        }
    }

    fn lock(&self) -> MutexGuard<'_, Waiters> {
        self.waiters.lock().expect("abort signal mutex")
    }
}

/// A reader whose reads fail after the signal fires.
///
/// A read that waits for input wakes when the signal fires. A read that waits
/// again with the waker that the slot holds takes no lock.
struct Abortable<'a, R> {
    inner: R,
    signal: &'a AbortSignal,
    /// The waker slot of the reader, after its first wait.
    id: Option<u64>,
    /// The waker stored in the slot.
    waker: Option<Waker>,
}

fn aborted_read() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "the session was aborted")
}

impl<R: AsyncRead + Unpin> AsyncRead for Abortable<'_, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.signal.fired.load(Ordering::Acquire) {
            return Poll::Ready(Err(aborted_read()));
        }
        if let Poll::Ready(read) = Pin::new(&mut me.inner).poll_read(cx, buf) {
            return Poll::Ready(read);
        }
        // The stored waker stays in the slot until the signal takes it and
        // wakes it. The signal sets the flag before that wake, so the next
        // poll sees the signal.
        if me.waker.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
            return Poll::Pending;
        }
        // The signal sets the flag under the lock. As a result, a check under
        // the lock sees the flag or stores the waker before the signal takes
        // it.
        let mut waiters = me.signal.lock();
        if me.signal.fired.load(Ordering::Acquire) {
            return Poll::Ready(Err(aborted_read()));
        }
        let id = *me.id.get_or_insert_with(|| {
            let id = waiters.next_id;
            waiters.next_id += 1;
            id
        });
        waiters.wakers.insert(id, cx.waker().clone());
        #[cfg(test)]
        {
            waiters.stores += 1;
        }
        me.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl<R> Drop for Abortable<'_, R> {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.signal.lock().wakers.remove(&id);
        }
    }
}

// The futures of the steps are `Send`, so they can run on a thread pool.
const _: fn() = || {
    fn assert_send<T: Send>(_: T) {}
    let _ = |repo: Repo, policy: Arc<ReceivePolicy>, hello: Hello| {
        assert_send(ReceiveService::hello(repo, policy, 1, hello))
    };
    let _ = |repo: Repo,
             policy: Arc<ReceivePolicy>,
             hooks: Option<Arc<dyn ReceiveHooks>>,
             hello: Hello| {
        assert_send(ReceiveService::hello_with_hooks(
            repo, policy, hooks, 1, hello,
        ))
    };
    let _ = |service: &ReceiveService, names: Vec<ObjectName>, request: CommitRequest| {
        assert_send(service.have(names));
        assert_send(service.objects(futures_lite::io::empty()));
        assert_send(service.commit(request));
    };
};

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;

    use super::*;

    /// A reader that always waits.
    struct Waits;

    impl AsyncRead for Waits {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }

    /// Counts the wakes of a waker.
    struct CountWakes(AtomicUsize);

    impl Wake for CountWakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A read that waits again with the waker that the slot holds stores no
    /// waker. A read with another waker replaces it. The signal wakes the
    /// waker that the slot holds and fails the next read.
    #[test]
    fn a_waiting_read_stores_its_waker_once() {
        let signal = AbortSignal::default();
        let mut reader = Abortable {
            inner: Waits,
            signal: &signal,
            id: None,
            waker: None,
        };
        let first = Arc::new(CountWakes(AtomicUsize::new(0)));
        let second = Arc::new(CountWakes(AtomicUsize::new(0)));
        let first_waker = Waker::from(first.clone());
        let second_waker = Waker::from(second.clone());
        let mut buf = [0u8; 8];
        let mut poll = |waker: &Waker| {
            Pin::new(&mut reader).poll_read(&mut Context::from_waker(waker), &mut buf)
        };
        assert!(poll(&first_waker).is_pending());
        assert!(poll(&first_waker).is_pending());
        assert_eq!(signal.lock().stores, 1);
        assert!(poll(&second_waker).is_pending());
        assert_eq!(signal.lock().stores, 2);
        assert_eq!(signal.lock().wakers.len(), 1);
        signal.fire();
        assert_eq!(first.0.load(Ordering::Relaxed), 0);
        assert_eq!(second.0.load(Ordering::Relaxed), 1);
        match poll(&second_waker) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::ConnectionAborted),
            other => panic!("the read after the signal: {other:?}"),
        }
    }
}
