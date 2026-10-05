//! One push session as steps, for a transport that carries each step in a
//! request of its own, such as HTTP.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use futures_io::AsyncRead;
use futures_lite::io::{AsyncReadExt, BufReader};
use ostrya_core::ObjectName;

use super::ReceivePolicy;
use super::core::SessionCore;
use super::session::{Failure, ReceiveReport, STREAM_BUFFER, aborted, next, out_of_order};
use crate::error::{Error, Result};
use crate::push;
use crate::push::proto::{
    CommitRequest, FrameReader, HaveReply, Hello, HelloReply, MAX_FRAME, Message, ObjectsReply,
};
use crate::repo::Repo;

type Core = SessionCore<Arc<ReceivePolicy>>;

/// One push session as steps, one for each request of the transport.
///
/// [`hello`](Self::hello) opens the session, and [`have`](Self::have),
/// [`objects`](Self::objects), and [`commit`](Self::commit) are its later
/// steps. Each step does what the message of the same name does in
/// [`Repo::receive`](crate::Repo::receive), with the same checks and the same
/// wire codes, and the host sends the reply. Every step takes `&self`, so the
/// host keeps the service in an `Arc` and runs steps of one session at the
/// same time:
///
/// - Up to `parallel_uploads` [`objects`](Self::objects) calls run at the
///   same time, and write through the one session transaction. One more is
///   `limit-exceeded`.
/// - One [`have`](Self::have) runs next to the other steps, and does not
///   count toward `parallel_uploads`. A second one while the first is in
///   flight is `limit-exceeded`.
/// - [`commit`](Self::commit) runs only when no other step is in flight, and
///   is `protocol` otherwise. While it runs, each other step is `protocol`.
///
/// The detached metadata of the session has one byte cap for the whole
/// session, [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), over every
/// object stream, and the read that takes the session past it is
/// `limit-exceeded`. The dirtree, dirmeta, and commit objects that the
/// streams read at the same time share a second budget of the same size,
/// from the arrival of their bytes to their stage step, and the read that
/// takes the session past it is `limit-exceeded`. The bytes of a detached
/// metadata object count against the first cap alone.
///
/// A step that fails ends the session with no commit, as one error ends a
/// session over a stream, and so does a refused step. An `objects` call in
/// flight then fails at its next read. A step future that is dropped before
/// it completes also ends the session. Once no step holds the session, the
/// session transaction is dropped in a task on the blocking pool, which
/// removes its staging directory and releases the repository lock in the
/// background: the call that ends the session does not wait for it. Under
/// the `tokio` backend, a call outside the context of a runtime drops the
/// transaction inline. After
/// the end, and after a commit, every step is `protocol`.
///
/// Each failure with a wire code returns as [`Error::Push`], and each failure
/// on the server side returns as the error it is, which the host sends as
/// `internal`. An I/O error of the input of `objects`, other than an end of
/// file, returns as [`Error::Io`]. A step of a session that an earlier
/// failure or [`abort`](Self::abort) ended returns [`push::Error::Protocol`]
/// with the message `the session was aborted: CAUSE`.
///
/// A step that completes after the session ended, by a failure of another
/// step or by [`abort`](Self::abort), returns the same `protocol` error in
/// place of its result. A service dropped while the session is open ends the
/// session in the same way.
///
/// The session id, the owner of the session, its idle timeout, and the
/// session limit belong to the host.
pub struct ReceiveService {
    state: Mutex<State>,
    signal: AbortSignal,
    parallel_uploads: u32,
}

enum State {
    /// The session takes steps. `uploads` counts the `objects` calls in
    /// flight, and `haves` the `have` calls, 0 or 1. Each step in flight
    /// holds a clone of `core`.
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

/// The error a step returns for `failure`. An `Abort` of the client, and an
/// input that ends before its last message, have no reply on a stream, and
/// here are `protocol`, which the host sends.
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
    /// Open the session: answer `Hello`, and open the session transaction,
    /// which holds the repository lock shared until the session ends.
    /// `parallel_uploads` is the value `HelloReply` announces, and the number
    /// of `objects` calls the session runs at the same time. A
    /// `parallel_uploads` of 0 is [`Error::InvalidInput`]. The service sets
    /// no upper bound: the host keeps the value in a range of its own. A
    /// `Hello` with `one-way` true is `protocol`.
    pub async fn hello(
        repo: Repo,
        policy: Arc<ReceivePolicy>,
        parallel_uploads: u32,
        hello: Hello,
    ) -> Result<(ReceiveService, HelloReply)> {
        if parallel_uploads == 0 {
            return Err(Error::InvalidInput(
                "parallel_uploads must be at least 1".into(),
            ));
        }
        let (core, reply) = SessionCore::open(repo, policy, parallel_uploads, hello)
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

    /// The checks of `hello` that every session runs before it opens, in
    /// this order: the protocol version (`version-unsupported`), the mode
    /// `bare-split-xattrs` (`mode-refused`), `[core] locking=false` for a
    /// `Hello` with `one-way` false (`locking-disabled`), each ref name
    /// (`invalid-ref`), and for a `Hello` with `one-way` false, the
    /// `HelloReply` with a commit for each ref against [`MAX_FRAME`]
    /// (`limit-exceeded`). The call is sync and does no I/O.
    ///
    /// [`hello`](Self::hello), [`Repo::receive`](crate::Repo::receive), and
    /// [`Repo::receive_stream`](crate::Repo::receive_stream) run the same
    /// checks. A `Hello` that passes can still fail to open: the open of the
    /// session transaction, the reads of `[core] fsync`, `[ex-integrity]
    /// fsverity`, and `[archive] zlib-level`, and the refusal of a `bare`
    /// repository when the process does not run as root come after them.
    /// The call does not refuse a `Hello` with `one-way` true, which
    /// [`hello`](Self::hello) refuses.
    pub fn check_hello(repo: &Repo, hello: &Hello) -> Result<()> {
        super::core::check_hello(repo, hello).map_err(into_error)
    }

    /// Answer a `Have`: one bit for each object the repository and the session
    /// do not hold. A call while another `have` of the session is in flight
    /// is `limit-exceeded`, and ends the session.
    pub async fn have(&self, names: Vec<ObjectName>) -> Result<HaveReply> {
        let step = self.enter(Kind::Have)?;
        let result = step.core().have(names).await;
        step.end(result)
    }

    /// Read one object stream from `input`: frames from `ObjectHeader` or
    /// `ObjectsEnd` on, to `ObjectsEnd`, and then the end of `input`. A byte
    /// after `ObjectsEnd`, and an `input` that ends before it, are
    /// `protocol`. An `Abort` frame of the client ends the session, and is
    /// `protocol`. An I/O error of `input` other than an end of file returns
    /// as [`Error::Io`]. A call past `parallel_uploads` calls in flight is
    /// `limit-exceeded`, and ends the session.
    ///
    /// The counts of `ObjectsReply` are those of this stream. A content,
    /// dirtree, dirmeta, or commit object that two streams of the session
    /// send at the same time can count in both. A detached metadata object
    /// that two streams send is `protocol`, and ends the session.
    pub async fn objects<R>(&self, input: R) -> Result<ObjectsReply>
    where
        R: AsyncRead + Unpin + Send,
    {
        let step = self.enter(Kind::Objects)?;
        let result = read_objects(step.core(), &self.signal, input).await;
        step.end(result)
    }

    /// Run `Commit`: the checks of the ref updates, the ref writes, and the
    /// transaction commit, as [`Repo::receive`](crate::Repo::receive) runs
    /// them. The session ends with it. A call while another step of the
    /// session is in flight is `protocol`, and ends the session.
    ///
    /// The host sends `CommitReply` from the refs of the report. When that
    /// send fails, the host adds a warning of the step
    /// [`ReplyNotDelivered`](super::ReceiveStep::ReplyNotDelivered) to the
    /// report.
    ///
    /// The commit owns the session transaction while it runs. A `commit`
    /// future that is dropped before it completes drops the transaction
    /// inline, on the thread that drops the future, and each later step is
    /// `protocol`. A host drops it only when it drops the commit task, for
    /// example at the shutdown of the runtime.
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

    /// End the session with no commit. Each `objects` call in flight fails at
    /// its next read, and every later step is `protocol`. The call returns at
    /// once, and the staging directory is removed in the background. A
    /// `commit` that runs is not stopped, and the call does nothing to it.
    pub fn abort(&self) {
        let core = close_locked(&mut self.lock(), "the host ended the session");
        self.closed(core);
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("receive service mutex")
    }

    /// Count one step of `kind` in flight, and give it a clone of the core.
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

    /// The error of a step that failed. A session that is open ends with it.
    /// A session that already ended gives its own reason, because the end is
    /// what failed the step.
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

    /// Refuse a step with `error`, and end the open session with it in the
    /// same hold of the lock that `state` holds.
    fn refuse(&self, mut state: MutexGuard<'_, State>, error: push::Error) -> Error {
        let core = close_locked(&mut state, &error.to_string());
        drop(state);
        self.closed(core);
        Error::Push(error)
    }

    /// Finish the end of a session after the lock is released: fire the
    /// signal, and release the reference of the state to the core. `None`,
    /// for a session that did not end here, does nothing.
    fn closed(&self, core: Option<Arc<Core>>) {
        if let Some(core) = core {
            self.signal.fire();
            release(core);
        }
    }
}

/// End an open session with `cause`, under the lock of the state. The
/// reference of the state to the core is returned, for
/// [`ReceiveService::closed`] to release after the lock. A session that is
/// not open is left as it is, and gives `None`.
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

/// Drop a reference to the core. The last reference drops the session
/// transaction in a detached task on the blocking pool, because the drop
/// removes the staging directory, and the caller does not wait for it.
/// Under the `tokio` backend with no runtime, the drop runs inline.
fn release(core: Arc<Core>) {
    if let Some(core) = Arc::into_inner(core) {
        ostrya_rt::unblock_detached(move || drop(core));
    }
}

impl Drop for ReceiveService {
    /// A session that is still open ends with no commit. No step is in flight,
    /// because each step borrows the service, so the state holds the last
    /// reference to the core.
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

/// The `protocol` error of a step on a session that does not take it.
fn refusal(state: &State) -> Error {
    match state {
        State::Open { .. } => unreachable!("an open session takes steps"),
        State::Committing => protocol("the session is committing"),
        State::Closed { reason } => protocol(reason.clone()),
    }
}

/// Read one object stream of [`ReceiveService::objects`].
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

/// One step in flight. Dropping it leaves the count of the session, and a
/// step that did not reach [`end`](Self::end) ends the session.
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

    /// The result of the step. A failure ends the session. A step that
    /// completes after the session ended gives the reason of the end.
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

/// Closes the session when `commit` ends, also when its future is dropped.
struct Ending<'a> {
    service: &'a ReceiveService,
    /// Why the session ended. `None` when the commit did not run to its end.
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

/// A signal that fires once, when the session ends with no commit, and wakes
/// each object stream that waits for input.
#[derive(Default)]
struct AbortSignal {
    /// Set under the lock of `waiters` when the signal fires, and read with
    /// no lock before each read.
    fired: AtomicBool,
    waiters: Mutex<Waiters>,
}

#[derive(Default)]
struct Waiters {
    next_id: u64,
    /// The waker of each reader that waits, by its id.
    wakers: HashMap<u64, Waker>,
    /// How many times a reader stored a waker, for the test of the reuse.
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

/// A reader whose reads fail once the signal fires. A read that waits for
/// input wakes when the signal fires. A read that waits again with the
/// waker the slot holds takes no lock.
struct Abortable<'a, R> {
    inner: R,
    signal: &'a AbortSignal,
    /// The waker slot of the reader, once it waited.
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
        // wakes it, and the flag is set before that wake, so the next poll
        // sees the signal.
        if me.waker.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
            return Poll::Pending;
        }
        // The signal sets the flag under the lock, so a check under the lock
        // either sees it or stores the waker before the signal takes it.
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

/// The futures of the steps can run on a thread pool.
const _: fn() = || {
    fn assert_send<T: Send>(_: T) {}
    let _ = |repo: Repo, policy: Arc<ReceivePolicy>, hello: Hello| {
        assert_send(ReceiveService::hello(repo, policy, 1, hello))
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

    /// A read that waits again with the waker the slot holds stores no
    /// waker, a read with another waker replaces it, and the signal wakes
    /// the waker the slot holds and fails the next read.
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
