//! The progress handle of a push and the statistics of a session.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The step that a push is in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PushPhase {
    /// The client reads its source and builds the object list.
    ///
    /// A tree push shows this phase from the start of its scan to the end of
    /// the walk, which lists and filters each directory. Hash jobs can run in
    /// this phase. A new [`PushProgress`] starts in this phase.
    #[default]
    Scanning,
    /// The client hashes the files and the directories of a tree.
    ///
    /// A tree push shows this phase after the walk. In this phase, the hash
    /// jobs that still run come to an end, and the client hashes the
    /// directories bottom-up.
    Hashing,
    /// The session starts its transport and exchanges `Hello` with the server.
    ///
    /// In this phase, an ssh client can ask for a password or a passphrase on
    /// the terminal.
    Connecting,
    /// The session exchanges `Have` with the server.
    Negotiating,
    /// The session sends objects.
    Uploading,
    /// The session sends `Commit` and waits for the reply.
    Committing,
}

impl PushPhase {
    fn as_u8(self) -> u8 {
        match self {
            PushPhase::Scanning => 0,
            PushPhase::Hashing => 1,
            PushPhase::Negotiating => 2,
            PushPhase::Uploading => 3,
            PushPhase::Committing => 4,
            PushPhase::Connecting => 5,
        }
    }

    fn from_u8(byte: u8) -> PushPhase {
        match byte {
            1 => PushPhase::Hashing,
            2 => PushPhase::Negotiating,
            3 => PushPhase::Uploading,
            4 => PushPhase::Committing,
            5 => PushPhase::Connecting,
            _ => PushPhase::Scanning,
        }
    }
}

/// A hook that receives the counters of a [`PushProgress`] when they change.
///
/// The hook gets a call only at a change that a progress display shows.
/// [Hook calls](PushProgress#hook-calls) lists these changes.
///
/// The hook runs on the task that changed the counters: the task of the
/// session, or the task of the scan of a tree push. Over HTTP, each parallel
/// object stream of a session calls the hook, so more than one thread can call
/// it at the same time. The session waits for the hook, so the hook must
/// return soon.
///
/// A hook that keeps state between calls holds that state behind interior
/// mutability of its own, for example an atomic or a mutex.
pub type PushProgressFn = Arc<dyn Fn(&PushProgressSnapshot) + Send + Sync>;

/// The step of the content count at which the hook gets a call: 100 KiB.
const HOOK_BYTE_STEP: u64 = 102_400;

/// A handle on the live counters of pushes.
///
/// A caller sets a clone of the handle in
/// [`SessionOptions::progress`](super::SessionOptions::progress). Then it
/// reads [`snapshot`](PushProgress::snapshot) from another task or thread
/// while the push runs. A session adds to the counters of the handle and
/// never sets them to zero.
///
/// If several sessions share a handle, the handle shows the sum of their
/// counters and the phase of the session that set it last.
///
/// The [`PushStats`] of a session come from counters of its own, and the
/// handle does not change them. Each count is one relaxed atomic add to those
/// counters, and one more to the handle if the session has one.
///
/// # Hook calls
///
/// A handle made with [`with_hook`](PushProgress::with_hook) calls its hook
/// with a snapshot at these changes:
///
/// - each time the phase changes to another phase
/// - after each object of the object stream, when
///   [`objects_sent`](PushProgressSnapshot::objects_sent) grows
/// - each time [`content_bytes`](PushProgressSnapshot::content_bytes)
///   reaches the next multiple of 102,400 bytes (100 KiB)
#[derive(Debug, Clone, Default)]
pub struct PushProgress {
    inner: Arc<ProgressCounters>,
}

impl PushProgress {
    /// Creates a handle whose counters are all zero.
    pub fn new() -> PushProgress {
        PushProgress::default()
    }

    /// Creates a handle whose counters are all zero and that calls `hook`.
    ///
    /// [Hook calls](PushProgress#hook-calls) lists the calls.
    /// [`PushProgressFn`] gives the rules of the hook.
    pub fn with_hook(hook: PushProgressFn) -> PushProgress {
        PushProgress {
            inner: Arc::new(ProgressCounters {
                hook: Some(hook),
                ..ProgressCounters::default()
            }),
        }
    }

    /// Returns the counters as they stand now.
    ///
    /// The method reads each counter on its own, so two counters of one
    /// snapshot can differ by the work of one step.
    pub fn snapshot(&self) -> PushProgressSnapshot {
        self.inner.snapshot()
    }

    /// Sets the phase of the handle. A tree push sets the phases of its scan
    /// before a session opens.
    pub(crate) fn set_phase(&self, phase: PushPhase) {
        self.inner.set_phase(phase);
    }
}

/// The counters of a [`PushProgress`] at one point in time.
///
/// Code outside this crate gets a snapshot from [`PushProgress::snapshot`],
/// from the hook, or from `Default`, and reads its fields by name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PushProgressSnapshot {
    /// The step that the push is in.
    pub phase: PushPhase,
    /// The count of [`PushStats::objects_total`] so far.
    pub objects_total: u64,
    /// The count of [`PushStats::objects_needed`] so far.
    pub objects_needed: u64,
    /// The count of [`PushStats::objects_sent`] so far.
    pub objects_sent: u64,
    /// The count of [`PushStats::bytes_sent`] so far.
    pub bytes_sent: u64,
    /// The count of [`PushStats::payload_bytes`] so far.
    pub payload_bytes: u64,
    /// The content bytes that the session read so far.
    ///
    /// These are the bytes that the session read from the reader that its
    /// source gave for each file object, before the compressor of the
    /// session. A stored `.filez` that the session sends as it is counts
    /// with its stored bytes. A symlink, a metadata object, and detached
    /// metadata count no byte.
    pub content_bytes: u64,
    /// The content bytes of the file objects that the session sends.
    ///
    /// The source tells this total before the first object, so
    /// `content_bytes` ends at this total. If the source does not tell it,
    /// or the query fails, the total stays 0. See
    /// [`ObjectSource::content_size`](super::ObjectSource::content_size).
    pub bytes_total: u64,
}

/// The statistics of one push session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PushStats {
    /// The number of objects that the client offered in `Have`.
    pub objects_total: u64,
    /// The number of objects that the server asked for in `HaveReply`.
    pub objects_needed: u64,
    /// The number of objects that the session sent in the object stream.
    ///
    /// A detached metadata object does not count.
    pub objects_sent: u64,
    /// The number of bytes that the session gave to its transport.
    ///
    /// The count holds the frames, the chunk lengths, and the object bytes.
    /// On a stream transport, a byte counts when the session writes it to
    /// the stream.
    ///
    /// Over HTTP, the request bodies count and the HTTP heads do not:
    ///
    /// - A whole body, as for `Hello`, `Have`, and `Commit`, counts when the
    ///   client gives its request to a connection. It counts if the request
    ///   gets a response, and also if the request fails after the hand-over.
    /// - An object stream counts each byte that it writes into its request
    ///   body after the hand-over. At the hand-over, it counts the bytes that
    ///   it wrote before.
    /// - A request that the client never gives to a connection counts no
    ///   byte.
    pub bytes_sent: u64,
    /// The object bytes that the session sent, without the chunk lengths.
    ///
    /// The bytes are in the encoding that the session sent them in. Detached
    /// metadata objects count.
    pub payload_bytes: u64,
    /// The time that the session ran.
    ///
    /// The clock starts when the session opens: after the ssh client starts,
    /// or before the first HTTP request. The scan and the hash pass of a tree
    /// push do not count.
    pub elapsed: Duration,
}

/// The counters behind a [`PushProgress`], and the counters of one session.
#[derive(Default)]
struct ProgressCounters {
    phase: AtomicU8,
    objects_total: AtomicU64,
    objects_needed: AtomicU64,
    objects_sent: AtomicU64,
    bytes_sent: AtomicU64,
    payload_bytes: AtomicU64,
    content_bytes: AtomicU64,
    bytes_total: AtomicU64,
    /// The hook of the handle. The counters of a session have none.
    hook: Option<PushProgressFn>,
}

impl fmt::Debug for ProgressCounters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProgressCounters")
            .field("counters", &self.snapshot())
            .field("hook", &self.hook.is_some())
            .finish()
    }
}

impl ProgressCounters {
    fn snapshot(&self) -> PushProgressSnapshot {
        PushProgressSnapshot {
            phase: PushPhase::from_u8(self.phase.load(Ordering::Relaxed)),
            objects_total: self.objects_total.load(Ordering::Relaxed),
            objects_needed: self.objects_needed.load(Ordering::Relaxed),
            objects_sent: self.objects_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            payload_bytes: self.payload_bytes.load(Ordering::Relaxed),
            content_bytes: self.content_bytes.load(Ordering::Relaxed),
            bytes_total: self.bytes_total.load(Ordering::Relaxed),
        }
    }

    /// Calls the hook with the counters as they stand.
    fn call_hook(&self) {
        if let Some(hook) = &self.hook {
            hook(&self.snapshot());
        }
    }

    /// Sets the phase, and calls the hook if the phase changed.
    fn set_phase(&self, phase: PushPhase) {
        let before = self.phase.swap(phase.as_u8(), Ordering::Relaxed);
        if before != phase.as_u8() {
            self.call_hook();
        }
    }

    /// Counts one object sent, and calls the hook.
    fn object_sent(&self) {
        self.objects_sent.fetch_add(1, Ordering::Relaxed);
        self.call_hook();
    }

    /// Counts `n` content bytes, and calls the hook if the count reaches the
    /// next multiple of [`HOOK_BYTE_STEP`].
    fn content(&self, n: u64) {
        let before = self.content_bytes.fetch_add(n, Ordering::Relaxed);
        if before / HOOK_BYTE_STEP != before.wrapping_add(n) / HOOK_BYTE_STEP {
            self.call_hook();
        }
    }
}

/// The counters that one session counts into: its own, which its
/// [`PushStats`] read, and the handle of the caller, which receives the same
/// additions.
#[derive(Debug)]
pub(crate) struct Counters {
    own: ProgressCounters,
    caller: Option<Arc<ProgressCounters>>,
    start: Instant,
}

impl Counters {
    /// Creates the counters of a session that starts now. The session also
    /// counts into `caller` if there is one.
    pub(crate) fn new(caller: Option<&PushProgress>) -> Counters {
        Counters {
            own: ProgressCounters::default(),
            caller: caller.map(|progress| Arc::clone(&progress.inner)),
            start: Instant::now(),
        }
    }

    /// Runs `f` on the own counters of the session, then on the counters of
    /// the caller.
    fn each(&self, f: impl Fn(&ProgressCounters)) {
        f(&self.own);
        if let Some(caller) = &self.caller {
            f(caller);
        }
    }

    pub(crate) fn phase(&self, phase: PushPhase) {
        self.each(|c| c.set_phase(phase));
    }

    pub(crate) fn offered(&self, n: u64) {
        self.each(|c| {
            c.objects_total.fetch_add(n, Ordering::Relaxed);
        });
    }

    pub(crate) fn needed(&self, n: u64) {
        self.each(|c| {
            c.objects_needed.fetch_add(n, Ordering::Relaxed);
        });
    }

    pub(crate) fn object_sent(&self) {
        self.each(ProgressCounters::object_sent);
    }

    /// Counts `n` content bytes read from the source of a file object.
    pub(crate) fn content(&self, n: u64) {
        self.each(|c| c.content(n));
    }

    /// Adds `n` to the content bytes that the session will send.
    pub(crate) fn content_total(&self, n: u64) {
        self.each(|c| {
            c.bytes_total.fetch_add(n, Ordering::Relaxed);
        });
    }

    /// Returns `true` if a handle of the caller receives the counts.
    pub(crate) fn has_caller(&self) -> bool {
        self.caller.is_some()
    }

    pub(crate) fn wire(&self, n: u64) {
        self.each(|c| {
            c.bytes_sent.fetch_add(n, Ordering::Relaxed);
        });
    }

    pub(crate) fn payload(&self, n: u64) {
        self.each(|c| {
            c.payload_bytes.fetch_add(n, Ordering::Relaxed);
        });
    }

    /// Returns the statistics of the session so far.
    pub(crate) fn stats(&self) -> PushStats {
        let s = self.own.snapshot();
        PushStats {
            objects_total: s.objects_total,
            objects_needed: s.objects_needed,
            objects_sent: s.objects_sent,
            bytes_sent: s.bytes_sent,
            payload_bytes: s.payload_bytes,
            elapsed: self.start.elapsed(),
        }
    }
}
