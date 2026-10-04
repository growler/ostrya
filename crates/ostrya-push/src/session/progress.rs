//! The progress handle of a push and the statistics of a session.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The step a push is in.
///
/// The enum is `#[non_exhaustive]`, so a match outside the crate needs a
/// wildcard arm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PushPhase {
    /// The client reads its source and builds the object list. A tree push
    /// shows it from the start of its scan until the walk has listed and
    /// filtered each directory. Hash jobs can run during it.
    #[default]
    Scanning,
    /// The client hashes the files of a tree. A tree push shows it after the
    /// walk, while the hash jobs still in flight end and the directories are
    /// hashed bottom-up.
    Hashing,
    /// The session starts its transport and exchanges `Hello` with the
    /// server. An ssh client can ask for a password or a passphrase on the
    /// terminal in this phase.
    Connecting,
    /// The session exchanges `Have` with the server.
    Negotiating,
    /// The session sends objects.
    Uploading,
    /// The session sent `Commit` and waits for the reply.
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

/// The hook of a [`PushProgress`]: a function that receives the counters of
/// the handle when they change in a way a progress display shows.
///
/// The hook runs on the task that changed the counters: the task of the
/// session, or the task of the scan of a tree push. Over HTTP each parallel
/// object stream of a session calls it, so it can be called from more than
/// one thread at the same time. The hook must return soon, because the
/// session waits for it. A hook that keeps state between calls holds that
/// state behind its own interior mutability, for example an atomic or a
/// mutex.
pub type PushProgressFn = Arc<dyn Fn(&PushProgressSnapshot) + Send + Sync>;

/// The number of content bytes between two calls of the hook that the
/// content bytes make: 100 KiB.
const HOOK_BYTE_STEP: u64 = 102_400;

/// The live counters of pushes, which a caller reads while they run.
///
/// A caller sets a clone of the handle in
/// [`SessionOptions::progress`](super::SessionOptions::progress) and reads
/// [`snapshot`](PushProgress::snapshot) from another task or thread. A
/// session adds to the counters of the handle and never sets them to zero. A
/// handle that several sessions share shows the sum of their counters, and the
/// phase of the session that set it last.
///
/// A handle made with [`with_hook`](PushProgress::with_hook) also calls its
/// hook with a snapshot:
///
/// - each time the phase changes to another phase;
/// - after each object of the object stream, when
///   [`objects_sent`](PushProgressSnapshot::objects_sent) grows;
/// - each time [`content_bytes`](PushProgressSnapshot::content_bytes)
///   reaches the next multiple of 102,400 bytes.
///
/// The [`PushStats`] of a session come from counters of its own, whatever the
/// handle holds. Each count is one relaxed atomic add to those counters, and
/// one more to the handle when the session has one.
#[derive(Debug, Clone, Default)]
pub struct PushProgress {
    inner: Arc<ProgressCounters>,
}

impl PushProgress {
    /// A handle whose counters are all zero.
    pub fn new() -> PushProgress {
        PushProgress::default()
    }

    /// A handle whose counters are all zero, and which calls `hook` as the
    /// type docs state. [`PushProgressFn`] gives the rules of the hook.
    pub fn with_hook(hook: PushProgressFn) -> PushProgress {
        PushProgress {
            inner: Arc::new(ProgressCounters {
                hook: Some(hook),
                ..ProgressCounters::default()
            }),
        }
    }

    /// The counters as they stand. Each counter is read on its own, so two
    /// counters of one snapshot can differ by the work of one step.
    pub fn snapshot(&self) -> PushProgressSnapshot {
        self.inner.snapshot()
    }

    /// Set the phase of the handle. A tree push sets the phases of its scan
    /// before a session opens.
    pub(crate) fn set_phase(&self, phase: PushPhase) {
        self.inner.set_phase(phase);
    }
}

/// The counters of a [`PushProgress`] at one point in time.
///
/// Code outside this crate gets one from [`PushProgress::snapshot`], from
/// the hook, or from `Default`. A later version can add a field, so that
/// code reads the fields by name and makes no struct literal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PushProgressSnapshot {
    /// The step the push is in.
    pub phase: PushPhase,
    /// As [`PushStats::objects_total`], so far.
    pub objects_total: u64,
    /// As [`PushStats::objects_needed`], so far.
    pub objects_needed: u64,
    /// As [`PushStats::objects_sent`], so far.
    pub objects_sent: u64,
    /// As [`PushStats::bytes_sent`], so far.
    pub bytes_sent: u64,
    /// As [`PushStats::payload_bytes`], so far.
    pub payload_bytes: u64,
    /// The content bytes the session read so far: the bytes it read from
    /// the reader that its source gave for each file object, before its own
    /// compressor. A stored `.filez` that the session sends as it is counts
    /// with its stored bytes. A symlink, a metadata object, and detached
    /// metadata count no byte.
    pub content_bytes: u64,
    /// The content bytes of the file objects that the session sends, as the
    /// source told them before the first object, so that `content_bytes`
    /// ends at this total. It stays 0 when the source does not tell it: see
    /// [`ObjectSource::content_size`](super::ObjectSource::content_size).
    pub bytes_total: u64,
}

/// What one push session sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PushStats {
    /// The objects the client offered in `Have`.
    pub objects_total: u64,
    /// The objects the server asked for in `HaveReply`.
    pub objects_needed: u64,
    /// The objects sent in the object stream. A detached metadata object
    /// does not count.
    pub objects_sent: u64,
    /// The bytes the session handed to its transport: frames, chunk
    /// lengths, and object bytes.
    ///
    /// On a stream transport, each byte counts when the session writes it
    /// to the stream. Over HTTP, the bodies of the requests count, and the
    /// HTTP heads do not. A body given whole, as for `Hello`, `Have`, and
    /// `Commit`, counts when the client handed its request to a connection:
    /// when the request gets a response, and when it fails after the
    /// hand-over. An object stream counts each byte it writes into its
    /// request body once the request is handed over, and the bytes it wrote
    /// before the hand-over at that time. A request that is never handed
    /// over counts no byte.
    pub bytes_sent: u64,
    /// The object bytes sent, in the encoding they were sent in, without the
    /// chunk lengths. Detached metadata objects count.
    pub payload_bytes: u64,
    /// How long the session ran.
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

    /// Call the hook with the counters as they stand.
    fn call_hook(&self) {
        if let Some(hook) = &self.hook {
            hook(&self.snapshot());
        }
    }

    /// Set the phase, and call the hook when the phase changed.
    fn set_phase(&self, phase: PushPhase) {
        let before = self.phase.swap(phase.as_u8(), Ordering::Relaxed);
        if before != phase.as_u8() {
            self.call_hook();
        }
    }

    /// Count one object sent, and call the hook.
    fn object_sent(&self) {
        self.objects_sent.fetch_add(1, Ordering::Relaxed);
        self.call_hook();
    }

    /// Count `n` content bytes, and call the hook when the count reached the
    /// next multiple of [`HOOK_BYTE_STEP`].
    fn content(&self, n: u64) {
        let before = self.content_bytes.fetch_add(n, Ordering::Relaxed);
        if before / HOOK_BYTE_STEP != before.wrapping_add(n) / HOOK_BYTE_STEP {
            self.call_hook();
        }
    }
}

/// The counters one session counts into: its own, which its [`PushStats`]
/// read, and the caller's handle, which receives the same additions.
#[derive(Debug)]
pub(crate) struct Counters {
    own: ProgressCounters,
    caller: Option<Arc<ProgressCounters>>,
    start: Instant,
}

impl Counters {
    /// The counters of a session that starts now, which also counts into
    /// `caller` where there is one.
    pub(crate) fn new(caller: Option<&PushProgress>) -> Counters {
        Counters {
            own: ProgressCounters::default(),
            caller: caller.map(|progress| Arc::clone(&progress.inner)),
            start: Instant::now(),
        }
    }

    /// Run `f` on the session's own counters, then on the caller's.
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

    /// Count `n` content bytes read from the source of a file object.
    pub(crate) fn content(&self, n: u64) {
        self.each(|c| c.content(n));
    }

    /// Add `n` to the content bytes the session is to send.
    pub(crate) fn content_total(&self, n: u64) {
        self.each(|c| {
            c.bytes_total.fetch_add(n, Ordering::Relaxed);
        });
    }

    /// Whether a caller's handle receives the counts.
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

    /// The statistics of the session so far.
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
