//! The progress handle of a push and the statistics of a session.

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
    /// The session exchanges `Hello` and `Have` with the server.
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
        }
    }

    fn from_u8(byte: u8) -> PushPhase {
        match byte {
            1 => PushPhase::Hashing,
            2 => PushPhase::Negotiating,
            3 => PushPhase::Uploading,
            4 => PushPhase::Committing,
            _ => PushPhase::Scanning,
        }
    }
}

/// The live counters of pushes, which a caller reads while they run.
///
/// A caller sets a clone of the handle in
/// [`SessionOptions::progress`](super::SessionOptions::progress) and reads
/// [`snapshot`](PushProgress::snapshot) from another task or thread. A
/// session adds to the counters of the handle and never sets them to zero. A
/// handle that several sessions share shows the sum of their counters, and the
/// phase of the session that set it last.
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

    /// The counters as they stand. Each counter is read on its own, so two
    /// counters of one snapshot can differ by the work of one step.
    pub fn snapshot(&self) -> PushProgressSnapshot {
        self.inner.snapshot()
    }

    /// Set the phase of the handle. A tree push sets the phases of its scan
    /// before a session opens.
    pub(crate) fn set_phase(&self, phase: PushPhase) {
        self.inner.phase.store(phase.as_u8(), Ordering::Relaxed);
    }
}

/// The counters of a [`PushProgress`] at one point in time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
#[derive(Debug, Default)]
struct ProgressCounters {
    phase: AtomicU8,
    objects_total: AtomicU64,
    objects_needed: AtomicU64,
    objects_sent: AtomicU64,
    bytes_sent: AtomicU64,
    payload_bytes: AtomicU64,
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
        self.each(|c| c.phase.store(phase.as_u8(), Ordering::Relaxed));
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
        self.each(|c| {
            c.objects_sent.fetch_add(1, Ordering::Relaxed);
        });
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
