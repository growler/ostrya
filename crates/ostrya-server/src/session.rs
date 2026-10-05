//! The sessions of the receive endpoint.
//!
//! The table holds one entry for each open session: the
//! [`ReceiveService`] of the session, its owner, the time of its last
//! activity, the count of its requests in progress, the request bodies in
//! flight with the time each one started to wait for the client, and a
//! cancel signal that ends the requests of the session in flight. One sweep
//! task applies the idle timeout to every entry. The lock of the table is
//! never held while a service is aborted or dropped.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use ostrya::{Checksum, ReceiveService};
use ostrya_rt as rt;

use crate::shutdown::{Shutdown, Wait};

/// The cause of a session with no request in progress for the idle timeout.
const IDLE: &str = "the session was idle for the idle timeout";

/// The cause of a session with a request body that delivered no byte for the
/// idle timeout.
const SILENT: &str = "a request body of the session delivered no byte for the idle timeout";

/// The cause of a session whose request failed.
const FAILED: &str = "a request of the session failed";

/// The cause of a session whose request ended before its response, for
/// example when the client closed the connection.
const CUT: &str = "a request of the session ended before its response";

/// The cause of a session that a `DELETE` ended.
const DELETED: &str = "the client deleted the session";

/// The cause of the end of a session after its commit.
const COMMITTED: &str = "the session committed";

/// The cause of the sessions that the stop of the server ended.
const STOPPED: &str = "the server stopped";

/// The id of a session: 32 random bytes, shown as 64 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionId {
    inner: [u8; 32],
}

impl SessionId {
    /// A new id from the random source of the operating system.
    pub(crate) fn new() -> Result<SessionId, getrandom::Error> {
        let mut inner = [0u8; 32];
        getrandom::fill(&mut inner)?;
        Ok(SessionId { inner })
    }

    /// The id that `text` shows. The text is exactly 64 lowercase hex
    /// digits, and any other text gives `None`.
    pub(crate) fn parse(text: &str) -> Option<SessionId> {
        let checksum = Checksum::from_hex_lower(text).ok()?;
        Some(SessionId {
            inner: *checksum.as_bytes(),
        })
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&Checksum::from_bytes(self.inner).to_hex())
    }
}

/// The signal that ends the requests of one session in flight, and the
/// cause the requests report.
pub(crate) struct Cancel {
    signal: Arc<Shutdown>,
    cause: OnceLock<&'static str>,
}

impl Cancel {
    fn new() -> Arc<Cancel> {
        Arc::new(Cancel {
            signal: Arc::new(Shutdown::default()),
            cause: OnceLock::new(),
        })
    }

    /// Record `cause`, unless a cause is already recorded, and wake each
    /// waiter.
    fn fire(&self, cause: &'static str) {
        let _ = self.cause.set(cause);
        self.signal.fire();
    }

    /// A future that completes when the session ends.
    pub(crate) fn wait(&self) -> Wait {
        self.signal.wait()
    }

    /// Why the session ended.
    pub(crate) fn cause(&self) -> &'static str {
        self.cause.get().copied().unwrap_or(STOPPED)
    }
}

/// One open session.
struct Entry {
    service: Arc<ReceiveService>,
    /// The owner key of the session.
    owner: String,
    /// The time of the last activity.
    last: Instant,
    /// The requests of the session in progress.
    active: usize,
    /// Each request body in flight, by its id, with the time it started to
    /// wait for the client, or `None` while it does not wait.
    bodies: HashMap<u64, Option<Instant>>,
    cancel: Arc<Cancel>,
    /// The commit of the session runs. The sweep and a `DELETE` leave the
    /// session alone.
    committing: bool,
    /// A request body of the session failed, as when the client closed the
    /// connection. A failed request then ends the session with the cause of
    /// a request that ended before its response.
    cut: bool,
}

impl Entry {
    /// End the session with `cause`: wake its requests in flight and abort
    /// its service. The caller holds no lock of the table.
    fn close(self, cause: &'static str) {
        self.cancel.fire(cause);
        self.service.abort();
    }
}

struct State {
    entries: HashMap<SessionId, Entry>,
    /// The slots reserved for sessions that open now.
    pending: usize,
    next_body: u64,
    /// The server stopped. The table takes no session from now on.
    closed: bool,
}

/// The open sessions of a server.
pub(crate) struct SessionTable {
    max: usize,
    idle: Duration,
    state: Mutex<State>,
}

/// The answer of [`SessionTable::delete`].
pub(crate) enum Deleted {
    /// The session ended.
    Done,
    /// The session commits, and the commit goes on.
    Committing,
    /// No session of the owner has the id.
    NotFound,
}

impl SessionTable {
    /// A table of at most `max` sessions, each aborted after `idle` with no
    /// request in progress.
    pub(crate) fn new(max: usize, idle: Duration) -> Arc<SessionTable> {
        Arc::new(SessionTable {
            max,
            idle,
            state: Mutex::new(State {
                entries: HashMap::new(),
                pending: 0,
                next_body: 0,
                closed: false,
            }),
        })
    }

    /// The idle timeout.
    pub(crate) fn idle(&self) -> Duration {
        self.idle
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("session table mutex")
    }

    /// Reserve the slot of a session that opens now, or `None` when the open
    /// sessions and the reserved slots are at the limit, or the server
    /// stopped.
    pub(crate) fn reserve(self: &Arc<SessionTable>) -> Option<Reservation> {
        let mut state = self.lock();
        if state.closed || state.entries.len() + state.pending >= self.max {
            return None;
        }
        state.pending += 1;
        Some(Reservation {
            table: self.clone(),
            used: false,
        })
    }

    /// The session `id` of the owner key `owner`, counted as active until the
    /// returned value drops. An unknown id and a session of another owner
    /// both give `None`.
    pub(crate) fn lookup(self: &Arc<SessionTable>, id: &SessionId, owner: &str) -> Option<Active> {
        let mut state = self.lock();
        let entry = state.entries.get_mut(id).filter(|e| e.owner == owner)?;
        entry.active += 1;
        Some(Active {
            table: self.clone(),
            id: *id,
            service: entry.service.clone(),
            cancel: entry.cancel.clone(),
            complete: false,
        })
    }

    /// End the session `id` of the owner key `owner` for a `DELETE`. A
    /// session that commits is left as it is.
    pub(crate) fn delete(&self, id: &SessionId, owner: &str) -> Deleted {
        let entry = {
            let mut state = self.lock();
            match state.entries.get(id) {
                Some(entry) if entry.owner == owner => {
                    if entry.committing {
                        return Deleted::Committing;
                    }
                }
                _ => return Deleted::NotFound,
            }
            state.entries.remove(id)
        };
        if let Some(entry) = entry {
            entry.close(DELETED);
        }
        Deleted::Done
    }

    /// Remove the session `id` and end it with `cause`. An id that is not in
    /// the table does nothing.
    pub(crate) fn end(&self, id: &SessionId, cause: &'static str) {
        let entry = self.lock().entries.remove(id);
        if let Some(entry) = entry {
            entry.close(cause);
        }
    }

    /// Remove the session `id` and end it after a failed request. A session
    /// that commits is left as it is, because its commit goes on and removes
    /// it at the end. A session with a request body that failed ends with
    /// the cause of a request that ended before its response.
    pub(crate) fn fail(&self, id: &SessionId) {
        let entry = {
            let mut state = self.lock();
            match state.entries.get(id) {
                Some(entry) if !entry.committing => state.entries.remove(id),
                _ => None,
            }
        };
        if let Some(entry) = entry {
            let cause = if entry.cut { CUT } else { FAILED };
            entry.close(cause);
        }
    }

    /// End every session, when the server stops. The table takes no session
    /// after it.
    pub(crate) fn close_all(&self) {
        let entries: Vec<Entry> = {
            let mut state = self.lock();
            state.closed = true;
            state.entries.drain().map(|(_, e)| e).collect()
        };
        for entry in entries {
            entry.close(STOPPED);
        }
    }

    /// Abort each session past its idle timeout, and each session with a
    /// request body that waited for the idle timeout, until the future is
    /// dropped. A session that commits is never aborted. The task sleeps to
    /// the earliest deadline, and at most one idle timeout. A deadline that
    /// arises while it sleeps is one idle timeout or more after its start,
    /// so it is never before the end of the sleep.
    pub(crate) async fn sweep(&self) {
        loop {
            let (expired, wait) = self.expire(Instant::now());
            for (entry, cause) in expired {
                entry.close(cause);
            }
            rt::Timer::after(wait).await;
        }
    }

    /// Remove each session past a deadline at `now`, with its cause, and give
    /// the time from `now` to the next deadline, at most one idle timeout.
    fn expire(&self, now: Instant) -> (Vec<(Entry, &'static str)>, Duration) {
        let mut state = self.lock();
        let mut next = self.idle;
        let mut due = Vec::new();
        for (id, entry) in &state.entries {
            if entry.committing {
                continue;
            }
            let silent = entry
                .bodies
                .values()
                .flatten()
                .map(|since| (*since, SILENT));
            let idle = (entry.active == 0).then_some((entry.last, IDLE));
            let Some((since, cause)) = silent.chain(idle).min_by_key(|(since, _)| *since) else {
                continue;
            };
            match (since + self.idle).checked_duration_since(now) {
                Some(left) if !left.is_zero() => next = next.min(left),
                _ => due.push((*id, cause)),
            }
        }
        let expired = due
            .into_iter()
            .filter_map(|(id, cause)| state.entries.remove(&id).map(|entry| (entry, cause)))
            .collect();
        (expired, next)
    }
}

/// A slot of the table for a session that opens now. Dropping it unused
/// frees the slot.
pub(crate) struct Reservation {
    table: Arc<SessionTable>,
    used: bool,
}

impl Reservation {
    /// Put the session `id` of the owner key `owner` into the slot. `false`
    /// when the server stopped after the slot was reserved: the service is
    /// then aborted and dropped, and the table holds no entry for it.
    pub(crate) fn insert(mut self, id: SessionId, service: ReceiveService, owner: String) -> bool {
        let mut state = self.table.lock();
        state.pending -= 1;
        self.used = true;
        if state.closed {
            drop(state);
            service.abort();
            drop(service);
            return false;
        }
        state.entries.insert(
            id,
            Entry {
                service: Arc::new(service),
                owner,
                last: Instant::now(),
                active: 0,
                bodies: HashMap::new(),
                cancel: Cancel::new(),
                committing: false,
                cut: false,
            },
        );
        true
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.used {
            self.table.lock().pending -= 1;
        }
    }
}

/// A request of a session in progress. Dropping it ends the count, and the
/// idle time of the session starts again. A request dropped before its
/// response, as when the client closes the connection, ends the session
/// unless the session commits.
pub(crate) struct Active {
    table: Arc<SessionTable>,
    id: SessionId,
    service: Arc<ReceiveService>,
    cancel: Arc<Cancel>,
    /// The request has its response.
    complete: bool,
}

impl Active {
    /// Record that the request has its response.
    pub(crate) fn complete(&mut self) {
        self.complete = true;
    }

    pub(crate) fn id(&self) -> SessionId {
        self.id
    }

    pub(crate) fn service(&self) -> &Arc<ReceiveService> {
        &self.service
    }

    pub(crate) fn cancel(&self) -> &Arc<Cancel> {
        &self.cancel
    }

    pub(crate) fn table(&self) -> &Arc<SessionTable> {
        &self.table
    }

    /// Record a request body of the session, which waits for nothing yet.
    pub(crate) fn track(&self) -> BodyTrack {
        let mut state = self.table.lock();
        let body = state.next_body;
        state.next_body += 1;
        if let Some(entry) = state.entries.get_mut(&self.id) {
            entry.bodies.insert(body, None);
        }
        BodyTrack {
            table: self.table.clone(),
            id: self.id,
            body,
        }
    }

    /// Mark the session as committing, unless it commits already or it
    /// ended.
    pub(crate) fn begin_commit(&self) -> Begin {
        let mut state = self.table.lock();
        let Some(entry) = state.entries.get_mut(&self.id) else {
            return Begin::Ended;
        };
        if entry.committing {
            return Begin::Committing;
        }
        entry.committing = true;
        Begin::Started(CommitEnd {
            table: self.table.clone(),
            id: self.id,
            cause: FAILED,
        })
    }
}

/// The answer of [`Active::begin_commit`].
pub(crate) enum Begin {
    /// The session commits from now on. The guard ends the session when it
    /// drops.
    Started(CommitEnd),
    /// The session commits already, and its commit goes on.
    Committing,
    /// The session ended.
    Ended,
}

/// The end of a session that commits. When it drops, it removes the session
/// and ends it with the cause of a commit, or with the cause of a failed
/// request unless [`committed`](Self::committed) ran. A commit that panics
/// or is dropped thus frees its slot.
pub(crate) struct CommitEnd {
    table: Arc<SessionTable>,
    id: SessionId,
    cause: &'static str,
}

impl CommitEnd {
    /// Record that the commit succeeded.
    pub(crate) fn committed(&mut self) {
        self.cause = COMMITTED;
    }
}

impl Drop for CommitEnd {
    fn drop(&mut self) {
        self.table.end(&self.id, self.cause);
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        let cut = {
            let mut state = self.table.lock();
            let Some(entry) = state.entries.get_mut(&self.id) else {
                return;
            };
            entry.active -= 1;
            entry.last = Instant::now();
            if self.complete || entry.committing {
                return;
            }
            state.entries.remove(&self.id)
        };
        if let Some(entry) = cut {
            entry.close(CUT);
        }
    }
}

/// The record of one request body in its session. It drops with the body.
pub(crate) struct BodyTrack {
    table: Arc<SessionTable>,
    id: SessionId,
    body: u64,
}

impl BodyTrack {
    /// Record that the body waits for the client from now on.
    pub(crate) fn waiting(&self) {
        self.set(Some(Instant::now()));
    }

    /// Record that the body delivered bytes now.
    pub(crate) fn progress(&self) {
        self.set(None);
    }

    /// Record that the body failed, as when the client closed the
    /// connection.
    pub(crate) fn cut(&self) {
        if let Some(entry) = self.table.lock().entries.get_mut(&self.id) {
            entry.cut = true;
        }
    }

    fn set(&self, since: Option<Instant>) {
        let mut state = self.table.lock();
        if let Some(entry) = state.entries.get_mut(&self.id) {
            if since.is_none() {
                entry.last = Instant::now();
            }
            if let Some(slot) = entry.bodies.get_mut(&self.body) {
                *slot = since;
            }
        }
    }
}

impl Drop for BodyTrack {
    fn drop(&mut self) {
        let mut state = self.table.lock();
        if let Some(entry) = state.entries.get_mut(&self.id) {
            entry.bodies.remove(&self.body);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;

    use ostrya::push::proto::Hello;
    use ostrya::{CreateOptions, ReceivePolicy, Repo, RepoMode};
    use ostrya_rt::block_on;

    use super::*;

    /// A repository in a directory of its own, removed with the value once
    /// no staging directory is left.
    pub(crate) struct TmpRepo {
        path: PathBuf,
        pub(crate) repo: Repo,
    }

    impl TmpRepo {
        pub(crate) fn new(tag: &str) -> TmpRepo {
            let path = std::env::temp_dir().join(format!(
                "ostrya-server-session-{}-{tag}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            let repo =
                block_on(Repo::create(&path, CreateOptions::new(RepoMode::Archive))).unwrap();
            TmpRepo { path, repo }
        }

        /// A new open session over the repository.
        fn service(&self) -> ReceiveService {
            let hello = Hello {
                version: 1,
                agent: None,
                refs: vec!["main".into()],
                one_way: false,
            };
            let policy = Arc::new(ReceivePolicy::default());
            block_on(ReceiveService::hello(self.repo.clone(), policy, 1, hello))
                .unwrap()
                .0
        }
    }

    impl Drop for TmpRepo {
        /// The core of an ended session goes on the blocking pool, so the
        /// staging directory can stay for a short time.
        fn drop(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                let staging = std::fs::read_dir(self.path.join("tmp")).map(|dir| {
                    dir.flatten()
                        .any(|e| e.file_name().to_string_lossy().starts_with("staging-"))
                });
                if !matches!(staging, Ok(true)) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// A table of one session over `repo`, and the id of the session.
    fn one_session(repo: &TmpRepo) -> (Arc<SessionTable>, SessionId) {
        let table = SessionTable::new(1, Duration::from_secs(60));
        let id = SessionId::new().unwrap();
        let slot = table.reserve().unwrap();
        assert!(slot.insert(id, repo.service(), "anonymous".into()));
        (table, id)
    }

    /// A new id is 64 lowercase hex digits, and the parser takes that form
    /// alone.
    #[test]
    fn a_session_id_is_64_lowercase_hex_digits() {
        let a = SessionId::new().unwrap();
        let b = SessionId::new().unwrap();
        assert!(a != b, "two ids of 32 random bytes differ");
        let text = a.to_string();
        assert_eq!(text.len(), 64);
        assert!(
            text.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "{text}"
        );
        assert!(SessionId::parse(&text) == Some(a));
        let upper = text.to_ascii_uppercase();
        let short = &text[..63];
        let long = format!("{text}0");
        let other = format!("{}g", &text[..63]);
        for bad in [upper.as_str(), short, long.as_str(), other.as_str(), ""] {
            assert!(SessionId::parse(bad).is_none(), "{bad}");
        }
    }

    /// A slot counts against the limit until it is used or dropped.
    #[test]
    fn a_reservation_counts_against_the_limit() {
        let table = SessionTable::new(1, Duration::from_secs(60));
        let slot = table.reserve().unwrap();
        assert!(table.reserve().is_none());
        drop(slot);
        assert!(table.reserve().is_some());
    }

    /// A request that drops before its response ends its session with the
    /// cause of a cut request, and the other requests of the session see the
    /// cause. A request with its response leaves the session.
    #[test]
    fn a_request_dropped_before_its_response_ends_the_session() {
        let repo = TmpRepo::new("cut");
        let (table, id) = one_session(&repo);
        let mut done = table.lookup(&id, "anonymous").unwrap();
        done.complete();
        drop(done);
        let other = table.lookup(&id, "anonymous").unwrap();
        let cut = table.lookup(&id, "anonymous").unwrap();
        drop(cut);
        assert!(table.lookup(&id, "anonymous").is_none());
        assert_eq!(other.cancel().cause(), CUT);
        assert!(table.reserve().is_some(), "the slot is free");
    }

    /// A failed request ends its session with the cause of a failed request,
    /// and with the cause of a cut request when a body of the session
    /// failed.
    #[test]
    fn a_failed_request_names_a_cut_body() {
        let repo = TmpRepo::new("fail");
        for (cut, cause) in [(false, FAILED), (true, CUT)] {
            let (table, id) = one_session(&repo);
            let mut active = table.lookup(&id, "anonymous").unwrap();
            let track = active.track();
            if cut {
                track.cut();
            }
            drop(track);
            table.fail(&id);
            assert_eq!(active.cancel().cause(), cause);
            active.complete();
        }
    }

    /// A second commit leaves the session to the first. The end of a commit
    /// frees the slot with the cause of a commit when it succeeded, and with
    /// the cause of a failed request when it failed or never reached its
    /// end, as after a panic.
    #[test]
    fn the_end_of_a_commit_frees_its_slot() {
        let repo = TmpRepo::new("commit");
        for (ok, cause) in [(true, COMMITTED), (false, FAILED)] {
            let (table, id) = one_session(&repo);
            let mut active = table.lookup(&id, "anonymous").unwrap();
            let Begin::Started(mut end) = active.begin_commit() else {
                panic!("the first commit starts");
            };
            assert!(matches!(active.begin_commit(), Begin::Committing));
            assert!(matches!(
                table.delete(&id, "anonymous"),
                Deleted::Committing
            ));
            assert!(table.reserve().is_none(), "the commit holds the slot");
            if ok {
                end.committed();
            }
            drop(end);
            assert_eq!(active.cancel().cause(), cause);
            assert!(matches!(active.begin_commit(), Begin::Ended));
            assert!(table.reserve().is_some(), "the slot is free");
            active.complete();
        }
    }

    /// After the stop of the server, the table reserves no slot, and a slot
    /// reserved before the stop takes no session.
    #[test]
    fn a_stopped_table_takes_no_session() {
        let repo = TmpRepo::new("closed");
        let table = SessionTable::new(2, Duration::from_secs(60));
        let slot = table.reserve().unwrap();
        table.close_all();
        assert!(table.reserve().is_none());
        let id = SessionId::new().unwrap();
        assert!(!slot.insert(id, repo.service(), "anonymous".into()));
        assert!(table.lookup(&id, "anonymous").is_none());
        assert_eq!(table.lock().pending, 0);
    }
}
