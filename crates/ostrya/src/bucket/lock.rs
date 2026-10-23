//! The writer lock of a bucket repository.

use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ostrya_core::{Checksum, KeyFile};
use sha2::{Digest, Sha256};

use super::BucketRepo;
use crate::error::{Error, Result};
use crate::remote::s3::{DeleteIfMatch, PutIfAbsent};

/// The key of the lock, relative to the prefix of the repository.
pub(super) const LOCK_KEY: &str = "extensions/ostrya/lock";

/// The group of the lock body.
const GROUP: &str = "lock";

/// The largest lock body that a read takes: 64 KiB. A larger object is a
/// lock of an unknown writer.
const MAX_LOCK: u64 = 64 * 1024;

/// The largest host name that the lock body holds: 256 bytes.
const MAX_HOST: u64 = 256;

/// The file that gives the host name.
const HOSTNAME_FILE: &str = "/proc/sys/kernel/hostname";

/// The operation of a writer, the key `operation` of the lock body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LockOperation {
    /// The init of a new bucket repository.
    Init,
    /// A push.
    Push,
    /// A prune.
    Prune,
    /// An update of the summary.
    Summary,
    /// A check that deletes the objects that it finds corrupt.
    Fsck,
}

impl LockOperation {
    /// Returns the value of the key `operation`: `init`, `push`, `prune`,
    /// `summary`, or `fsck`.
    pub fn as_str(self) -> &'static str {
        match self {
            LockOperation::Init => "init",
            LockOperation::Push => "push",
            LockOperation::Prune => "prune",
            LockOperation::Summary => "summary",
            LockOperation::Fsck => "fsck",
        }
    }
}

/// The writer that a lock names, as the lock body states it.
///
/// Each field is `None` if the body does not give it in a form that this
/// version reads. A body that is not UTF-8, that is not a key file, that has
/// no group `[lock]`, or that is larger than 64 KiB gives `None` in each
/// field. Such a lock is the lock of an unknown writer.
///
/// The [`Display`](std::fmt::Display) output names each field that is not
/// `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockHolder {
    /// The id of the run of the writer, in 64 lowercase hex digits.
    pub id: Option<String>,
    /// The host name of the writer.
    pub host: Option<String>,
    /// The process id of the writer.
    pub pid: Option<u32>,
    /// The value of the key `operation`, as the writer wrote it. A later
    /// version can write a value that [`LockOperation`] does not name.
    pub operation: Option<String>,
    /// The time at which the writer took the lock, in seconds since the
    /// epoch, UTC.
    pub started: Option<u64>,
}

impl std::fmt::Display for LockHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if let Some(operation) = &self.operation {
            parts.push(format!("operation {}", operation.escape_debug()));
        }
        if let Some(host) = self.host.as_deref().filter(|host| !host.is_empty()) {
            parts.push(format!("host {}", host.escape_debug()));
        }
        if let Some(pid) = self.pid {
            parts.push(format!("pid {pid}"));
        }
        if let Some(started) = self.started {
            parts.push(format!("started at {started} seconds since the epoch, UTC"));
        }
        if let Some(id) = &self.id {
            parts.push(format!("id {id}"));
        }
        if parts.is_empty() {
            f.write_str("a writer that the lock body does not name")
        } else {
            f.write_str(&parts.join(", "))
        }
    }
}

/// A writer lock that this process holds.
///
/// [`BucketRepo::lock`] gives it, and it borrows the repository. A drop
/// sends no request, so the lock stays in the bucket, as after a crash of
/// the writer. [`release`](WriterLock::release) removes it.
#[derive(Debug)]
#[must_use = "a dropped lock stays in the bucket; release it"]
pub struct WriterLock<'a> {
    repo: &'a BucketRepo,
    id: String,
    broken: Option<LockHolder>,
}

/// A lock that a read found, with the `ETag` of the read.
struct Held {
    holder: LockHolder,
    etag: Option<String>,
}

impl BucketRepo {
    /// Takes the writer lock for `operation`, as [`BucketRepo::lock`] states.
    pub(super) async fn take_lock(
        &self,
        operation: LockOperation,
        break_lock: bool,
    ) -> Result<WriterLock<'_>> {
        let broken = if break_lock {
            self.break_lock().await?
        } else {
            None
        };
        let host = host_name();
        let id = new_id(&host);
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let body = lock_body(&id, &host, std::process::id(), operation, started)?.into_bytes();
        match self.bucket.put_if_absent(LOCK_KEY, body.clone()).await? {
            PutIfAbsent::Created { .. }
            | PutIfAbsent::Matches { .. }
            | PutIfAbsent::Refused { .. } => {}
            _ => return Err(self.locked(self.read_lock(false).await?)),
        }
        let lock = WriterLock {
            repo: self,
            id,
            broken,
        };
        let failure = match self.bucket.put_if_absent(LOCK_KEY, body).await {
            // The key held an object at the probe. A probe whose read after
            // an interrupted request found other bytes gives this too, so
            // the read tells if the key holds the lock of this take.
            Ok(PutIfAbsent::Present) => match self.read_lock(false).await {
                Ok(Some(held)) if lock.is_own(&held.holder) => return Ok(lock),
                // Another writer holds the key, or no writer does. The lock
                // of this take is gone, so the call removes no lock.
                Ok(other) => return Err(self.locked(other)),
                Err(e) => ProbeFailure::Error(e),
            },
            // The server honors the header, and the key holds the body of
            // this take.
            Ok(PutIfAbsent::Refused { .. }) => return Ok(lock),
            Ok(PutIfAbsent::Created { .. }) => ProbeFailure::NoExclusion,
            Ok(_) => ProbeFailure::Unknown,
            Err(e) => ProbeFailure::Error(e.into()),
        };
        // The error of the probe is the error of the call. A lock that the
        // removal leaves stays until a break of the lock.
        let removal = lock.remove().await;
        Err(match failure {
            ProbeFailure::NoExclusion => Error::BucketNoExclusion {
                address: self.address().to_string(),
            },
            ProbeFailure::Unknown => {
                let removal = match removal {
                    Ok(()) => "the call removed the lock of this run".to_owned(),
                    Err(Error::BucketLockLost { .. }) => {
                        "the key holds no lock of this run".to_owned()
                    }
                    Err(e) => format!(
                        "the removal of the lock of this run failed, so the lock stays until a \
                         break of the lock: {e}"
                    ),
                };
                Error::Remote(crate::remote::Error::Transport(format!(
                    "the probe of the writer lock of {} had an unknown outcome, so it is not \
                     known if the server honors If-None-Match; {removal}; run the operation \
                     again",
                    self.address()
                )))
            }
            ProbeFailure::Error(e) => e,
        })
    }

    /// Reads the lock that the key holds, as [`BucketRepo::lock_holder`]
    /// states.
    pub(super) async fn read_holder(&self) -> Result<Option<LockHolder>> {
        Ok(self.read_lock(false).await?.map(|held| held.holder))
    }

    /// Deletes the lock that the key holds, with `If-Match` and the `ETag`
    /// of the read, and returns its holder. Returns `None` if the key holds
    /// no lock at the read, or at the read after a 412 to the delete.
    async fn break_lock(&self) -> Result<Option<LockHolder>> {
        let Some(held) = self.read_lock(true).await? else {
            return Ok(None);
        };
        let Some(etag) = held.etag.as_deref() else {
            return Err(Error::Remote(crate::remote::Error::Transport(format!(
                "the read of the writer lock of {} gave no ETag, so the break of the lock \
                 cannot delete it with If-Match; the call deleted no lock",
                self.address()
            ))));
        };
        match self.bucket.delete_if_match(LOCK_KEY, etag).await? {
            DeleteIfMatch::Deleted => Ok(Some(held.holder)),
            // The lock changed after the read. If its holder removed it, no
            // lock stops the take.
            _ => match self.read_lock(false).await? {
                None => Ok(None),
                other => Err(self.locked(other)),
            },
        }
    }

    /// Reads the lock that the key holds, with the `ETag` of the read.
    ///
    /// A lock larger than 64 KiB names no writer. Its `ETag` needs a second
    /// `GET`, so the read gives it only with `etag`.
    async fn read_lock(&self, etag: bool) -> Result<Option<Held>> {
        match self.bucket.get(LOCK_KEY, MAX_LOCK).await {
            Ok(Some(object)) => Ok(Some(Held {
                holder: parse_holder(&object.bytes),
                etag: object.etag,
            })),
            Ok(None) => Ok(None),
            // The body is not read, so the lock names no writer.
            Err(crate::remote::Error::LimitExceeded(_)) if etag => {
                Ok(self.bucket.get_stream(LOCK_KEY).await?.map(|stream| Held {
                    holder: LockHolder::default(),
                    etag: stream.etag().map(str::to_owned),
                }))
            }
            Err(crate::remote::Error::LimitExceeded(_)) => Ok(Some(Held {
                holder: LockHolder::default(),
                etag: None,
            })),
            Err(e) => Err(e.into()),
        }
    }

    /// Returns the error of a take that found the lock `held`.
    fn locked(&self, held: Option<Held>) -> Error {
        Error::BucketLocked {
            address: self.address().to_string(),
            holder: held.map(|held| Box::new(held.holder)),
        }
    }
}

/// A probe that does not show that the server honors `If-None-Match`.
enum ProbeFailure {
    /// The server wrote the probe.
    NoExclusion,
    /// The probe had an unknown outcome, and the key holds the body of the
    /// take.
    Unknown,
    /// An error of the bucket client.
    Error(Error),
}

impl WriterLock<'_> {
    /// Returns the id of the lock, in 64 lowercase hex digits.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the holder of the lock that the break of the lock deleted, or
    /// `None` if the take deleted no lock.
    pub fn broken(&self) -> Option<&LockHolder> {
        self.broken.as_ref()
    }

    /// Reads the lock, and compares its id with the id of this lock.
    ///
    /// A writer that breaks the lock and takes its own after the check does
    /// not stop the change that the check guards.
    ///
    /// # Errors
    ///
    /// - [`Error::BucketLockLost`] if the key holds a lock with another id,
    ///   a lock that names no id, or no lock.
    /// - [`Error::Remote`] for an error of the bucket client.
    pub async fn check(&self) -> Result<()> {
        match self.repo.read_lock(false).await? {
            Some(held) if self.is_own(&held.holder) => Ok(()),
            other => Err(self.lost(other)),
        }
    }

    /// Removes the lock if it still holds the id of this lock.
    ///
    /// The call reads the lock, and deletes it with `If-Match` and the
    /// `ETag` of the read. A response with no `ETag` gives a delete with no
    /// condition, and a writer that takes the lock between the read and the
    /// delete then loses its lock. So does a writer on a server that does
    /// not honor `If-Match`.
    ///
    /// A delete that removed the lock, but whose answer did not arrive, is
    /// sent again. If another writer took the lock between the two
    /// requests, the second request gets 412, and the call gives
    /// [`Error::BucketLockLost`] with the holder of the new lock. The
    /// release of this lock was then complete before the other writer took
    /// its lock.
    ///
    /// # Errors
    ///
    /// - [`Error::BucketLockLost`] if the key holds a lock with another id,
    ///   a lock that names no id, or no lock, or if the lock changed between
    ///   the read and the delete. The call then deletes nothing. A delete
    ///   whose answer did not arrive gives this error also after it removed
    ///   the lock, if another writer took the lock after the removal.
    /// - [`Error::Remote`] for an error of the bucket client.
    pub async fn release(self) -> Result<()> {
        self.remove().await
    }

    /// Removes the lock if it holds the id of this lock.
    async fn remove(&self) -> Result<()> {
        let bucket = &self.repo.bucket;
        let held = match self.repo.read_lock(false).await? {
            Some(held) if self.is_own(&held.holder) => held,
            other => return Err(self.lost(other)),
        };
        match held.etag.as_deref() {
            Some(etag) => match bucket.delete_if_match(LOCK_KEY, etag).await? {
                DeleteIfMatch::Deleted => Ok(()),
                _ => Err(self.lost(self.repo.read_lock(false).await?)),
            },
            None => Ok(bucket.delete(LOCK_KEY).await?),
        }
    }

    /// Returns `true` if `holder` names the id of this lock.
    fn is_own(&self, holder: &LockHolder) -> bool {
        names_id(holder, &self.id)
    }

    /// Returns the error of a lock that holds `held` in place of this lock.
    fn lost(&self, held: Option<Held>) -> Error {
        Error::BucketLockLost {
            address: self.repo.address().to_string(),
            holder: held.map(|held| Box::new(held.holder)),
        }
    }
}

/// Returns the text of [`Error::BucketLocked`] after the address.
pub(crate) fn describe_locked(holder: Option<&LockHolder>) -> String {
    match holder {
        Some(holder) => format!("another writer holds the writer lock: {holder}"),
        None => "a request of this run found a lock, and the lock was gone at the read after \
                 it, so a new run can take the lock"
            .to_owned(),
    }
}

/// Returns the text of [`Error::BucketLockLost`] after the address.
pub(crate) fn describe_lost(holder: Option<&LockHolder>) -> String {
    match holder {
        Some(holder) => format!("another lock is in its place: {holder}"),
        None => "the bucket holds no lock".to_owned(),
    }
}

/// Returns the lock body of the run `id` of the writer on `host` with the
/// process id `pid`, which took the lock for `operation` at `started`
/// seconds since the epoch.
fn lock_body(
    id: &str,
    host: &str,
    pid: u32,
    operation: LockOperation,
    started: u64,
) -> Result<String> {
    let mut body = KeyFile::default();
    body.set_value(GROUP, "id", id)?;
    body.set_string(GROUP, "host", host)?;
    body.set_value(GROUP, "pid", &pid.to_string())?;
    body.set_value(GROUP, "operation", operation.as_str())?;
    body.set_value(GROUP, "started", &started.to_string())?;
    Ok(body.to_string())
}

/// Returns the holder that the lock body `bytes` names.
fn parse_holder(bytes: &[u8]) -> LockHolder {
    let Some(body) = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| KeyFile::parse(text).ok())
        .filter(|body| body.has_group(GROUP))
    else {
        return LockHolder::default();
    };
    let text = |key: &str| body.get_string(GROUP, key).ok().flatten();
    let value = |key: &str| body.get_value(GROUP, key);
    LockHolder {
        id: value("id").filter(|id| is_lock_id(id)).map(str::to_owned),
        host: text("host"),
        pid: value("pid").and_then(|pid| pid.parse().ok()),
        operation: text("operation"),
        started: value("started").and_then(|started| started.parse().ok()),
    }
}

/// Returns `true` if `holder` names the id `id`. A holder that names no id
/// names no lock of this process.
fn names_id(holder: &LockHolder, id: &str) -> bool {
    holder.id.as_deref() == Some(id)
}

/// Returns `true` if `id` is 64 lowercase hex digits.
fn is_lock_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Returns a new id of a run on `host`.
///
/// The id is the SHA-256, in lowercase hex, of the host name, the process
/// id, the time in nanoseconds since the epoch, and a counter of the
/// process, one per line. Two ids are equal only for the same host, process
/// id, nanosecond, and counter value.
fn new_id(host: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let text = format!("{host}\n{}\n{nanos}\n{counter}", std::process::id());
    Checksum::from_bytes(Sha256::digest(text.as_bytes()).into()).to_hex()
}

/// Returns the host name, or an empty name if it cannot be read.
///
/// The name is the first line of `/proc/sys/kernel/hostname`, at most 256
/// bytes. A name that is not UTF-8 gives an empty name.
fn host_name() -> String {
    let mut bytes = Vec::new();
    let read = std::fs::File::open(HOSTNAME_FILE)
        .and_then(|file| file.take(MAX_HOST).read_to_end(&mut bytes));
    if read.is_err() {
        return String::new();
    }
    String::from_utf8(bytes)
        .ok()
        .and_then(|text| text.lines().next().map(str::to_owned))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holder(text: &[u8]) -> LockHolder {
        parse_holder(text)
    }

    #[test]
    fn the_lock_body_has_one_group_and_five_keys_in_order() {
        let id = "ab".repeat(32);
        let body = lock_body(&id, "build1", 4242, LockOperation::Prune, 1_761_062_400).unwrap();
        assert_eq!(
            body,
            format!(
                "[lock]\nid={id}\nhost=build1\npid=4242\noperation=prune\nstarted=1761062400\n"
            )
        );
        assert_eq!(
            holder(body.as_bytes()),
            LockHolder {
                id: Some(id),
                host: Some("build1".into()),
                pid: Some(4242),
                operation: Some("prune".into()),
                started: Some(1_761_062_400),
            }
        );
    }

    #[test]
    fn a_host_name_with_a_leading_space_and_a_backslash_reads_back() {
        let id = "0f".repeat(32);
        let body = lock_body(&id, " a\\b", 1, LockOperation::Push, 0).unwrap();
        assert!(body.contains("host=\\sa\\\\b\n"), "{body}");
        assert_eq!(holder(body.as_bytes()).host.as_deref(), Some(" a\\b"));
        // An empty host name keeps its key.
        let body = lock_body(&id, "", 1, LockOperation::Fsck, 0).unwrap();
        assert!(body.contains("\nhost=\n"), "{body}");
    }

    #[test]
    fn a_body_that_this_version_cannot_read_names_no_id() {
        let good = "a".repeat(64);
        for body in [
            format!("[lock]\nid={}\n", "A".repeat(64)),
            format!("[lock]\nid={}\n", "a".repeat(63)),
            format!("[other]\nid={good}\n"),
            format!("id={good}\n"),
            "[lock\n".to_owned(),
        ] {
            assert_eq!(holder(body.as_bytes()).id, None, "{body}");
        }
        assert_eq!(holder(b"[lock]\nid=\xff\n"), LockHolder::default());
        // A bad pid or start time gives that field alone as `None`.
        let read = holder(format!("[lock]\nid={good}\npid=x\nstarted=-1\n").as_bytes());
        assert_eq!(read.id.as_deref(), Some(good.as_str()));
        assert_eq!((read.pid, read.started), (None, None));
    }

    #[test]
    fn a_holder_names_each_field_that_it_has() {
        let full = LockHolder {
            id: Some("c".repeat(64)),
            host: Some("build\n1".into()),
            pid: Some(7),
            operation: Some("push".into()),
            started: Some(12),
        };
        assert_eq!(
            full.to_string(),
            format!(
                "operation push, host build\\n1, pid 7, started at 12 seconds since the epoch, \
                 UTC, id {}",
                "c".repeat(64)
            )
        );
        assert_eq!(
            LockHolder::default().to_string(),
            "a writer that the lock body does not name"
        );
    }

    #[test]
    fn only_the_own_id_is_the_own_lock() {
        let own = "d".repeat(64);
        let named = |id: Option<String>| LockHolder {
            id,
            ..LockHolder::default()
        };
        assert!(names_id(&named(Some(own.clone())), &own));
        assert!(!names_id(&named(Some("e".repeat(64))), &own));
        assert!(!names_id(&named(None), &own));
    }

    #[test]
    fn each_new_id_is_64_lowercase_hex_digits_and_unique() {
        let first = new_id("build1");
        let second = new_id("build1");
        assert!(is_lock_id(&first), "{first}");
        assert!(is_lock_id(&second), "{second}");
        assert_ne!(first, second);
    }

    #[test]
    fn the_operations_have_their_key_values() {
        let values: Vec<&str> = [
            LockOperation::Init,
            LockOperation::Push,
            LockOperation::Prune,
            LockOperation::Summary,
            LockOperation::Fsck,
        ]
        .into_iter()
        .map(LockOperation::as_str)
        .collect();
        assert_eq!(values, ["init", "push", "prune", "summary", "fsck"]);
    }

    #[test]
    fn the_lock_errors_name_the_address_and_the_holder() {
        let id = "a".repeat(64);
        let holder = || {
            Some(Box::new(LockHolder {
                id: Some(id.clone()),
                ..LockHolder::default()
            }))
        };
        let address = || "s3://bkt/repo".to_owned();
        let locked = Error::BucketLocked {
            address: address(),
            holder: holder(),
        };
        assert_eq!(
            locked.to_string(),
            format!(
                "the bucket repository s3://bkt/repo is locked: another writer holds the writer \
                 lock: id {id}"
            )
        );
        let gone = Error::BucketLocked {
            address: address(),
            holder: None,
        };
        assert!(
            gone.to_string().contains("a new run can take the lock"),
            "{gone}"
        );
        let lost = Error::BucketLockLost {
            address: address(),
            holder: holder(),
        };
        assert_eq!(
            lost.to_string(),
            format!(
                "the writer lock of s3://bkt/repo was broken: another lock is in its place: id {id}"
            )
        );
        let absent = Error::BucketLockLost {
            address: address(),
            holder: None,
        };
        assert!(
            absent.to_string().ends_with("the bucket holds no lock"),
            "{absent}"
        );
        let open = Error::BucketNoExclusion { address: address() };
        assert!(open.to_string().contains("s3://bkt/repo"), "{open}");
    }

    #[test]
    fn the_host_name_is_one_line() {
        let host = host_name();
        assert!(!host.contains('\n'), "{host:?}");
        assert!(host.len() <= MAX_HOST as usize);
    }
}
