//! The steps of one push session, which each transport drives.
//!
//! The steps are `Hello`, `Have`, the object stream, and `Commit`. Each step
//! uses the session transaction.

use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_io::AsyncRead;
use ostrya_core::{
    Checksum, ObjectName, ObjectType, RepoMode, choose_offset_size, loose_path, offset_size_for,
};

use super::ReceivePolicy;
use super::hooks::ReceiveHooks;
use super::ingest::{self, Counted, ModeRules, limit_exceeded};
use super::merge::check_incoming;
use super::session::{Failure, ReceiveReport, aborted, codec, next, out_of_order};
use crate::error::{Error, Result};
use crate::object::{MAX_METADATA_SIZE, object_exists};
use crate::push::proto::{
    CommitRequest, FrameReader, HaveReply, Hello, HelloReply, MAX_FRAME, MAX_HAVE, Message,
    ObjectHeader, ObjectsReply, PROTOCOL_VERSION, RefState,
};
use crate::push::{self, Encoding};
use crate::repo::Repo;
use crate::transaction::Transaction;

/// One open push session.
///
/// The session holds the session transaction and the state that it keeps
/// until `Commit`. The session transaction holds the repository lock in
/// shared mode. Each step except [`finish`](Self::finish) takes `&self`, so
/// concurrent object streams can share one session.
pub(super) struct SessionCore<P: Deref<Target = ReceivePolicy>> {
    repo: Repo,
    policy: P,
    txn: Transaction,
    rules: ModeRules,
    /// The refs that `Hello` named.
    named: Vec<String>,
    /// `true` if the session reads a one-way stream.
    one_way: bool,
    /// The hooks of the session, which `Commit` calls.
    hooks: Option<Arc<dyn ReceiveHooks>>,
    meta: Mutex<MetaState>,
    /// The bytes of the dirtree, dirmeta, and commit objects that the object
    /// streams of the session read now and did not stage yet. The session
    /// keeps this count at most [`MAX_METADATA_SIZE`].
    reading: AtomicU64,
}

/// The detached metadata of a session.
///
/// A step holds the lock on this state only for a check or an update of its
/// fields. No step holds the lock across a read of an object.
#[derive(Default)]
struct MetaState {
    /// The dicts of the session, by commit, as they arrived.
    dicts: HashMap<Checksum, Vec<u8>>,
    /// The commits whose dict an object stream reads or checks now.
    pending: HashSet<Checksum>,
    /// The bytes of detached metadata that the session read, in the dicts
    /// that it keeps and in the dicts that it reads now. The session keeps
    /// this count at most [`MAX_METADATA_SIZE`].
    reserved: u64,
}

impl<P: Deref<Target = ReceivePolicy>> SessionCore<P> {
    /// Answers the `Hello` of a two-way session and opens the session
    /// transaction.
    ///
    /// The answer checks the version, the repository, and the ref names.
    /// `parallel_uploads` is the value that the reply announces. `hooks` are
    /// the hooks that `Commit` calls.
    ///
    /// The session checks `one-way` before the version. A `Hello` with
    /// `one-way` set to `true` gives a `protocol` failure.
    pub(super) async fn open(
        repo: Repo,
        policy: P,
        hooks: Option<Arc<dyn ReceiveHooks>>,
        parallel_uploads: u32,
        hello: Hello,
    ) -> std::result::Result<(Self, HelloReply), Failure> {
        if hello.one_way {
            return Err(Failure::Wire(push::Error::Protocol(
                "a Hello with one-way true opens a one-way stream, which this session does not \
                 read"
                    .into(),
            )));
        }
        let core = Self::start(repo, policy, hooks, hello, false).await?;
        let repo = &core.repo;
        let tips = repo
            .resolve_ref_tips(&core.named)
            .await
            .map_err(Failure::Internal)?;
        let refs = core
            .named
            .iter()
            .cloned()
            .zip(tips)
            .map(|(name, commit)| RefState { name, commit })
            .collect();
        let reply = hello_reply(repo, parallel_uploads, refs);
        Ok((core, reply))
    }

    /// Reads the `Hello` of a one-way stream and opens the session
    /// transaction.
    ///
    /// The checks are those of a two-way `Hello`, except the refusal of
    /// `[core] locking=false` and the check of the reply size. A one-way
    /// stream gets no reply.
    ///
    /// The session checks `one-way` before the version. A `Hello` without
    /// `one-way` set to `true` gives a `protocol` failure.
    pub(super) async fn open_one_way(
        repo: Repo,
        policy: P,
        hello: Hello,
    ) -> std::result::Result<Self, Failure> {
        if !hello.one_way {
            return Err(Failure::Wire(push::Error::Protocol(
                "a one-way stream starts with a Hello with one-way true".into(),
            )));
        }
        Self::start(repo, policy, None, hello, true).await
    }

    /// Runs the checks of [`check_hello`] on `hello` and opens the session
    /// transaction.
    ///
    /// If the repository mode is `bare` and the server does not run as root,
    /// the result is a `mode-refused` failure.
    async fn start(
        repo: Repo,
        policy: P,
        hooks: Option<Arc<dyn ReceiveHooks>>,
        hello: Hello,
        one_way: bool,
    ) -> std::result::Result<Self, Failure> {
        check_hello(&repo, &hello)?;
        let mode = repo.mode();
        let txn = repo.transaction().await.map_err(Failure::Internal)?;
        // Read the settings that the writes of the session use. A malformed
        // value then fails here as a fault of the server, before an object
        // can fail on it.
        txn.fsync_flags().map_err(Failure::Internal)?;
        repo.config().fsverity().map_err(Failure::Internal)?;
        if mode.is_archive() {
            repo.config().zlib_level().map_err(Failure::Internal)?;
        }
        if mode == RepoMode::Bare {
            let (uid, _) = txn.fresh_owner().await.map_err(Failure::Internal)?;
            if uid != 0 {
                return Err(Failure::Wire(push::Error::ModeRefused(
                    "a bare repository stores the owner of each file, which needs the server \
                     to run as root"
                        .into(),
                )));
            }
        }
        let rules = ModeRules::new(mode, policy.allow_privileged);
        Ok(SessionCore {
            repo,
            policy,
            txn,
            rules,
            named: hello.refs,
            one_way,
            hooks,
            meta: Mutex::default(),
            reading: AtomicU64::new(0),
        })
    }

    /// Answers a `Have` with one bit for each object that the repository and
    /// the session do not hold.
    pub(super) async fn have(
        &self,
        names: Vec<ObjectName>,
    ) -> std::result::Result<HaveReply, Failure> {
        if names.len() > MAX_HAVE as usize {
            return Err(Failure::Wire(push::Error::LimitExceeded(format!(
                "a Have of {} entries is over max-have {MAX_HAVE}",
                names.len()
            ))));
        }
        let mode = self.repo.mode();
        let paths: Vec<Option<String>> = names
            .iter()
            .map(|n| {
                (!self.txn.is_staged(&n.checksum, n.ty))
                    .then(|| loose_path(&n.checksum, n.ty, mode))
            })
            .collect();
        let repo = self.repo.clone();
        let present = ostrya_rt::unblock(move || {
            paths
                .iter()
                .map(|path| match path {
                    Some(path) => object_exists(repo.objects_fd(), path),
                    None => Ok(true),
                })
                .collect::<Result<Vec<bool>>>()
        })
        .await
        .map_err(Failure::Internal)?;
        Ok(HaveReply::from_missing(present.into_iter().map(|p| !p)))
    }

    /// Reads one object stream from `reader`, from its first `ObjectHeader` to
    /// `ObjectsEnd`.
    ///
    /// `first` is the header that the caller already read. It is `None` if
    /// the caller read `ObjectsEnd`. `buf` is the chunk buffer of the stream,
    /// and each object of the stream uses it.
    pub(super) async fn objects<R: AsyncRead + Unpin>(
        &self,
        first: Option<ObjectHeader>,
        reader: &mut FrameReader<R>,
        buf: &mut Vec<u8>,
    ) -> std::result::Result<ObjectsReply, Failure> {
        let mut objects = 0u32;
        let mut payload_bytes = 0u64;
        let Some(mut header) = first else {
            return Ok(ObjectsReply {
                objects,
                payload_bytes,
            });
        };
        loop {
            if let Some(bytes) = self.ingest(header, reader, buf).await? {
                objects = objects.saturating_add(1);
                payload_bytes += bytes;
            }
            match next(reader).await? {
                Message::ObjectHeader(next) => header = next,
                Message::ObjectsEnd => break,
                // If a one-way sender fails, it abandons the object that it
                // sends. As a result, in a one-way stream `Abort` comes only
                // after the abandon marker.
                Message::Abort if !self.one_way => return Err(aborted()),
                other => return Err(out_of_order(&other)),
            }
        }
        Ok(ObjectsReply {
            objects,
            payload_bytes,
        })
    }

    /// Ingests one object and returns its byte count if the session keeps it.
    ///
    /// The result is `Some` with the byte count if the session staged the
    /// object. For a detached metadata object, it is `Some` if the session
    /// kept the object. The result is `None` if the session dropped the
    /// object.
    ///
    /// The bytes of a dirtree, dirmeta, or commit object count against one
    /// budget of [`MAX_METADATA_SIZE`]. The budget covers each object of
    /// these types that the session streams read at the same time, from its
    /// arrival to the stage step. The bytes of a detached metadata
    /// object count only against the cap of the detached metadata.
    async fn ingest<R: AsyncRead + Unpin>(
        &self,
        header: ObjectHeader,
        reader: &mut FrameReader<R>,
        buf: &mut Vec<u8>,
    ) -> std::result::Result<Option<u64>, Failure> {
        let (txn, rules) = (&self.txn, &self.rules);
        let ObjectName { checksum, ty } = header.name;
        // For a metadata object, the stage step checks the object store
        // itself. This code checks a content object here, because the ingest
        // hashes a content object that the repository holds and does not
        // write it.
        let held = match ty {
            ObjectType::CommitMeta => false,
            _ if txn.is_staged(&checksum, ty) => true,
            ObjectType::File => self
                .repo
                .has_object(ty, &checksum)
                .await
                .map_err(Failure::Internal)?,
            _ => false,
        };
        let mut body = Counted::new(reader.object_body());
        let result = match (ty, header.encoding) {
            (ObjectType::CommitMeta, _) => self.commit_meta_object(&checksum, &mut body).await,
            (ObjectType::File, Encoding::Raw) => {
                ingest::raw_content(txn, rules, &checksum, held, &mut body, buf).await
            }
            (ObjectType::File, Encoding::Deflate) => {
                ingest::deflate_content(txn, rules, &checksum, held, &mut body, buf).await
            }
            (ty, _) => {
                let mut reading = Reading {
                    total: &self.reading,
                    held: 0,
                };
                let reserve = |n| reading.reserve(n);
                ingest::metadata(txn, rules, ty, &checksum, held, &mut body, reserve).await
            }
        };
        let count = body.count;
        let mut body = body.inner;
        // If the reader under the ingest fails, its failure wins over the
        // failure that it caused.
        if let Some(e) = body.take_error() {
            return Err(codec(e));
        }
        if body.is_abandoned() {
            return match body.finish_abandon().await {
                Ok(()) => Err(aborted()),
                Err(e) => Err(codec(e)),
            };
        }
        match result {
            Ok(stored) if body.is_finished() => Ok(stored.then_some(count)),
            Ok(_) => Err(Failure::Wire(push::Error::Protocol(format!(
                "bytes follow {ty:?} object {checksum}"
            )))),
            Err(failure) => Err(failure),
        }
    }

    /// Keeps one detached metadata object, a dict `a{sv}` for the commit
    /// `checksum`.
    ///
    /// These objects give a `protocol` failure:
    ///
    /// - A second object for the same commit, also while another stream
    ///   reads the first.
    /// - A dict that the merge into the stored dict refuses. This is a dict
    ///   that holds a key twice, or a dict with a signature key whose value
    ///   is not `aay`.
    ///
    /// The bytes of each dict of the session count against one cap of
    /// [`MAX_METADATA_SIZE`] as they arrive. The read that takes the session
    /// past the cap gives a `limit-exceeded` failure.
    async fn commit_meta_object<B: AsyncRead + Unpin>(
        &self,
        checksum: &Checksum,
        body: &mut B,
    ) -> std::result::Result<bool, Failure> {
        {
            let mut meta = self.lock_meta();
            if meta.dicts.contains_key(checksum) || !meta.pending.insert(*checksum) {
                return Err(Failure::Wire(push::Error::Protocol(format!(
                    "a second detached metadata object for commit {checksum}"
                ))));
            }
        }
        let bytes = ingest::read_capped(body, "detached metadata of commit", checksum, |n| {
            self.reserve(n)
        })
        .await?;
        // Check the dict in place on the blocking pool. The check builds no
        // value tree, because the session keeps the bytes until the merge.
        let (bytes, checked) = ostrya_rt::unblock(move || {
            let checked = check_incoming(&bytes);
            (bytes, checked)
        })
        .await;
        checked.map_err(|e| {
            Failure::Wire(push::Error::Protocol(format!(
                "the detached metadata of commit {checksum}: {e}"
            )))
        })?;
        let mut meta = self.lock_meta();
        meta.pending.remove(checksum);
        meta.dicts.insert(*checksum, bytes);
        Ok(true)
    }

    /// Counts `n` more bytes of detached metadata against the cap of the
    /// session.
    fn reserve(&self, n: u64) -> std::result::Result<(), Failure> {
        let mut meta = self.lock_meta();
        let reserved = meta.reserved + n;
        if reserved > MAX_METADATA_SIZE {
            return Err(limit_exceeded(format!(
                "the detached metadata of the session is larger than {MAX_METADATA_SIZE} bytes"
            )));
        }
        meta.reserved = reserved;
        Ok(())
    }

    fn lock_meta(&self) -> std::sync::MutexGuard<'_, MetaState> {
        self.meta.lock().expect("detached metadata mutex")
    }

    /// Runs `Commit`: the checks of the ref updates, the ref writes, and the
    /// transaction commit.
    ///
    /// The session ends with this step.
    pub(super) async fn finish(
        self,
        request: CommitRequest,
    ) -> std::result::Result<ReceiveReport, Failure> {
        let SessionCore {
            repo,
            policy,
            txn,
            named,
            hooks,
            meta,
            ..
        } = self;
        let dicts = meta.into_inner().expect("detached metadata mutex").dicts;
        let hooks = hooks.as_deref();
        super::finish::finish(&repo, &policy, hooks, txn, &named, dicts, request).await
    }
}

/// Checks `hello` before a session opens.
///
/// Each session runs these checks, in this order:
///
/// 1. The protocol version.
/// 2. The repository mode `bare-split-xattrs`.
/// 3. `[core] locking=false`, for a two-way `Hello`.
/// 4. Each ref name.
/// 5. The size of the longest `HelloReply`, for a two-way `Hello`.
///
/// No check does I/O.
pub(super) fn check_hello(repo: &Repo, hello: &Hello) -> std::result::Result<(), Failure> {
    if hello.version != PROTOCOL_VERSION {
        return Err(Failure::Wire(push::Error::VersionUnsupported(format!(
            "the server speaks protocol version {PROTOCOL_VERSION}, not {}",
            hello.version
        ))));
    }
    if repo.mode() == RepoMode::BareSplitXattrs {
        return Err(Failure::Wire(push::Error::ModeRefused(
            "the repository mode bare-split-xattrs is read-only".into(),
        )));
    }
    if !hello.one_way && !repo.config().locking().map_err(Failure::Internal)? {
        return Err(Failure::Wire(push::Error::LockingDisabled(
            "the repository sets [core] locking=false".into(),
        )));
    }
    for name in &hello.refs {
        crate::validate_refspec(name).map_err(|e| match e {
            Error::InvalidRefspec(_) => Failure::Wire(push::Error::InvalidRef(format!(
                "invalid ref name '{name}'"
            ))),
            other => Failure::Internal(other),
        })?;
    }
    if !hello.one_way {
        check_hello_reply_fits(repo, &hello.refs)?;
    }
    Ok(())
}

/// Returns the `HelloReply` of `repo` for the ref states `refs`.
///
/// `parallel_uploads` is the value that the reply announces.
fn hello_reply(repo: &Repo, parallel_uploads: u32, refs: Vec<RefState>) -> HelloReply {
    HelloReply {
        version: PROTOCOL_VERSION,
        mode: repo.mode().as_mode_str().into(),
        collection_id: repo.config().collection_id().map(Into::into),
        max_frame: MAX_FRAME,
        max_have: MAX_HAVE,
        encodings: vec![Encoding::Raw, Encoding::Deflate],
        parallel_uploads,
        refs,
    }
}

/// Checks that the `HelloReply` for `names` fits in a frame of [`MAX_FRAME`].
///
/// The check uses a commit for each ref, which is the longest state that a
/// ref can have. A reply over the limit gives a `limit-exceeded` failure.
/// The size comes from the reply with no ref and from the length of each
/// name. The check builds no reply with the refs.
fn check_hello_reply_fits(repo: &Repo, names: &[String]) -> std::result::Result<(), Failure> {
    // If the codec refuses the reply, the failure is a fault of the server,
    // whatever code the codec gives it. The value of `parallel_uploads` does
    // not change the size of the reply.
    let empty = Message::HelloReply(hello_reply(repo, 1, Vec::new()))
        .encode_body()
        .map_err(|e| Failure::Wire(push::Error::Internal(e.to_string())))?;
    let fits = reply_frame_len(empty.len(), names.iter().map(String::len))
        .is_some_and(|len| len <= u64::from(MAX_FRAME));
    if !fits {
        return Err(Failure::Wire(push::Error::LimitExceeded(format!(
            "the reply to the {} refs of Hello can need a frame over the limit {MAX_FRAME}",
            names.len()
        ))));
    }
    Ok(())
}

/// Returns the size in bytes of one ref state `(smay)` with a commit and a
/// name of `name` bytes.
///
/// The size is the sum of these parts:
///
/// - The name and its NUL byte.
/// - The 32 bytes of the commit.
/// - The byte that marks a maybe of variable size.
/// - The framing offset of the name.
fn ref_state_len(name: u64) -> u64 {
    let data = name + 1 + 32 + 1;
    data + offset_size(data, 1)
}

/// Returns the framing offset size of a container of `data` bytes with `n`
/// offsets.
fn offset_size(data: u64, n: u64) -> u64 {
    match (usize::try_from(data), usize::try_from(n)) {
        (Ok(data), Ok(n)) => choose_offset_size(data, n) as u64,
        _ => 8,
    }
}

/// Returns the frame length of a `HelloReply` `(ua{sv}a(smay))` with one
/// ref for each name length in `names`.
///
/// The body of the reply with no ref is `empty` bytes. Each ref has a
/// commit. The result is `None` as soon as the ref states alone pass
/// [`MAX_FRAME`].
///
/// The body with no ref is the version, its padding, and the dict, then one
/// framing offset for the end of the dict. The encoder chose the size of
/// this offset from the length of the body. The array of the ref states
/// follows the dict with no padding. The array holds the states and one
/// framing offset for each state.
fn reply_frame_len(empty: usize, names: impl Iterator<Item = usize>) -> Option<u64> {
    let head = (empty - offset_size_for(empty)) as u64;
    let mut states = 0u64;
    let mut count = 0u64;
    for name in names {
        states += ref_state_len(name as u64);
        count += 1;
        if states > u64::from(MAX_FRAME) {
            return None;
        }
    }
    let array = if count == 0 {
        0
    } else {
        states + count * offset_size(states, count)
    };
    let data = head + array;
    Some(data + offset_size(data, 1) + 1)
}

/// The bytes of one dirtree, dirmeta, or commit object that an object stream
/// reads.
///
/// The bytes count against the budget that all object streams of the session
/// share. A drop of this value gives the bytes back. The drop occurs when the
/// session stages the object, drops it, or fails on it.
struct Reading<'a> {
    total: &'a AtomicU64,
    held: u64,
}

impl Reading<'_> {
    /// Counts `n` more bytes against the budget.
    ///
    /// The read that takes the session past [`MAX_METADATA_SIZE`] gives a
    /// `limit-exceeded` failure.
    fn reserve(&mut self, n: u64) -> std::result::Result<(), Failure> {
        self.total
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |total| {
                total.checked_add(n).filter(|&t| t <= MAX_METADATA_SIZE)
            })
            .map_err(|_| {
                limit_exceeded(format!(
                    "the metadata objects that the session reads at the same time are larger \
                     than {MAX_METADATA_SIZE} bytes"
                ))
            })?;
        self.held += n;
        Ok(())
    }
}

impl Drop for Reading<'_> {
    fn drop(&mut self) {
        self.total.fetch_sub(self.held, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a `HelloReply` like the one of a session.
    ///
    /// The reply has a collection id of `collection_id` bytes, or no
    /// collection id for 0. It has `count` refs with names of `name` bytes,
    /// each with a commit.
    fn reply(collection_id: usize, name: usize, count: usize) -> HelloReply {
        let commit = Some(Checksum::from_bytes([7; 32]));
        HelloReply {
            version: PROTOCOL_VERSION,
            mode: RepoMode::Archive.as_mode_str().into(),
            collection_id: (collection_id > 0).then(|| "c".repeat(collection_id)),
            max_frame: MAX_FRAME,
            max_have: MAX_HAVE,
            encodings: vec![Encoding::Raw, Encoding::Deflate],
            parallel_uploads: 1,
            refs: (0..count)
                .map(|i| RefState {
                    name: format!("{i:0>name$}")[..name].into(),
                    commit,
                })
                .collect(),
        }
    }

    fn encoded_frame_len(reply: HelloReply) -> u64 {
        Message::HelloReply(reply).encode_body().unwrap().len() as u64 + 1
    }

    fn computed_frame_len(collection_id: usize, name: usize, count: usize) -> Option<u64> {
        let empty = Message::HelloReply(reply(collection_id, 0, 0))
            .encode_body()
            .unwrap();
        reply_frame_len(empty.len(), std::iter::repeat_n(name, count))
    }

    /// The computed frame length is the length of the frame that the encoder
    /// writes. The test covers each size of the framing offsets of a ref
    /// state, of the array, and of the reply.
    #[test]
    fn the_reply_bound_is_the_encoded_size() {
        for collection_id in [0, 300] {
            for name in [0, 1, 220, 221, 300] {
                for count in [0, 1, 2, 7, 8, 9, 1000] {
                    assert_eq!(
                        computed_frame_len(collection_id, name, count),
                        Some(encoded_frame_len(reply(collection_id, name, count))),
                        "collection id {collection_id}, name {name}, count {count}"
                    );
                }
            }
        }
    }

    /// The largest count of refs whose bound fits in a frame gives a reply
    /// that fits. One ref more gives a reply over the limit.
    #[test]
    fn the_largest_count_that_fits_is_the_limit_of_the_encoder() {
        let limit = u64::from(MAX_FRAME);
        for (collection_id, name) in [(0, 220), (300, 1)] {
            let fits = |count| {
                computed_frame_len(collection_id, name, count).is_some_and(|len| len <= limit)
            };
            // The largest count that fits, by bisection: `low` fits, and
            // `high` does not.
            let (mut low, mut high) = (0, MAX_FRAME as usize);
            while high - low > 1 {
                let mid = low + (high - low) / 2;
                if fits(mid) {
                    low = mid;
                } else {
                    high = mid;
                }
            }
            let count = low;
            assert!(encoded_frame_len(reply(collection_id, name, count)) <= limit);
            assert!(encoded_frame_len(reply(collection_id, name, count + 1)) > limit);
        }
    }

    /// The computation stops as soon as the ref states pass the frame
    /// limit, and returns `None`.
    #[test]
    fn the_reply_bound_stops_past_the_frame_limit() {
        let empty = Message::HelloReply(reply(0, 0, 0)).encode_body().unwrap();
        let mut taken = 0usize;
        let names = std::iter::repeat_n(1000, usize::MAX).inspect(|_| taken += 1);
        assert_eq!(reply_frame_len(empty.len(), names), None);
        assert!(taken <= MAX_FRAME as usize / 1000 + 1, "{taken}");
    }
}
