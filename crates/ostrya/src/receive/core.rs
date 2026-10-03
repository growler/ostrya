//! The steps of one push session that each transport drives: `Hello`, `Have`,
//! the object stream, and `Commit`, over the session transaction.

use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use futures_io::AsyncRead;
use ostrya_core::{Checksum, ObjectName, ObjectType, RepoMode, loose_path};

use super::ReceivePolicy;
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

/// One open push session: the session transaction, which holds the
/// repository lock shared, and what the session keeps until `Commit`. Every
/// step but [`finish`](Self::finish) takes `&self`, so concurrent object
/// streams can share one session.
pub(super) struct SessionCore<P: Deref<Target = ReceivePolicy>> {
    repo: Repo,
    policy: P,
    txn: Transaction,
    rules: ModeRules,
    /// The refs `Hello` named.
    named: Vec<String>,
    meta: Mutex<MetaState>,
    /// The bytes of the dirtree, dirmeta, and commit objects that the object
    /// streams of the session read now and did not stage yet. The session
    /// holds it to [`MAX_METADATA_SIZE`].
    reading: AtomicU64,
}

/// The detached metadata of a session. The lock over it is held for a check
/// or an update of these fields alone, and never across a read of an object.
#[derive(Default)]
struct MetaState {
    /// The dicts of the session, by commit, as they arrived.
    dicts: HashMap<Checksum, Vec<u8>>,
    /// The commits whose dict an object stream reads or checks now.
    pending: HashSet<Checksum>,
    /// The bytes of detached metadata the session read, in the dicts it keeps
    /// and in those it reads now. The session holds it to
    /// [`MAX_METADATA_SIZE`].
    reserved: u64,
}

impl<P: Deref<Target = ReceivePolicy>> SessionCore<P> {
    /// Answer `Hello`: check the version, the repository, and the ref names,
    /// and open the session transaction. `parallel_uploads` is the value the
    /// reply announces.
    pub(super) async fn open(
        repo: Repo,
        policy: P,
        parallel_uploads: u32,
        hello: Hello,
    ) -> std::result::Result<(Self, HelloReply), Failure> {
        if hello.version != PROTOCOL_VERSION {
            return Err(Failure::Wire(push::Error::VersionUnsupported(format!(
                "the server speaks protocol version {PROTOCOL_VERSION}, not {}",
                hello.version
            ))));
        }
        let mode = repo.mode();
        if mode == RepoMode::BareSplitXattrs {
            return Err(Failure::Wire(push::Error::ModeRefused(
                "the repository mode bare-split-xattrs is read-only".into(),
            )));
        }
        if !repo.config().locking().map_err(Failure::Internal)? {
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
        let txn = repo.transaction().await.map_err(Failure::Internal)?;
        // Read the settings the writes of the session read, so a malformed
        // value fails here as a fault of the server, and not later as a fault
        // of an object.
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
        let tips = repo
            .resolve_ref_tips(&hello.refs)
            .await
            .map_err(Failure::Internal)?;
        let refs = hello
            .refs
            .iter()
            .cloned()
            .zip(tips)
            .map(|(name, commit)| RefState { name, commit })
            .collect();
        let reply = HelloReply {
            version: PROTOCOL_VERSION,
            mode: mode.as_mode_str().into(),
            collection_id: repo.config().collection_id().map(Into::into),
            max_frame: MAX_FRAME,
            max_have: MAX_HAVE,
            encodings: vec![Encoding::Raw, Encoding::Deflate],
            parallel_uploads,
            refs,
        };
        let core = SessionCore {
            repo,
            policy,
            txn,
            rules,
            named: hello.refs,
            meta: Mutex::default(),
            reading: AtomicU64::new(0),
        };
        Ok((core, reply))
    }

    /// Answer a `Have`: one bit for each object the repository and the session
    /// do not hold.
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

    /// Read one object stream from `reader`, from its first `ObjectHeader` to
    /// `ObjectsEnd`. `first` is the header the caller already read, or `None`
    /// when the caller read `ObjectsEnd`. `buf` is the chunk buffer of the
    /// stream, shared by every object.
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
                Message::Abort => return Err(aborted()),
                other => return Err(out_of_order(&other)),
            }
        }
        Ok(ObjectsReply {
            objects,
            payload_bytes,
        })
    }

    /// Ingest one object. `Some` with its byte count when it was staged or,
    /// for a detached metadata object, kept. `None` when it was dropped.
    ///
    /// The bytes of a dirtree, dirmeta, or commit object count against one
    /// budget of [`MAX_METADATA_SIZE`] for every object of these types that
    /// the streams of the session read at the same time, from their arrival
    /// to the stage step. The bytes of a detached metadata object count
    /// against the cap of the detached metadata alone.
    async fn ingest<R: AsyncRead + Unpin>(
        &self,
        header: ObjectHeader,
        reader: &mut FrameReader<R>,
        buf: &mut Vec<u8>,
    ) -> std::result::Result<Option<u64>, Failure> {
        let (txn, rules) = (&self.txn, &self.rules);
        let ObjectName { checksum, ty } = header.name;
        // A metadata object learns whether the repository holds it from the
        // stage step, which checks the store itself. A content object is
        // checked here, because one the repository holds is hashed and not
        // written.
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
        // A failure of the reader under the ingest wins over the failure it
        // caused.
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

    /// Keep one detached metadata object: a dict `a{sv}` for the commit
    /// `checksum`. A second one for the same commit is `protocol`, also while
    /// another stream reads the first, and so is a dict that the merge into
    /// the stored dict refuses: one that holds a key twice, or a signature key
    /// whose value is not `aay`. The bytes of every dict of the session count
    /// against one cap of [`MAX_METADATA_SIZE`], as they arrive, and the read
    /// that takes the session past it is `limit-exceeded`.
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
        // The dict is checked in place on the blocking pool, and no value tree
        // is built: the session keeps its bytes until the merge.
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

    /// Count `n` more bytes of detached metadata against the cap of the
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

    /// Run `Commit`: the checks of the ref updates, the ref writes, and the
    /// transaction commit. The session ends with it.
    pub(super) async fn finish(
        self,
        request: CommitRequest,
    ) -> std::result::Result<ReceiveReport, Failure> {
        let SessionCore {
            repo,
            policy,
            txn,
            named,
            meta,
            ..
        } = self;
        let dicts = meta.into_inner().expect("detached metadata mutex").dicts;
        super::finish::finish(&repo, &policy, txn, &named, dicts, request).await
    }
}

/// The bytes of one dirtree, dirmeta, or commit object that an object stream
/// reads, counted against the budget that every object stream of the session
/// shares. Dropping it, when the object is staged, dropped, or failed, gives
/// the bytes back.
struct Reading<'a> {
    total: &'a AtomicU64,
    held: u64,
}

impl Reading<'_> {
    /// Count `n` more bytes against the budget. The read that takes the
    /// session past [`MAX_METADATA_SIZE`] is `limit-exceeded`.
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
