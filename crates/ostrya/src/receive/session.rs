//! One push session over a pair of streams: the receive side of the push wire
//! protocol.

use std::collections::HashMap;
use std::io;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::{BufReader, BufWriter};
use ostrya_core::{Checksum, ObjectName, ObjectType, RepoMode, Type, loose_path};

use super::ReceivePolicy;
use super::ingest::{self, Counted, ModeRules};
use crate::error::{Error, Result};
use crate::object::object_exists;
use crate::push::proto::{
    FrameReader, FrameWriter, HaveReply, Hello, HelloReply, MAX_FRAME, MAX_HAVE, Message,
    ObjectHeader, ObjectsReply, PROTOCOL_VERSION, RefState,
};
use crate::push::{self, Encoding, RefOutcome};
use crate::repo::Repo;
use crate::transaction::{Transaction, TransactionStats};

/// The buffer size of each direction of the session stream. A read or a write
/// at least this long passes through to the stream with no copy.
const STREAM_BUFFER: usize = 64 * 1024;

/// The result of a push session that committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveReport {
    /// One outcome for each ref update, in the order of the `Commit` message.
    pub refs: Vec<RefOutcome>,
    /// The statistics of the session transaction.
    pub stats: TransactionStats,
}

/// How a session failed.
pub(super) enum Failure {
    /// A failure with a wire code. The session sends it to the peer, and the
    /// caller gets it as [`Error::Push`].
    Wire(push::Error),
    /// A failure on the server side. The session sends it to the peer as
    /// `internal`, and the caller gets it as it is.
    Internal(Error),
    /// A failure the session does not report to the peer: an error of the
    /// stream, an end of file, or an abort by the client.
    Silent(Error),
}

/// A codec error of the reader: an error of the stream is silent, and every
/// other error carries its wire code.
fn codec(error: push::Error) -> Failure {
    match error {
        push::Error::Io(e) => Failure::Silent(Error::Io(e)),
        other => Failure::Wire(other),
    }
}

fn aborted() -> Failure {
    Failure::Silent(Error::Push(push::Error::Aborted))
}

fn out_of_order(msg: &Message) -> Failure {
    Failure::Wire(push::Error::Protocol(format!(
        "{:?} is out of order",
        msg.kind()
    )))
}

impl Repo {
    /// Run one push session: read the messages of a client from `input`, and
    /// write the replies to `output`.
    ///
    /// The session opens a transaction at `Hello`, which holds the repository
    /// lock shared, under `[core] lock-timeout-secs`, until the session ends. A
    /// repository with `[core] locking=false` refuses the session with the code
    /// `locking-disabled`, and a `bare-split-xattrs` repository with
    /// `mode-refused`. A `bare` repository refuses the session with
    /// `mode-refused` unless the process runs as root, because only root can
    /// store the owner of each file.
    ///
    /// `Have` gets one bit for each object: whether the repository or the
    /// session holds it. The object stream stages each object in the
    /// transaction after it checks its checksum and the content rules of the
    /// repository mode and of `policy`. An object the repository or the session
    /// already holds is read, checked, and dropped. A detached metadata object
    /// is kept in the session.
    ///
    /// The receive side does not yet update refs: a `Commit` message ends the
    /// session with the code `internal`. So every session returns an error, and
    /// the transaction aborts with nothing published.
    ///
    /// Each failure is sent to the peer as an `Error` message and returned. A
    /// failure with a wire code returns as [`Error::Push`]. A failure on the
    /// server side goes to the peer as `internal` and returns as the error it
    /// is. An error of `input`, an end of file, an `Abort` of the client, and an
    /// abandoned object send nothing. An `Abort` and an abandoned object return
    /// [`push::Error::Aborted`], and an end of file at a frame boundary returns
    /// an [`Error::Io`] of kind `UnexpectedEof`. The call does not close
    /// `output`.
    pub async fn receive<R, W>(
        &self,
        input: R,
        output: W,
        policy: &ReceivePolicy,
    ) -> Result<ReceiveReport>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let mut session = Session {
            repo: self,
            policy,
            reader: FrameReader::new(BufReader::with_capacity(STREAM_BUFFER, input)),
            writer: FrameWriter::new(BufWriter::with_capacity(STREAM_BUFFER, output)),
            txn: None,
            rules: None,
            commit_meta: HashMap::new(),
            buf: Vec::new(),
        };
        let failure = session.run().await;
        let error = match failure {
            Failure::Wire(e) => {
                session.send_error(e.to_message()).await;
                Error::Push(e)
            }
            Failure::Internal(e) => {
                let msg = push::Error::Internal(e.to_string()).to_message();
                session.send_error(msg).await;
                e
            }
            Failure::Silent(e) => e,
        };
        // Dropping the transaction removes its staging directory and releases
        // the repository lock.
        drop(session);
        Err(error)
    }
}

struct Session<'a, R, W> {
    repo: &'a Repo,
    policy: &'a ReceivePolicy,
    reader: FrameReader<BufReader<R>>,
    writer: FrameWriter<BufWriter<W>>,
    /// The session transaction, open from `Hello` on.
    txn: Option<Transaction>,
    rules: Option<ModeRules>,
    /// The detached metadata dicts of the session, by commit, as they arrived.
    commit_meta: HashMap<Checksum, Vec<u8>>,
    /// The chunk buffer of the object stream, shared by every object.
    buf: Vec<u8>,
}

impl<R, W> Session<'_, R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    /// Run the session until it fails.
    async fn run(&mut self) -> Failure {
        match self.run_inner().await {
            Ok(never) => match never {},
            Err(failure) => failure,
        }
    }

    async fn run_inner(&mut self) -> std::result::Result<std::convert::Infallible, Failure> {
        match self.next().await? {
            Message::Hello(hello) => self.hello(hello).await?,
            other => return Err(out_of_order(&other)),
        }
        loop {
            match self.next().await? {
                Message::Have(names) => self.have(names).await?,
                Message::ObjectHeader(header) => self.objects(header).await?,
                Message::ObjectsEnd => self.reply_objects(0, 0).await?,
                Message::Commit(_) => {
                    return Err(Failure::Wire(push::Error::Internal(
                        "the receive side does not update refs".into(),
                    )));
                }
                Message::Abort => return Err(aborted()),
                other => return Err(out_of_order(&other)),
            }
        }
    }

    /// The next message. An end of file at a frame boundary is silent.
    async fn next(&mut self) -> std::result::Result<Message, Failure> {
        match self.reader.read_message().await {
            Ok(Some(msg)) => Ok(msg),
            Ok(None) => Err(Failure::Silent(Error::Io(
                io::ErrorKind::UnexpectedEof.into(),
            ))),
            Err(e) => Err(codec(e)),
        }
    }

    async fn reply(&mut self, msg: &Message) -> std::result::Result<(), Failure> {
        let sent = match self.writer.write_message(msg).await {
            Ok(()) => self.writer.flush().await,
            Err(e) => Err(e),
        };
        sent.map_err(|e| match e {
            push::Error::Io(e) => Failure::Silent(Error::Io(e)),
            // A reply the codec refuses is a fault of the server, whatever
            // code the codec gives it.
            other => Failure::Wire(push::Error::Internal(other.to_string())),
        })
    }

    /// Send an `Error` message. A failure to send it is ignored, because the
    /// peer can be gone.
    async fn send_error(&mut self, msg: push::proto::ErrorMessage) {
        if self
            .writer
            .write_message(&Message::Error(msg))
            .await
            .is_ok()
        {
            let _ = self.writer.flush().await;
        }
    }

    fn txn(&self) -> &Transaction {
        self.txn
            .as_ref()
            .expect("the transaction is open after Hello")
    }

    async fn hello(&mut self, hello: Hello) -> std::result::Result<(), Failure> {
        if hello.version != PROTOCOL_VERSION {
            return Err(Failure::Wire(push::Error::VersionUnsupported(format!(
                "the server speaks protocol version {PROTOCOL_VERSION}, not {}",
                hello.version
            ))));
        }
        let mode = self.repo.mode();
        if mode == RepoMode::BareSplitXattrs {
            return Err(Failure::Wire(push::Error::ModeRefused(
                "the repository mode bare-split-xattrs is read-only".into(),
            )));
        }
        if !self.repo.config().locking().map_err(Failure::Internal)? {
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
        let txn = self.repo.transaction().await.map_err(Failure::Internal)?;
        // Read the settings the writes of the session read, so a malformed
        // value fails here as a fault of the server, and not later as a fault
        // of an object.
        txn.fsync_flags().map_err(Failure::Internal)?;
        self.repo.config().fsverity().map_err(Failure::Internal)?;
        if mode.is_archive() {
            self.repo.config().zlib_level().map_err(Failure::Internal)?;
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
        self.txn = Some(txn);
        self.rules = Some(ModeRules::new(mode, self.policy.allow_privileged));
        let tips = self
            .repo
            .resolve_ref_tips(&hello.refs)
            .await
            .map_err(Failure::Internal)?;
        let refs = hello
            .refs
            .into_iter()
            .zip(tips)
            .map(|(name, commit)| RefState { name, commit })
            .collect();
        let reply = HelloReply {
            version: PROTOCOL_VERSION,
            mode: mode.as_mode_str().into(),
            collection_id: self.repo.config().collection_id().map(Into::into),
            max_frame: MAX_FRAME,
            max_have: MAX_HAVE,
            encodings: vec![Encoding::Raw, Encoding::Deflate],
            parallel_uploads: 1,
            refs,
        };
        self.reply(&Message::HelloReply(reply)).await
    }

    /// Answer a `Have`: one bit for each object the repository and the session
    /// do not hold.
    async fn have(&mut self, names: Vec<ObjectName>) -> std::result::Result<(), Failure> {
        if names.len() > MAX_HAVE as usize {
            return Err(Failure::Wire(push::Error::LimitExceeded(format!(
                "a Have of {} entries is over max-have {MAX_HAVE}",
                names.len()
            ))));
        }
        let txn = self.txn();
        let mode = self.repo.mode();
        let paths: Vec<Option<String>> = names
            .iter()
            .map(|n| {
                (!txn.is_staged(&n.checksum, n.ty)).then(|| loose_path(&n.checksum, n.ty, mode))
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
        let reply = HaveReply::from_missing(present.into_iter().map(|p| !p));
        self.reply(&Message::HaveReply(reply)).await
    }

    /// Read one object stream, from its first `ObjectHeader` to `ObjectsEnd`.
    async fn objects(&mut self, first: ObjectHeader) -> std::result::Result<(), Failure> {
        let mut objects = 0u32;
        let mut payload = 0u64;
        let mut header = first;
        loop {
            if let Some(bytes) = self.ingest(header).await? {
                objects = objects.saturating_add(1);
                payload += bytes;
            }
            match self.next().await? {
                Message::ObjectHeader(next) => header = next,
                Message::ObjectsEnd => break,
                Message::Abort => return Err(aborted()),
                other => return Err(out_of_order(&other)),
            }
        }
        self.reply_objects(objects, payload).await
    }

    async fn reply_objects(
        &mut self,
        objects: u32,
        payload_bytes: u64,
    ) -> std::result::Result<(), Failure> {
        let reply = ObjectsReply {
            objects,
            payload_bytes,
        };
        self.reply(&Message::ObjectsReply(reply)).await
    }

    /// Ingest one object. `Some` with its byte count when it was staged or,
    /// for a detached metadata object, kept. `None` when it was dropped.
    async fn ingest(&mut self, header: ObjectHeader) -> std::result::Result<Option<u64>, Failure> {
        let Session {
            repo,
            reader,
            txn,
            rules,
            commit_meta,
            buf,
            ..
        } = self;
        let txn = txn.as_ref().expect("the transaction is open after Hello");
        let rules = rules.as_ref().expect("the mode rules are set at Hello");
        let ObjectName { checksum, ty } = header.name;
        // A metadata object learns whether the repository holds it from the
        // stage step, which checks the store itself. A content object is
        // checked here, because one the repository holds is hashed and not
        // written.
        let held = match ty {
            ObjectType::CommitMeta => false,
            _ if txn.is_staged(&checksum, ty) => true,
            ObjectType::File => repo
                .has_object(ty, &checksum)
                .await
                .map_err(Failure::Internal)?,
            _ => false,
        };
        let mut body = Counted::new(reader.object_body());
        let result = match (ty, header.encoding) {
            (ObjectType::CommitMeta, _) => {
                commit_meta_object(commit_meta, &checksum, &mut body).await
            }
            (ObjectType::File, Encoding::Raw) => {
                ingest::raw_content(txn, rules, &checksum, held, &mut body, buf).await
            }
            (ObjectType::File, Encoding::Deflate) => {
                ingest::deflate_content(txn, rules, &checksum, held, &mut body, buf).await
            }
            (ty, _) => ingest::metadata(txn, rules, ty, &checksum, held, &mut body).await,
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
}

/// Keep one detached metadata object: a dict `a{sv}` for the commit
/// `checksum`. A second one for the same commit is `protocol`.
async fn commit_meta_object<B: AsyncRead + Unpin>(
    commit_meta: &mut HashMap<Checksum, Vec<u8>>,
    checksum: &Checksum,
    body: &mut B,
) -> std::result::Result<bool, Failure> {
    if commit_meta.contains_key(checksum) {
        return Err(Failure::Wire(push::Error::Protocol(format!(
            "a second detached metadata object for commit {checksum}"
        ))));
    }
    let bytes = ingest::read_capped(body, "detached metadata of commit", checksum).await?;
    let dict = Type::parse("a{sv}").expect("valid signature");
    ostrya_core::validate(&dict, &bytes).map_err(|e| {
        Failure::Wire(push::Error::Protocol(format!(
            "the detached metadata of commit {checksum} is not a dict a{{sv}}: {e}"
        )))
    })?;
    commit_meta.insert(*checksum, bytes);
    Ok(true)
}

/// The future of a session can run on a thread pool.
const _: fn() = || {
    fn assert_send<T: Send>(_: T) {}
    let _ = |repo: &Repo, policy: &ReceivePolicy| {
        assert_send(repo.receive(futures_lite::io::empty(), futures_lite::io::sink(), policy))
    };
};
