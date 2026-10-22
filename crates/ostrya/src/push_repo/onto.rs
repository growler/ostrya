//! The server commit of a local commit: the checks before the session opens,
//! the tree walk, one `Have` round, and the `ServerCommit`.

use std::collections::HashSet;

use futures_io::{AsyncRead, AsyncWrite};
use ostrya_core::{Checksum, Commit, ObjectName, ObjectType};

use super::invalid;
use super::negotiate::{check_tag_names, collection_id_refusal};
use super::source::RepoSource;
use crate::error::{Error, Result};
use crate::lock::{LockGuard, LockKind};
use crate::pull::DetachedMetadataFilter;
use crate::read::CommitState;
use crate::remote::proto::ServerCommit;
use crate::remote::{
    Compression, Endpoint, PushOutcome, PushProgress, PushSession, SessionOptions,
};
use crate::repo::Repo;

/// The metadata keys of the bindings, which the server writes for its
/// namespace.
const BINDING_KEYS: [&str; 2] = ["ostree.ref-binding", "ostree.collection-binding"];

/// The options of [`Repo::push_onto`] and [`Repo::push_onto_over_stream`].
///
/// The struct is not `#[non_exhaustive]`. A caller can build it with
/// `..Default::default()`.
#[derive(Debug, Clone, Default)]
pub struct PushOntoOptions {
    /// The revision of the local commit, as
    /// [`resolve_rev`](Repo::resolve_rev) reads it.
    pub rev: String,
    /// The branch of the server that the server moves to the new commit.
    ///
    /// The parent of the new commit is the commit of the branch on the
    /// server when the server writes the commit. If the branch is absent,
    /// the commit has no parent.
    pub onto: String,
    /// The collection id of the namespace of the server that the push
    /// writes.
    ///
    /// `None` writes the local refs of the server. The collection id of the
    /// server also writes its local refs. The bindings of the local commit
    /// do not select the namespace.
    pub collection: Option<String>,
    /// The tags that the server creates at the new commit, in order.
    ///
    /// The server binds each tag. A tag that exists on the server refuses
    /// the push.
    pub tags: Vec<String>,
    /// The names that the new commit binds and that get no ref, in order.
    pub bind_refs: Vec<String>,
    /// The switch that makes a commit with no parent.
    ///
    /// On a branch that exists, the server allows it only for a client that
    /// can also delete the branch.
    pub orphan: bool,
    /// The timestamp of the new commit, in seconds since the Unix epoch, UTC.
    ///
    /// `None` takes the timestamp of the local commit.
    pub timestamp: Option<u64>,
    /// The encoding of the content objects that the push sends.
    pub compression: Compression,
    /// A progress handle that receives the counters of the session.
    pub progress: Option<PushProgress>,
}

/// The local work of a server commit before the session opens.
struct Onto {
    repo: Repo,
    /// The repository lock, held shared until the upload ends. `Commit`
    /// reads no local object.
    lock: LockGuard,
    /// The refs of `Hello`: the branch, then each tag.
    refs: Vec<String>,
    /// The server commit, with the fields of the local commit.
    commit: ServerCommit,
}

/// Methods that make a server commit from a local commit.
impl Repo {
    /// Pushes the tree of a local commit to `endpoint`, and asks the server
    /// to commit it onto a branch.
    ///
    /// The server makes the commit, moves the branch to it, and creates each
    /// tag at it, in one transaction. The push makes the transport ready with
    /// [`PushSession::prepare`] first, as [`push`](Repo::push) does. If the
    /// prepare step refuses the endpoint, the push takes no lock and reads no
    /// commit. Then it does the work of
    /// [`push_onto_over_stream`](Repo::push_onto_over_stream) over a session
    /// that [`PreparedSession::open`](crate::remote::PreparedSession::open)
    /// opens.
    ///
    /// Under the tokio backend, the call must run in a runtime that has the
    /// IO driver and the time driver enabled, as [`push`](Repo::push)
    /// states.
    ///
    /// # Errors
    ///
    /// - [`Error::Remote`] with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the endpoint
    ///   is an `s3://` address. A bucket repository has no server that makes
    ///   a commit.
    /// - [`Error::Remote`] with the error of [`PushSession::prepare`] if the
    ///   endpoint does not apply, or if the HTTP client cannot be built.
    /// - [`Error::Remote`] with the error of
    ///   [`PreparedSession::open`](crate::remote::PreparedSession::open) if the
    ///   session does not open.
    /// - Each error of [`push_onto_over_stream`](Repo::push_onto_over_stream).
    pub async fn push_onto(
        &self,
        endpoint: Endpoint,
        opts: PushOntoOptions,
    ) -> Result<PushOutcome> {
        #[cfg(feature = "s3")]
        if matches!(endpoint, Endpoint::S3(_)) {
            return Err(invalid(
                "a push onto a branch takes an ssh or an HTTP endpoint, and this endpoint is an \
                 s3:// address",
            ));
        }
        let transport = PushSession::prepare(endpoint).await?;
        let onto = self.plan_onto(&opts).await?;
        let session = transport.open(&onto.refs, session_options(&opts)).await?;
        onto.run(session, &opts).await
    }

    /// Pushes the tree of a local commit over a pair of byte streams, and
    /// asks the server to commit it onto a branch.
    ///
    /// `input` comes from the server, and `output` goes to it.
    ///
    /// # Before the session
    ///
    /// The push checks the names and the collection id before it writes a
    /// byte. Then it takes the repository lock as [`LockKind::Shared`] and
    /// holds it until the push sent the objects that the server lacks.
    /// `Commit` reads no local object. The push resolves
    /// [`rev`](PushOntoOptions::rev) and reads its commit. The commit must not
    /// be partial, and its related objects must be empty.
    ///
    /// The server commit holds these fields of the local commit: the root
    /// dirtree, the root dirmeta, the subject, the body, and the metadata
    /// entries in order. The push leaves out each entry under
    /// `ostree.ref-binding` and `ostree.collection-binding`, because the
    /// server writes the bindings of its namespace. The entries under
    /// `ostree.sizes` and `ostree.composefs.digest.v0` pass unchanged. The
    /// timestamp is [`timestamp`](PushOntoOptions::timestamp), else the
    /// timestamp of the local commit.
    ///
    /// The push sends no parent, no commit object, and no detached metadata,
    /// so a signature of the local commit does not reach the server. The
    /// server takes the tip of the branch as the parent and signs the commit
    /// with its own keys.
    ///
    /// # Session
    ///
    /// The session opens with the branch, then each tag, and with
    /// [`collection`](PushOntoOptions::collection) in `Hello`. After
    /// `HelloReply`, the push refuses a tag that the server holds. Then it
    /// checks the `Commit` frame of the server commit and the longest
    /// `CommitReply` against the `max-frame` of the server with
    /// [`PushSession::check_server_commit`]. Each refusal comes before the
    /// push offers an object.
    ///
    /// The push walks the tree of the commit and offers each of its objects
    /// in one round of `Have`. It offers no composefs image. It sends the
    /// objects that the server lacks, and then the server commit. [`PushOutcome::commit`] holds the commit
    /// that the server wrote, and [`PushOutcome::refs`] holds the outcome of
    /// the branch, then of each tag.
    ///
    /// If the push fails after the session opened and before `Commit`, it
    /// ends the session and returns that failure. It writes `Abort` if the
    /// stream is still usable.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidRefspec`] with the name if
    ///   [`validate_refspec`](crate::validate_refspec) refuses the branch or a
    ///   tag, or if the name holds a `:` or is 64 lowercase hex characters.
    ///   The same error is given for a bound name that
    ///   `validate_refspec` refuses or that holds a `:`.
    /// - [`Error::Remote`] with [`InvalidInput`](crate::remote::Error::InvalidInput)
    ///   if a tag is named twice or is the branch, or if `collection` fails
    ///   [`is_collection_id`](crate::is_collection_id) or is longer than 255
    ///   bytes.
    /// - [`Error::RefNotFound`], [`Error::AmbiguousRefspec`],
    ///   [`Error::NoParentCommit`], or another error of
    ///   [`resolve_rev`](Repo::resolve_rev) if `rev` does not resolve.
    /// - [`Error::Remote`] with [`InvalidInput`](crate::remote::Error::InvalidInput)
    ///   if the local repository marks the commit partial, or if the commit
    ///   has related objects.
    /// - [`Error::ObjectNotFound`] if the local repository lacks the commit,
    ///   or a dirtree or a dirmeta of its tree.
    /// - [`Error::LockTimeout`] if the wait for the lock passes
    ///   `[core] lock-timeout-secs`.
    /// - [`Error::Core`] if a commit or a dirtree object does not parse.
    /// - [`Error::Io`] if a read from the file system fails.
    /// - [`Error::Remote`] with
    ///   [`RefMismatch`](crate::remote::Error::RefMismatch) if `HelloReply`
    ///   reports a commit for a tag.
    /// - [`Error::Remote`] with
    ///   [`LimitExceeded`](crate::remote::Error::LimitExceeded) if the
    ///   `Commit` frame of the server commit, or the longest `CommitReply`
    ///   to it, is over the `max-frame` of the server.
    /// - [`Error::Remote`] with the error of the server if the server refuses
    ///   the session, an object, or the server commit. An example is
    ///   [`RefDenied`](crate::remote::Error::RefDenied) if the client has no
    ///   `c` on the branch, or if the server runs hooks, which take no server
    ///   commit.
    /// - [`Error::Remote`] with the error of the session if the stream or the
    ///   protocol fails. If the reply to `Commit` is lost, the error is
    ///   [`CommitOutcomeUnknown`](crate::remote::Error::CommitOutcomeUnknown).
    /// - [`Error::Remote`] with [`Source`](crate::remote::Error::Source) if a
    ///   read of the local repository fails while the session sends objects.
    pub async fn push_onto_over_stream<R, W>(
        &self,
        input: R,
        output: W,
        opts: PushOntoOptions,
    ) -> Result<PushOutcome>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let onto = self.plan_onto(&opts).await?;
        let session =
            PushSession::over_stream(input, output, &onto.refs, session_options(&opts)).await?;
        onto.run(session, &opts).await
    }

    /// Runs the refusals of a server commit and reads the local commit, under
    /// the repository lock held shared.
    async fn plan_onto(&self, opts: &PushOntoOptions) -> Result<Onto> {
        check_ref_name(&opts.onto)?;
        check_tag_names(&opts.tags)?;
        if opts.tags.contains(&opts.onto) {
            return Err(invalid(format!(
                "the tag '{}' is also the branch",
                opts.onto
            )));
        }
        for name in &opts.bind_refs {
            crate::validate_refspec(name)?;
            if name.contains(':') {
                return Err(Error::InvalidRefspec(name.clone()));
            }
        }
        if let Some(reason) = opts.collection.as_deref().and_then(collection_id_refusal) {
            return Err(invalid(reason));
        }
        let lock = self.lock_repo(LockKind::Shared).await?;
        let checksum = self
            .resolve_rev(&opts.rev, false)
            .await?
            .ok_or_else(|| Error::RefNotFound(opts.rev.clone()))?;
        let bytes = self
            .load_object_bytes(ObjectType::Commit, &checksum)
            .await?;
        let (commit, metadata) = Commit::parse_with_metadata_entries(&bytes)?;
        drop(bytes);
        if self.commit_state(&checksum).await? == CommitState::Partial {
            return Err(invalid(format!(
                "commit {checksum} is marked partial in the local repository"
            )));
        }
        if !commit.related.is_empty() {
            return Err(invalid(format!(
                "commit {checksum} has related objects, which a server commit cannot carry"
            )));
        }
        Ok(Onto {
            repo: self.clone(),
            lock,
            refs: std::iter::once(opts.onto.clone())
                .chain(opts.tags.iter().cloned())
                .collect(),
            commit: server_commit(commit, metadata, opts),
        })
    }
}

/// Refuses a branch name that a server commit cannot write.
///
/// The name passes [`validate_refspec`](crate::validate_refspec), holds no
/// `:`, and is not 64 lowercase hex characters. Each refusal is
/// [`Error::InvalidRefspec`] with the name.
fn check_ref_name(name: &str) -> Result<()> {
    crate::validate_refspec(name)?;
    if name.contains(':') || ostrya_core::is_checksum_shaped(name) {
        return Err(Error::InvalidRefspec(name.to_owned()));
    }
    Ok(())
}

/// Returns the server commit of the local commit `commit` under `opts`.
///
/// `metadata` holds the metadata entries of the local commit as bytes, from
/// [`Commit::parse_with_metadata_entries`]. The entries keep their order and
/// their bytes, without the binding keys.
fn server_commit(
    commit: Commit,
    mut metadata: Vec<(String, Vec<u8>)>,
    opts: &PushOntoOptions,
) -> ServerCommit {
    let Commit {
        subject,
        body,
        timestamp,
        root_dirtree,
        root_dirmeta,
        ..
    } = commit;
    metadata.retain(|(key, _)| !BINDING_KEYS.contains(&key.as_str()));
    ServerCommit {
        branch: opts.onto.clone(),
        tags: opts.tags.clone(),
        bind_refs: opts.bind_refs.clone(),
        root_dirtree,
        root_dirmeta,
        subject,
        body,
        metadata,
        timestamp: Some(opts.timestamp.unwrap_or(timestamp)),
        orphan: opts.orphan,
    }
}

/// Returns the options of the session of a server commit.
fn session_options(opts: &PushOntoOptions) -> SessionOptions {
    SessionOptions {
        collection: opts.collection.clone(),
        progress: opts.progress.clone(),
        ..SessionOptions::default()
    }
}

impl Onto {
    /// Runs the server commit over `session`.
    ///
    /// If the push fails before `Commit`, the run ends the session. It writes
    /// `Abort` if the stream is still usable.
    async fn run(self, session: PushSession, opts: &PushOntoOptions) -> Result<PushOutcome> {
        match self.upload(&session, opts.compression).await {
            Ok(()) => {
                let Onto { lock, commit, .. } = self;
                drop(lock);
                Ok(session.server_commit(commit).await?)
            }
            Err(e) => {
                let _ = session.abort().await;
                Err(e)
            }
        }
    }

    /// Runs the checks after `HelloReply`, the walk of the tree, the one
    /// `Have` round, and the upload.
    async fn upload(&self, session: &PushSession, compression: Compression) -> Result<()> {
        let server = session.server();
        // A tag expects an absent ref, so a tag that the server holds fails
        // before any `Have`. The server refuses it at `Commit` too.
        if let Some((tag, current)) = self
            .commit
            .tags
            .iter()
            .find_map(|tag| server.tip(tag).map(|tip| (tag, tip)))
        {
            return Err(Error::Remote(crate::remote::Error::RefMismatch {
                message: format!("ref '{tag}' is at {current}"),
                name: tag.clone(),
                current: Some(current),
            }));
        }
        session.check_server_commit(&self.commit)?;
        let mut seen: HashSet<ObjectName> = HashSet::new();
        let mut names = Vec::new();
        self.repo
            .collect_tree_strict(
                self.commit.root_dirtree,
                self.commit.root_dirmeta,
                &mut seen,
                &mut names,
            )
            .await?;
        drop(seen);
        let missing = session.missing(&names).await?;
        drop(names);
        let source = RepoSource::new(self.repo.clone(), DetachedMetadataFilter::default());
        let no_commits: &[Checksum] = &[];
        session
            .send(&source, &missing, no_commits, compression)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ostrya_core::{Type, Value};

    use super::*;

    /// Returns the server commit of `local` under `opts`, read from the bytes
    /// of `local`.
    fn from_local(local: &Commit, opts: &PushOntoOptions) -> ServerCommit {
        let bytes = local.serialize().unwrap();
        let (commit, metadata) = Commit::parse_with_metadata_entries(&bytes).unwrap();
        server_commit(commit, metadata, opts)
    }

    fn string(s: &str) -> Value {
        Value::variant(Type::Str, Value::Str(s.into()))
    }

    fn entry(key: &str, value: Value) -> Value {
        Value::Tuple(vec![Value::Str(key.into()), value])
    }

    fn commit(metadata: Vec<Value>) -> Commit {
        Commit {
            metadata: Value::Array(metadata),
            parent: Some(Checksum::from_bytes([3; 32])),
            related: Vec::new(),
            subject: "subject".into(),
            body: "body".into(),
            timestamp: 1_700_000_000,
            root_dirtree: Checksum::from_bytes([1; 32]),
            root_dirmeta: Checksum::from_bytes([2; 32]),
        }
    }

    /// The server commit keeps the order, the duplicates, and the bytes of
    /// the metadata entries, and leaves out the binding keys.
    #[test]
    fn the_server_commit_keeps_the_entries_without_the_bindings() {
        let sizes = Value::variant(Type::parse("a(ayttt)").unwrap(), Value::Array(Vec::new()));
        let local = commit(vec![
            entry("z", string("1")),
            entry("ostree.ref-binding", ostrya_core::ref_binding(&["main"])),
            entry("a", string("2")),
            entry("ostree.collection-binding", string("org.example.C")),
            entry("z", string("3")),
            entry("ostree.sizes", sizes.clone()),
        ]);
        let opts = PushOntoOptions {
            onto: "main".into(),
            tags: vec!["t".into()],
            bind_refs: vec!["b".into()],
            orphan: true,
            ..Default::default()
        };
        let sc = from_local(&local, &opts);
        let v = |value: &Value| ostrya_core::to_bytes(&Type::Variant, value).unwrap();
        assert_eq!(
            sc.metadata,
            [
                ("z".to_owned(), v(&string("1"))),
                ("a".to_owned(), v(&string("2"))),
                ("z".to_owned(), v(&string("3"))),
                ("ostree.sizes".to_owned(), v(&sizes)),
            ]
        );
        assert_eq!(sc.branch, "main");
        assert_eq!(sc.tags, ["t"]);
        assert_eq!(sc.bind_refs, ["b"]);
        assert!(sc.orphan);
        assert_eq!((sc.subject.as_str(), sc.body.as_str()), ("subject", "body"));
        assert_eq!(sc.root_dirtree, Checksum::from_bytes([1; 32]));
        assert_eq!(sc.root_dirmeta, Checksum::from_bytes([2; 32]));
        assert_eq!(sc.timestamp, Some(1_700_000_000));

        let opts = PushOntoOptions {
            timestamp: Some(5),
            ..opts
        };
        assert_eq!(from_local(&commit(Vec::new()), &opts).timestamp, Some(5));
    }
}
