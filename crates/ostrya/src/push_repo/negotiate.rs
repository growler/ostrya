//! The push of commits from a repository: the checks before the session
//! opens, the commit walk, the two `Have` rounds, and the ref updates.

use std::collections::{HashMap, HashSet};

use futures_io::{AsyncRead, AsyncWrite};
use ostrya_core::{Checksum, Commit, CommitLink, ObjectName, ObjectType};

use super::invalid;
use super::refspec::PushTarget;
use super::source::RepoSource;
use crate::error::{Error, Result};
use crate::lock::{LockGuard, LockKind};
use crate::read::CommitState;
use crate::refs::MAX_COLLECTION_ID_LEN;
use crate::related::RelatedRule;
use crate::remote::{
    Compression, Endpoint, Expected, PushOutcome, PushProgress, PushSession, RefUpdate, ServerInfo,
    SessionOptions,
};
use crate::repo::Repo;

/// The options of [`Repo::push`] and [`Repo::push_over_stream`].
///
/// The struct is not `#[non_exhaustive]`. A caller can build it with
/// `..Default::default()`.
#[derive(Clone, Debug, Default)]
pub struct RepoPushOptions {
    /// The refspecs, each `SRC[:DST]`, split at the last `:`.
    ///
    /// `SRC` is a revision of the local repository, as
    /// [`resolve_rev`](Repo::resolve_rev) reads it. `DST` is the ref of the
    /// server that takes the commit of `SRC`. `:DST` deletes the ref `DST` of
    /// the server. If `SRC` is a ref with no `^` suffix, `DST` defaults to
    /// `SRC`.
    ///
    /// A `SRC` with a `^` suffix needs a `DST`. A `SRC` that resolves as a
    /// full or an abbreviated checksum also needs a `DST`. Because the split
    /// is at the last `:`, `SRC` can name a remote ref, as in
    /// `origin:main:DST`.
    ///
    /// `DST` holds no `:`, so a push names no remote ref of the server.
    /// `DST` holds no `^`. A revision reads 64 lowercase hex characters as a
    /// commit checksum, so a `DST` that takes a commit is not 64 lowercase hex
    /// characters. A delete can name such a `DST`.
    pub refspecs: Vec<String>,
    /// The depth of the parent chain that the push reads for each source
    /// commit.
    ///
    /// - `None`: the push sends the parent chain back to the server tip of
    ///   the ref, the tip excluded. If the chain does not hold the tip, the
    ///   push sends the source commit alone.
    /// - `Some(0)`: the push reads each source commit alone.
    /// - `Some(n)`: the push reads `n` more parents.
    /// - `Some(-1)`: the push reads the whole chain that the local repository
    ///   holds.
    ///
    /// The push refuses a value less than `-1`.
    pub depth: Option<i32>,
    /// The collection id of the namespace of the server that the push
    /// writes.
    ///
    /// The push reads the `ostree.collection-binding` of each source commit
    /// before it opens the session. The namespace is the collection of these
    /// bindings: a commit with no binding goes to the local refs, and a
    /// commit bound to `ID` goes to the namespace of `ID`. With `None`, the
    /// bindings alone give the namespace. A value must agree with each
    /// binding, and a commit with no binding cannot go to the refs of a
    /// collection. The server writes the refs of the collection of its own
    /// collection id as its local refs, under `refs/heads/`. It writes the
    /// refs of each other collection under `refs/mirrors/ID/`.
    ///
    /// A push to a bucket repository takes the `config` of the bucket in the
    /// role of the server: no collection, or the `[core] collection-id` of
    /// the bucket, writes `refs/heads/DST`, and each other collection writes
    /// `refs/mirrors/ID/DST`, also in a bucket with no collection id.
    pub collection: Option<String>,
    /// The tags that the push creates at the source commit.
    ///
    /// Each tag is one more ref update that expects an absent ref, also with
    /// [`force`](RepoPushOptions::force). The refspecs that are not deletes
    /// must give one source commit, and its `ostree.ref-binding` must hold
    /// each tag. A tag that exists on the server gets
    /// [`RefMismatch`](crate::remote::Error::RefMismatch) after `HelloReply`,
    /// and the push sends no `Have` and no object.
    pub tags: Vec<String>,
    /// The encoding of the content objects that the push sends.
    pub compression: Compression,
    /// The switch that updates each ref whatever its state on the server.
    ///
    /// If `true`, each ref update expects any state. The push also asks the
    /// server to allow an update that is not a fast-forward.
    pub force: bool,
    /// A progress handle that receives the counters of the session.
    pub progress: Option<PushProgress>,
    /// The switch that removes the writer lock of a bucket repository before
    /// the push takes its own.
    ///
    /// A push over ssh or HTTP refuses `true`.
    pub break_lock: bool,
    /// The part size of a multipart upload to a bucket repository, for
    /// tests. `None` takes the part size rule of the bucket client.
    ///
    /// The bucket client refuses a part size below 5 MiB. A push over ssh
    /// or HTTP refuses a value.
    #[doc(hidden)]
    pub part_size: Option<u64>,
}

/// Refuses the fields of `opts` that apply to a push to a bucket repository
/// alone.
fn refuse_bucket_fields(opts: &RepoPushOptions) -> Result<()> {
    let set = [
        ("break_lock", opts.break_lock),
        ("part_size", opts.part_size.is_some()),
    ];
    match set.iter().find(|(_, set)| *set) {
        Some((name, _)) => Err(invalid(format!(
            "{name} applies to a push to an s3:// address"
        ))),
        None => Ok(()),
    }
}

/// A commit of a chain, as the local repository holds it.
#[derive(Debug, Clone, Copy)]
pub(super) enum Local {
    /// The repository holds the commit and does not mark it partial.
    Held(CommitLink),
    /// The repository marks the commit partial.
    Partial,
    /// The repository does not hold the commit.
    Absent,
}

/// Returns the parts of a parsed commit that the push reads.
pub(super) fn link_of(commit: &Commit) -> CommitLink {
    CommitLink {
        parent: commit.parent,
        root_dirtree: commit.root_dirtree,
        root_dirmeta: commit.root_dirmeta,
    }
}

/// The local work of a push before the session opens.
pub(super) struct Plan {
    pub(super) repo: Repo,
    /// The repository lock, held shared until the push returns.
    pub(super) _lock: LockGuard,
    /// The `DST` of each target, in the order of the refspecs, then each
    /// tag: the refs of `Hello`.
    pub(super) refs: Vec<String>,
    pub(super) targets: Vec<PushTarget>,
    /// The collection id that `Hello` names.
    pub(super) collection: Option<String>,
    /// The source commits, each once, in the order of the targets, with the
    /// `ostree.collection-binding` of each.
    pub(super) sources: Vec<(Checksum, Option<String>)>,
    /// The history commits of each target, from the parent of its source
    /// commit on, as the walk read them. A delete has none. The negotiation
    /// drops the chains when it has the commits to offer.
    pub(super) chains: Vec<Vec<Checksum>>,
    /// Each commit the walk read. The negotiation drops the map after the
    /// tree walk.
    pub(super) commits: HashMap<Checksum, Local>,
}

/// Methods that push commits to a remote.
impl Repo {
    /// Pushes the commits of `opts.refspecs` to `endpoint` and updates the
    /// server refs.
    ///
    /// The server updates all the refs in one transaction.
    /// [`resolve_push`](crate::endpoint::resolve_push) gives the endpoint of a
    /// configured remote or of an address. A caller can also build the
    /// endpoint itself.
    ///
    /// The push makes the transport ready with [`PushSession::prepare`]. The
    /// prepare step reads no file that the endpoint names. For an HTTP push,
    /// it builds the HTTP client. An `https://` endpoint with
    /// [`TrustRoots::System`](crate::fetch::TrustRoots::System) reads the
    /// trust store of the host.
    ///
    /// This step comes before the checks and the commit walk of
    /// [`push_over_stream`](Repo::push_over_stream). If the prepare step
    /// refuses the endpoint, the push takes no lock and reads no refspec.
    /// After this step, the push runs the checks and the walk. It opens the
    /// session with [`PreparedSession::open`](crate::remote::PreparedSession::open)
    /// and does the rest of the work of `push_over_stream`.
    ///
    /// # Tokio runtime
    ///
    /// Under the tokio backend, the call must run in a runtime that has the
    /// IO driver and the time driver enabled. The runtime builder enables
    /// them with `enable_io` and `enable_time`, or with `enable_all`. The
    /// ssh child process, its pipes, and the connections of an HTTP session
    /// need the IO driver. The time limits of the session need the time
    /// driver.
    ///
    /// # Bucket repository
    ///
    /// With the `s3` feature, an `Endpoint::S3` goes to
    /// `Repo::push_to_bucket`, which writes the bucket repository with no
    /// session. The call gives the outcome of that push and drops the holder
    /// of a lock that [`break_lock`](RepoPushOptions::break_lock) removed.
    /// Each other endpoint refuses
    /// [`break_lock`](RepoPushOptions::break_lock) and a part size.
    ///
    /// # Errors
    ///
    /// - [`Error::Remote`] with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the endpoint
    ///   is not a bucket repository and `opts` sets `break_lock` or a part
    ///   size. The push then takes no lock.
    /// - [`Error::Remote`] with the error of [`PushSession::prepare`] if the
    ///   endpoint does not apply, or if the HTTP client cannot be built.
    /// - [`Error::Remote`] with the error of
    ///   [`PreparedSession::open`](crate::remote::PreparedSession::open) if the
    ///   session does not open.
    /// - Each error of [`push_over_stream`](Repo::push_over_stream).
    /// - For an `Endpoint::S3`, each error of `Repo::push_to_bucket`.
    pub async fn push(&self, endpoint: Endpoint, opts: RepoPushOptions) -> Result<PushOutcome> {
        #[cfg(feature = "s3")]
        let endpoint = match endpoint {
            Endpoint::S3(s3) => {
                return Ok(Box::pin(self.push_to_bucket(s3, opts)).await?.outcome);
            }
            other => other,
        };
        refuse_bucket_fields(&opts)?;
        let transport = PushSession::prepare(endpoint).await?;
        let plan = self.plan_push(&opts).await?;
        let session = transport
            .open(&plan.refs, plan.session_options(&opts))
            .await?;
        plan.run(session, &opts).await
    }

    /// Pushes the commits of `opts.refspecs` over a pair of byte streams.
    ///
    /// The server updates all the refs in one transaction. `input` comes from
    /// the server, and `output` goes to it.
    ///
    /// The push checks the depth, the refspecs, and the source commits
    /// before it writes a byte. After the depth check, it takes the repository
    /// lock as [`LockKind::Shared`] and holds it to the end of the call. A
    /// prune of the local repository waits for the push.
    ///
    /// # Commit walk
    ///
    /// After the checks, the push reads only commit objects:
    ///
    /// - If `depth` is `None`, it reads the parent chain of each source
    ///   commit to the root.
    /// - If `depth` is `Some(n)`, it reads `n` parents.
    /// - If `depth` is `Some(-1)`, it reads the whole chain.
    ///
    /// Each chain stops at the first commit that the local repository does
    /// not hold. It also stops at the first commit that the local repository
    /// marks partial. If `depth` is `Some`, the chain stops before that
    /// commit. If `depth` is `None`, that commit is the last commit of the
    /// chain, and the push does not walk its tree.
    ///
    /// # Namespace
    ///
    /// Before the session opens, the push reads the `ostree.collection-binding`
    /// of each source commit. The `Hello` of the session names
    /// [`collection`](RepoPushOptions::collection), else the binding of the
    /// source commits, else no collection. Two different bindings, and a
    /// binding that differs from `collection`, refuse the push before it
    /// writes a byte.
    ///
    /// `HelloReply` reports the namespace that the server selected. The
    /// server takes its own collection id as its local refs. A bound commit
    /// needs a namespace of the same id: the collection, or the local refs of
    /// a server with that collection id. A commit with no binding needs the
    /// local refs. Else the push sends no object and ends the session with
    /// `Abort`.
    ///
    /// # Negotiation
    ///
    /// The session opens with the `DST` of each refspec, in order, then each
    /// tag.
    ///
    /// If `depth` is `None`, the push cuts each chain at the server tip of
    /// its `DST`, the tip excluded. If the chain does not hold the tip, the
    /// push keeps the source commit alone. It also keeps the source commit
    /// alone if the server does not hold the `DST`. The server then decides
    /// if the update is a fast-forward.
    ///
    /// The negotiation offers the commits first, in the first `Have` round.
    /// Then the push walks the tree of each source commit, also when the
    /// server holds that commit. It also walks the tree of each history
    /// commit that the server lacks. It does not walk the tree of a history
    /// commit that the server holds.
    ///
    /// If the local repository lacks a dirtree or a dirmeta, the push ends
    /// the session with `Abort`. The second `Have` round offers the tree
    /// objects. After them it offers the composefs image of each walked
    /// commit that the local repository holds, so a server that holds a
    /// source commit with no image gets the image. The push sends the objects
    /// that the server lacks.
    ///
    /// The push also sends the detached metadata of each commit that it sends
    /// and of each source commit. It sends the stored `.commitmeta` bytes with
    /// no parse, so the server refuses a `.commitmeta` that is not an `a{sv}`
    /// dict.
    ///
    /// # Ref updates
    ///
    /// Each ref update expects the state that the server reported when the
    /// session opened: the commit of the ref, or no ref. If `force` is
    /// `true`, each update expects any state. A refspec `:DST` is an update
    /// with no new commit. If all the refspecs are deletes, the push offers
    /// and sends no object. Each tag of
    /// [`tags`](RepoPushOptions::tags) follows the updates of the refspecs.
    /// It takes the source commit and expects no ref, also if `force` is
    /// `true`.
    ///
    /// # Failure
    ///
    /// If the push fails after the session opened and before `Commit`, it
    /// ends the session and returns that failure. It writes `Abort` if the
    /// stream is still usable.
    ///
    /// # Errors
    ///
    /// - [`Error::Remote`] with [`InvalidInput`](crate::remote::Error::InvalidInput)
    ///   if `opts` sets `break_lock` or a part size, which apply to a push to
    ///   a bucket repository alone.
    /// - [`Error::Remote`] with [`InvalidInput`](crate::remote::Error::InvalidInput)
    ///   if `depth` is less than `-1`, or if `collection` or the
    ///   `ostree.collection-binding` of a source commit fails
    ///   [`is_collection_id`](crate::is_collection_id) or is longer than 255
    ///   bytes.
    /// - [`Error::InvalidRefspec`] with the tag if
    ///   [`validate_refspec`](crate::validate_refspec) refuses a tag, or if a
    ///   tag holds a `:` or is 64 lowercase hex characters.
    /// - [`Error::Remote`] with [`InvalidInput`](crate::remote::Error::InvalidInput)
    ///   if a tag is named twice or is the `DST` of a refspec, or if `tags`
    ///   is not empty and the refspecs that are not deletes do not give
    ///   exactly one source commit.
    /// - [`Error::Remote`] with [`InvalidInput`](crate::remote::Error::InvalidInput)
    ///   if `refspecs` is empty, or if a refspec is empty, is `:`, or names an
    ///   empty `DST`.
    /// - [`Error::Remote`] with [`InvalidInput`](crate::remote::Error::InvalidInput)
    ///   if a `SRC` with a `^` suffix or a checksum `SRC` has no `DST`, or if
    ///   two refspecs name the same `DST`.
    /// - [`Error::Remote`] with [`InvalidInput`](crate::remote::Error::InvalidInput)
    ///   if the local repository marks a source commit partial.
    /// - [`Error::InvalidRefspec`] with the `DST` if
    ///   [`validate_refspec`](crate::validate_refspec) refuses a `DST`, or if
    ///   a `DST` holds a `^`. A `DST` of 64 lowercase hex characters that takes
    ///   a commit also gives this error. A delete (`:DST`) of such a `DST`
    ///   passes.
    /// - [`Error::RefNotFound`], [`Error::AmbiguousRefspec`],
    ///   [`Error::NoParentCommit`], or another error of
    ///   [`resolve_rev`](Repo::resolve_rev) if a `SRC` does not resolve.
    /// - [`Error::Remote`] with
    ///   [`BindingMismatch`](crate::remote::Error::BindingMismatch) if the
    ///   `ostree.ref-binding` of a source commit is a list that does not hold
    ///   its `DST`. A commit with no binding, or with an empty list, passes.
    /// - [`Error::Remote`] with
    ///   [`BindingMismatch`](crate::remote::Error::BindingMismatch) if the
    ///   `ostree.ref-binding` of the source commit of a tag does not hold the
    ///   tag. A commit with no ref binding fails too.
    /// - [`Error::Remote`] with
    ///   [`BindingMismatch`](crate::remote::Error::BindingMismatch) if two
    ///   source commits have different `ostree.collection-binding` values, or
    ///   if a binding differs from `collection`.
    /// - [`Error::Remote`] with
    ///   [`BindingMismatch`](crate::remote::Error::BindingMismatch) if the
    ///   namespace that the server reports does not agree with the binding of
    ///   a source commit, as "Namespace" states.
    /// - [`Error::ObjectNotFound`] if the local repository lacks a source
    ///   commit, or a dirtree or a dirmeta of a tree that the push walks.
    /// - [`Error::LockTimeout`] if the wait for the lock passes
    ///   `[core] lock-timeout-secs`.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is less than
    ///   `-1`.
    /// - [`Error::Core`] if `[core] locking` is not a boolean or
    ///   `[core] lock-timeout-secs` is not an integer, or if a commit or a
    ///   dirtree object does not parse.
    /// - [`Error::Io`] if a read from the file system fails, or if a metadata
    ///   object is larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    /// - [`Error::Remote`] with
    ///   [`RefMismatch`](crate::remote::Error::RefMismatch) if `HelloReply`
    ///   reports a commit for a tag.
    /// - [`Error::Remote`] with the error of the server if the server refuses
    ///   the session, an object, or a ref update.
    /// - [`Error::Remote`] with the error of the session if the stream or the
    ///   protocol fails. If the reply to `Commit` is lost, the error is
    ///   [`CommitOutcomeUnknown`](crate::remote::Error::CommitOutcomeUnknown).
    /// - [`Error::Remote`] with [`Source`](crate::remote::Error::Source) if a
    ///   read of the local repository fails while the session sends objects.
    pub async fn push_over_stream<R, W>(
        &self,
        input: R,
        output: W,
        opts: RepoPushOptions,
    ) -> Result<PushOutcome>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        refuse_bucket_fields(&opts)?;
        let plan = self.plan_push(&opts).await?;
        let session =
            PushSession::over_stream(input, output, &plan.refs, plan.session_options(&opts))
                .await?;
        plan.run(session, &opts).await
    }

    /// Runs the refusals and the commit walk of a push, under the repository
    /// lock held shared.
    pub(super) async fn plan_push(&self, opts: &RepoPushOptions) -> Result<Plan> {
        if let Some(depth) = opts.depth
            && depth < -1
        {
            return Err(invalid(format!("depth {depth} is below -1")));
        }
        if let Some(reason) = opts.collection.as_deref().and_then(collection_id_refusal) {
            return Err(invalid(reason));
        }
        check_tag_names(&opts.tags)?;
        let lock = self.lock_repo(LockKind::Shared).await?;
        let targets = self.push_targets(&opts.refspecs).await?;

        let mut sources: Vec<(Checksum, Commit)> = Vec::new();
        let mut commits: HashMap<Checksum, Local> = HashMap::new();
        for target in &targets {
            let Some(checksum) = target.commit else {
                continue;
            };
            let position = match sources.iter().position(|(c, _)| *c == checksum) {
                Some(position) => position,
                None => {
                    let (commit, state) = self.load_commit(&checksum).await?;
                    if state == CommitState::Partial {
                        return Err(invalid(format!(
                            "commit {checksum} for '{}' is marked partial in the local \
                             repository",
                            target.dst
                        )));
                    }
                    commits.insert(checksum, Local::Held(link_of(&commit)));
                    sources.push((checksum, commit));
                    sources.len() - 1
                }
            };
            check_ref_binding(&checksum, &sources[position].1, &target.dst)?;
        }
        check_tags(&opts.tags, &targets, &sources)?;
        let sources: Vec<(Checksum, Option<String>)> = sources
            .into_iter()
            .map(|(checksum, commit)| (checksum, commit.collection_binding().map(str::to_owned)))
            .collect();
        let collection = hello_collection(opts.collection.as_deref(), &sources)?;

        // With no depth the chain runs to the root, and the cut at the
        // server tip comes after `HelloReply`.
        let depth = opts.depth.unwrap_or(-1);
        let mut chains = Vec::with_capacity(targets.len());
        for target in &targets {
            let mut chain = Vec::new();
            if let Some(source) = target.commit {
                let mut next = match commits[&source] {
                    Local::Held(link) => link.parent,
                    Local::Partial | Local::Absent => unreachable!("a source commit is held"),
                };
                let mut remaining = depth;
                while remaining != 0
                    && let Some(parent) = next
                {
                    match self.history_commit(&parent, &mut commits).await? {
                        Local::Held(link) => {
                            chain.push(parent);
                            next = link.parent;
                        }
                        // With no depth, a partial commit ends the chain, so
                        // that the cut can find the server tip there.
                        Local::Partial => {
                            if opts.depth.is_none() {
                                chain.push(parent);
                            }
                            break;
                        }
                        Local::Absent => break,
                    }
                    if remaining > 0 {
                        remaining -= 1;
                    }
                }
            }
            chains.push(chain);
        }

        Ok(Plan {
            repo: self.clone(),
            _lock: lock,
            refs: targets
                .iter()
                .map(|t| t.dst.clone())
                .chain(opts.tags.iter().cloned())
                .collect(),
            targets,
            collection,
            chains,
            sources,
            commits,
        })
    }

    /// Returns the local state of the history commit `checksum`, read once.
    ///
    /// One blocking call reads the object and the partial marker, and parses
    /// the link of the commit.
    pub(super) async fn history_commit(
        &self,
        checksum: &Checksum,
        commits: &mut HashMap<Checksum, Local>,
    ) -> Result<Local> {
        if let Some(local) = commits.get(checksum) {
            return Ok(*local);
        }
        let repo = self.clone();
        let key = *checksum;
        let local = ostrya_rt::unblock(move || {
            let bytes = match repo.load_object_bytes_blocking(ObjectType::Commit, &key) {
                Ok(bytes) => bytes,
                Err(Error::ObjectNotFound { .. }) => return Ok(Local::Absent),
                Err(e) => return Err(e),
            };
            Ok(match repo.commit_state_blocking(&key)? {
                CommitState::Normal => Local::Held(Commit::parse_link(&bytes)?),
                CommitState::Partial => Local::Partial,
            })
        })
        .await?;
        commits.insert(*checksum, local);
        Ok(local)
    }
}

/// Refuses a tag name that a push cannot create.
///
/// A tag passes [`validate_refspec`](crate::validate_refspec), holds no `:`,
/// is not 64 lowercase hex characters, and is named once. Each refusal of the
/// name is [`Error::InvalidRefspec`] with the name. A repeated name is
/// [`InvalidInput`](crate::remote::Error::InvalidInput).
pub(super) fn check_tag_names(tags: &[String]) -> Result<()> {
    let mut seen = HashSet::new();
    for tag in tags {
        crate::validate_refspec(tag)?;
        if tag.contains(':') || ostrya_core::is_checksum_shaped(tag) {
            return Err(Error::InvalidRefspec(tag.clone()));
        }
        if !seen.insert(tag.as_str()) {
            return Err(invalid(format!("the tag '{tag}' is named twice")));
        }
    }
    Ok(())
}

/// Refuses tags that the targets and the source commits of a push cannot
/// carry.
///
/// A tag is not the `DST` of a refspec. With one tag or more, the refspecs
/// that are not deletes give exactly one source commit, and the
/// `ostree.ref-binding` of that commit holds each tag.
fn check_tags(
    tags: &[String],
    targets: &[PushTarget],
    sources: &[(Checksum, Commit)],
) -> Result<()> {
    if tags.is_empty() {
        return Ok(());
    }
    let dsts: HashSet<&str> = targets.iter().map(|t| t.dst.as_str()).collect();
    if let Some(tag) = tags.iter().find(|tag| dsts.contains(tag.as_str())) {
        return Err(invalid(format!(
            "the tag '{tag}' is also the destination of a refspec"
        )));
    }
    let (checksum, commit) = match sources {
        [] => return Err(invalid("a tag needs a refspec that is not a delete")),
        [source] => source,
        _ => {
            return Err(invalid(format!(
                "a tag needs one source commit, and the refspecs give {}",
                sources.len()
            )));
        }
    };
    let bindings = commit.ref_bindings();
    let bound: HashSet<&str> = bindings.iter().copied().collect();
    for tag in tags {
        if !bound.contains(tag.as_str()) {
            return Err(Error::Remote(crate::remote::Error::BindingMismatch(
                format!(
                    "commit {checksum} is bound to the refs {bindings:?}, which do not hold the \
                     tag '{tag}'"
                ),
            )));
        }
    }
    Ok(())
}

/// Returns the reason that `id` cannot name a namespace of the server, or
/// `None` if it can.
///
/// The id is one name under `refs/mirrors/` on the server, so it is not
/// longer than [`MAX_COLLECTION_ID_LEN`] bytes. It also passes
/// [`is_collection_id`](crate::is_collection_id).
pub(super) fn collection_id_refusal(id: &str) -> Option<String> {
    if id.len() > MAX_COLLECTION_ID_LEN {
        Some(format!(
            "the collection id of {} bytes is longer than {MAX_COLLECTION_ID_LEN} bytes",
            id.len()
        ))
    } else if !ostrya_core::is_collection_id(id) {
        Some(format!("invalid collection id '{id}'"))
    } else {
        None
    }
}

/// Returns the collection id that the `Hello` of a push names.
///
/// `requested` is [`RepoPushOptions::collection`]. `sources` holds each
/// source commit with its `ostree.collection-binding`. The result is
/// `requested`, else the binding of the source commits, else `None`. The
/// server maps its own collection id to its local refs, so the result does
/// not need to know that id.
///
/// Two source commits bound to different collections, and a binding that
/// differs from `requested`, are
/// [`BindingMismatch`](crate::remote::Error::BindingMismatch). A commit with
/// no binding passes here, and the check after `HelloReply` decides it.
/// A binding that [`collection_id_refusal`] refuses is
/// [`InvalidInput`](crate::remote::Error::InvalidInput).
pub(super) fn hello_collection(
    requested: Option<&str>,
    sources: &[(Checksum, Option<String>)],
) -> Result<Option<String>> {
    let mut bound: Option<(&Checksum, &str)> = None;
    for (checksum, binding) in sources {
        let Some(binding) = binding.as_deref() else {
            continue;
        };
        match bound {
            Some((first, id)) if id != binding => {
                return Err(binding_mismatch(format!(
                    "commit {checksum} is bound to the collection '{binding}', and commit \
                     {first} to the collection '{id}'"
                )));
            }
            Some(_) => {}
            None => {
                if let Some(reason) = collection_id_refusal(binding) {
                    return Err(invalid(format!(
                        "commit {checksum} has a collection binding that a push cannot name: \
                         {reason}"
                    )));
                }
                bound = Some((checksum, binding));
            }
        }
    }
    match (requested, bound) {
        (Some(requested), Some((checksum, id))) if requested != id => Err(binding_mismatch(
            format!("commit {checksum} is bound to the collection '{id}', not '{requested}'"),
        )),
        (Some(requested), _) => Ok(Some(requested.to_owned())),
        (None, bound) => Ok(bound.map(|(_, id)| id.to_owned())),
    }
}

/// Checks the collection binding of each source commit against the namespace
/// that `server` reports.
///
/// A bound commit needs the binding id of the namespace:
/// [`ServerInfo::binding_collection`]. A commit with no binding needs the
/// local refs of the server. Each other commit is
/// [`BindingMismatch`](crate::remote::Error::BindingMismatch).
fn check_namespace(server: &ServerInfo, sources: &[(Checksum, Option<String>)]) -> Result<()> {
    check_bindings(
        server.collection.as_deref(),
        server.binding_collection(),
        sources,
    )
}

/// Checks the collection binding of each source commit against the
/// namespace that a push writes.
///
/// `collection` is the id of a collection namespace, or `None` for the local
/// refs. `binding` is the id that a bound commit must name: the collection
/// of the namespace, or the collection id of the repository for its local
/// refs. A commit with no binding needs the local refs. Each other commit is
/// [`BindingMismatch`](crate::remote::Error::BindingMismatch).
pub(super) fn check_bindings(
    collection: Option<&str>,
    binding: Option<&str>,
    sources: &[(Checksum, Option<String>)],
) -> Result<()> {
    let namespace = match collection {
        Some(id) => format!("the collection '{id}'"),
        None => "the local refs".to_owned(),
    };
    for (checksum, bound) in sources {
        match (bound.as_deref(), binding) {
            (Some(bound), Some(id)) if bound == id => {}
            (Some(bound), _) => {
                return Err(binding_mismatch(format!(
                    "commit {checksum} is bound to the collection '{bound}', and the push \
                     writes {namespace}"
                )));
            }
            (None, _) if collection.is_some() => {
                return Err(binding_mismatch(format!(
                    "commit {checksum} has no collection binding, and the push writes \
                     {namespace}"
                )));
            }
            (None, _) => {}
        }
    }
    Ok(())
}

fn binding_mismatch(message: String) -> Error {
    Error::Remote(crate::remote::Error::BindingMismatch(message))
}

/// Refuses a commit whose `ostree.ref-binding` is a list that does not hold
/// `dst`.
///
/// The check compares `dst` without the `REMOTE:` part of a remote ref. A
/// commit with no binding, or with an empty list, passes, as on the server.
pub(super) fn check_ref_binding(checksum: &Checksum, commit: &Commit, dst: &str) -> Result<()> {
    let bindings = commit.ref_bindings();
    let bare = dst.split_once(':').map_or(dst, |(_, bare)| bare);
    if bindings.is_empty() || bindings.contains(&bare) {
        return Ok(());
    }
    Err(Error::Remote(crate::remote::Error::BindingMismatch(
        format!("commit {checksum} is bound to the refs {bindings:?}, which do not hold '{bare}'"),
    )))
}

impl Plan {
    /// Returns the options of the session of the push.
    fn session_options(&self, opts: &RepoPushOptions) -> SessionOptions {
        SessionOptions {
            collection: self.collection.clone(),
            progress: opts.progress.clone(),
            ..SessionOptions::default()
        }
    }

    /// Runs the push over `session`.
    ///
    /// If the push fails before `Commit`, the run ends the session. It writes
    /// `Abort` if the stream is still usable.
    async fn run(mut self, session: PushSession, opts: &RepoPushOptions) -> Result<PushOutcome> {
        match self.negotiate(&session, opts).await {
            Ok(updates) => Ok(session.commit(&updates, opts.force).await?),
            Err(e) => {
                let _ = session.abort().await;
                Err(e)
            }
        }
    }

    /// Runs the checks after `HelloReply`, the two `Have` rounds, and the
    /// upload.
    ///
    /// Returns the ref updates of `Commit`.
    async fn negotiate(
        &mut self,
        session: &PushSession,
        opts: &RepoPushOptions,
    ) -> Result<Vec<RefUpdate>> {
        let server = session.server();
        check_namespace(server, &self.sources)?;
        // A tag expects an absent ref, so a tag that the server holds fails
        // before any `Have`. The server refuses it at `Commit` too.
        if let Some((tag, current)) = opts
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

        // The commits to offer: each source commit and its chain. If no depth
        // is set, the chain is cut at the server tip.
        let chains = std::mem::take(&mut self.chains);
        let mut offered: HashSet<Checksum> = HashSet::new();
        let mut names = Vec::new();
        for (target, chain) in self.targets.iter().zip(&chains) {
            let Some(source) = target.commit else {
                continue;
            };
            let history = offered_history(opts.depth, server.tip(&target.dst), chain);
            for commit in std::iter::once(&source).chain(history) {
                if offered.insert(*commit) {
                    names.push(ObjectName::new(*commit, ObjectType::Commit));
                }
            }
        }

        drop(chains);
        drop(offered);
        let commits = std::mem::take(&mut self.commits);

        if !names.is_empty() {
            let missing_commits = session.missing(&names).await?;
            drop(names);
            let lacking: HashSet<Checksum> = missing_commits.iter().map(|n| n.checksum).collect();

            // The trees of the source commits, and of each history commit
            // that the server lacks.
            let sources: HashSet<Checksum> = self.sources.iter().map(|(c, _)| *c).collect();
            let walked = self
                .sources
                .iter()
                .map(|(c, _)| *c)
                .chain(
                    missing_commits
                        .iter()
                        .map(|n| n.checksum)
                        .filter(|c| !sources.contains(c)),
                )
                .collect::<Vec<_>>();
            let mut seen = HashSet::new();
            let mut tree_names = Vec::new();
            for commit in &walked {
                let Local::Held(link) = commits[commit] else {
                    unreachable!("an offered commit is held");
                };
                self.repo
                    .collect_tree_strict(
                        link.root_dirtree,
                        link.root_dirmeta,
                        &mut seen,
                        &mut tree_names,
                    )
                    .await?;
            }
            drop(commits);
            drop(seen);
            // The composefs image of each walked commit that this repository
            // holds goes after the trees. A source commit that the server
            // holds is walked too, so the server gets an image that it lacks
            // for that commit.
            let repo = self.repo.clone();
            let images = ostrya_rt::unblock(move || -> Result<Vec<ObjectName>> {
                let mut images = Vec::new();
                for commit in walked {
                    if repo.has_object_blocking(ObjectType::ComposefsImage, &commit)? {
                        images.push(ObjectName::new(commit, ObjectType::ComposefsImage));
                    }
                }
                Ok(images)
            })
            .await?;
            tree_names.extend(images);
            let missing_trees = session.missing(&tree_names).await?;
            drop(tree_names);

            let mut needed = missing_commits;
            needed.extend(missing_trees);
            // The detached metadata goes with each commit the push sends and
            // with each new value of a ref, also when the server holds it.
            let mut metadata: Vec<Checksum> = needed
                .iter()
                .filter(|n| n.ty == ObjectType::Commit)
                .map(|n| n.checksum)
                .collect();
            metadata.extend(
                self.sources
                    .iter()
                    .map(|(c, _)| *c)
                    .filter(|c| !lacking.contains(c)),
            );
            let source = RepoSource::new(self.repo.clone(), RelatedRule::default());
            session
                .send(&source, &needed, &metadata, opts.compression)
                .await?;
        }

        // A tag expects an absent ref, also under `force`, so the push never
        // moves a tag. Each tag takes the one source commit.
        let tags = opts.tags.iter().map(|tag| RefUpdate {
            name: tag.clone(),
            expected: Expected::Absent,
            new: self.sources.first().map(|(c, _)| *c),
        });
        Ok(self
            .targets
            .iter()
            .map(|target| RefUpdate {
                name: target.dst.clone(),
                expected: match (opts.force, server.tip(&target.dst)) {
                    (true, _) => Expected::Any,
                    (false, Some(tip)) => Expected::Commit(tip),
                    (false, None) => Expected::Absent,
                },
                new: target.commit,
            })
            .chain(tags)
            .collect())
    }
}

/// Returns the history commits of a chain that a push offers.
///
/// With a `depth`, the push offers the whole `chain`. With no depth, it cuts
/// the chain at the tip `tip` of the destination, the tip excluded. If the
/// chain does not hold the tip, or the destination has no tip, the push
/// offers no history commit.
pub(super) fn offered_history(
    depth: Option<i32>,
    tip: Option<Checksum>,
    chain: &[Checksum],
) -> &[Checksum] {
    match (depth, tip) {
        (Some(_), _) => chain,
        (None, Some(tip)) => match chain.iter().position(|c| *c == tip) {
            Some(at) => &chain[..at],
            None => &[],
        },
        (None, None) => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    fn sources(bindings: &[Option<&str>]) -> Vec<(Checksum, Option<String>)> {
        bindings
            .iter()
            .enumerate()
            .map(|(i, b)| (csum(i as u8 + 1), b.map(str::to_owned)))
            .collect()
    }

    fn mismatch<T: std::fmt::Debug>(result: Result<T>) -> String {
        match result {
            Err(Error::Remote(crate::remote::Error::BindingMismatch(message))) => message,
            other => panic!("expected BindingMismatch, got {other:?}"),
        }
    }

    fn server(collection_id: Option<&str>, collection: Option<&str>) -> ServerInfo {
        ServerInfo {
            version: 1,
            mode: "archive".into(),
            collection_id: collection_id.map(str::to_owned),
            collection: collection.map(str::to_owned),
            max_frame: 1 << 20,
            max_have: 16_384,
            encodings: Vec::new(),
            parallel_uploads: 1,
            refs: Vec::new(),
        }
    }

    /// `Hello` names the requested collection, else the one binding of the
    /// source commits, else none.
    #[test]
    fn the_hello_collection_comes_from_the_request_or_the_bindings() {
        let os = Some("org.example.Os");
        assert_eq!(hello_collection(None, &sources(&[])).unwrap(), None);
        assert_eq!(
            hello_collection(None, &sources(&[None, None])).unwrap(),
            None
        );
        for bindings in [&[os][..], &[os, os], &[None, os], &[os, None]] {
            assert_eq!(
                hello_collection(None, &sources(bindings))
                    .unwrap()
                    .as_deref(),
                os,
                "{bindings:?}"
            );
            assert_eq!(
                hello_collection(os, &sources(bindings)).unwrap().as_deref(),
                os,
                "{bindings:?}"
            );
        }
        assert_eq!(
            hello_collection(os, &sources(&[None])).unwrap().as_deref(),
            os
        );
    }

    /// Two different bindings, and a binding that differs from the request,
    /// are `binding-mismatch`.
    #[test]
    fn disagreeing_bindings_are_refused() {
        let message = mismatch(hello_collection(
            None,
            &sources(&[Some("org.example.A"), None, Some("org.example.B")]),
        ));
        assert!(message.contains("'org.example.B'"), "{message}");
        assert!(message.contains("'org.example.A'"), "{message}");
        let message = mismatch(hello_collection(
            Some("org.example.B"),
            &sources(&[Some("org.example.A")]),
        ));
        assert!(message.contains("not 'org.example.B'"), "{message}");
    }

    /// A binding that fails the collection-id rule, or that is longer than
    /// 255 bytes, is `InvalidInput`. A binding of 255 bytes passes.
    #[test]
    fn a_binding_that_names_no_namespace_is_invalid_input() {
        let longest = format!("org.{}", "a".repeat(251));
        let over = format!("org.{}", "a".repeat(252));
        assert_eq!(collection_id_refusal(&longest), None);
        assert_eq!(
            hello_collection(None, &sources(&[Some(&longest)]))
                .unwrap()
                .as_deref(),
            Some(longest.as_str())
        );
        for (binding, needle) in [("no-dot", "'no-dot'"), (over.as_str(), "256 bytes")] {
            for requested in [None, Some(binding)] {
                match hello_collection(requested, &sources(&[None, Some(binding)])) {
                    Err(Error::Remote(crate::remote::Error::InvalidInput(message))) => {
                        assert!(message.contains(needle), "{message}");
                        assert!(message.contains(&csum(2).to_string()), "{message}");
                    }
                    other => panic!("{binding}: expected InvalidInput, got {other:?}"),
                }
            }
            assert!(
                collection_id_refusal(binding).is_some_and(|reason| reason.contains(needle)),
                "{binding}"
            );
        }
    }

    /// A bound commit needs the binding id of the namespace. An unbound
    /// commit needs the local refs.
    #[test]
    fn the_reported_namespace_must_agree_with_each_binding() {
        let os = Some("org.example.Os");
        let own = server(os, None);
        let mirror = server(None, os);
        let plain = server(None, None);
        check_namespace(&own, &sources(&[os, None])).unwrap();
        check_namespace(&mirror, &sources(&[os, os])).unwrap();
        check_namespace(&plain, &sources(&[None])).unwrap();
        let message = mismatch(check_namespace(&mirror, &sources(&[os, None])));
        assert!(message.contains("no collection binding"), "{message}");
        let message = mismatch(check_namespace(&plain, &sources(&[os])));
        assert!(message.contains("the local refs"), "{message}");
        mismatch(check_namespace(
            &server(Some("org.example.B"), None),
            &sources(&[os]),
        ));
    }

    /// The namespace of a push to a bucket repository: the local refs take
    /// the collection id of the bucket as their binding, and a collection
    /// namespace takes its own id.
    #[test]
    fn the_bindings_must_agree_with_the_namespace_of_the_push() {
        let a = Some("org.example.A");
        let b = Some("org.example.B");
        // The local refs of a bucket with no collection id.
        check_bindings(None, None, &sources(&[None])).unwrap();
        let message = mismatch(check_bindings(None, None, &sources(&[a])));
        assert!(
            message.contains("and the push writes the local refs"),
            "{message}"
        );
        // The local refs of a bucket with the collection id A.
        check_bindings(None, a, &sources(&[a, None])).unwrap();
        mismatch(check_bindings(None, a, &sources(&[b])));
        // The namespace of the collection B.
        check_bindings(b, b, &sources(&[b, b])).unwrap();
        let message = mismatch(check_bindings(b, b, &sources(&[None])));
        assert!(message.contains("no collection binding"), "{message}");
        assert!(
            message.contains("the collection 'org.example.B'"),
            "{message}"
        );
        mismatch(check_bindings(b, b, &sources(&[a])));
    }

    /// With no depth, the history ends before the tip of the destination.
    #[test]
    fn the_offered_history_ends_before_the_tip() {
        let chain = [csum(1), csum(2), csum(3)];
        assert_eq!(offered_history(Some(0), Some(csum(2)), &chain), chain);
        assert_eq!(
            offered_history(None, Some(csum(3)), &chain),
            [csum(1), csum(2)]
        );
        assert_eq!(offered_history(None, Some(csum(1)), &chain), []);
        assert!(offered_history(None, Some(csum(9)), &chain).is_empty());
        assert!(offered_history(None, None, &chain).is_empty());
    }

    /// A field of a push to a bucket repository is refused for each other
    /// push.
    #[test]
    fn the_bucket_fields_are_refused_for_a_session_push() {
        refuse_bucket_fields(&RepoPushOptions::default()).unwrap();
        for (opts, name) in [
            (
                RepoPushOptions {
                    break_lock: true,
                    ..RepoPushOptions::default()
                },
                "break_lock",
            ),
            (
                RepoPushOptions {
                    part_size: Some(5 << 20),
                    ..RepoPushOptions::default()
                },
                "part_size",
            ),
        ] {
            match refuse_bucket_fields(&opts) {
                Err(Error::Remote(crate::remote::Error::InvalidInput(message))) => {
                    assert_eq!(
                        message,
                        format!("{name} applies to a push to an s3:// address")
                    );
                }
                other => panic!("{name}: {other:?}"),
            }
        }
    }
}
