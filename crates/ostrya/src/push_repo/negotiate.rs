//! The push of commits from a repository: the checks before the session
//! opens, the commit walk, the two `Have` rounds, and the ref updates.

use std::collections::{HashMap, HashSet};

use futures_io::{AsyncRead, AsyncWrite};
use ostrya_core::{Checksum, Commit, CommitLink, ObjectName, ObjectType};

use super::refspec::PushTarget;
use super::source::RepoSource;
use super::{invalid, resolve_push_remote};
use crate::error::{Error, Result};
use crate::lock::{LockGuard, LockKind};
use crate::pull::DetachedMetadataFilter;
use crate::push::{
    Compression, ConnectOptions, Expected, PushOutcome, PushProgress, PushSession, RefUpdate,
    SessionOptions,
};
use crate::read::CommitState;
use crate::repo::Repo;

/// The options of [`Repo::push`] and [`Repo::push_over_stream`].
///
/// The struct is not `#[non_exhaustive]`. A caller can build it with
/// `..Default::default()`.
#[derive(Debug, Clone, Default)]
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
    /// The encoding of the content objects that the push sends.
    pub compression: Compression,
    /// The switch that updates each ref whatever its state on the server.
    ///
    /// If `true`, each ref update expects any state. The push also asks the
    /// server to allow an update that is not a fast-forward.
    pub force: bool,
    /// The connect options of [`Repo::push`].
    ///
    /// A field that is set here wins over the matching key of the remote
    /// section. [`Repo::push_over_stream`] does not read this field.
    pub connect: ConnectOptions,
    /// The filter of the detached metadata of each commit that the push sends.
    ///
    /// If the filter is unset, the push sends every key.
    pub detached_metadata_filter: DetachedMetadataFilter,
    /// A progress handle that receives the counters of the session.
    pub progress: Option<PushProgress>,
}

/// A commit of a chain, as the local repository holds it.
#[derive(Debug, Clone, Copy)]
enum Local {
    /// The repository holds the commit and does not mark it partial.
    Held(CommitLink),
    /// The repository marks the commit partial.
    Partial,
    /// The repository does not hold the commit.
    Absent,
}

/// Returns the parts of a parsed commit that the push reads.
fn link_of(commit: &Commit) -> CommitLink {
    CommitLink {
        parent: commit.parent,
        root_dirtree: commit.root_dirtree,
        root_dirmeta: commit.root_dirmeta,
    }
}

/// The local work of a push before the session opens.
struct Plan {
    repo: Repo,
    /// The repository lock, held shared until the push returns.
    _lock: LockGuard,
    /// The `DST` of each target, in the order of the refspecs: the refs of
    /// `Hello`.
    refs: Vec<String>,
    targets: Vec<PushTarget>,
    /// The source commits, each once, in the order of the targets, with the
    /// `ostree.collection-binding` of each.
    sources: Vec<(Checksum, Option<String>)>,
    /// The history commits of each target, from the parent of its source
    /// commit on, as the walk read them. A delete has none. The negotiation
    /// drops the chains when it has the commits to offer.
    chains: Vec<Vec<Checksum>>,
    /// Each commit the walk read. The negotiation drops the map after the
    /// tree walk.
    commits: HashMap<Checksum, Local>,
}

/// Methods that push commits to a remote.
impl Repo {
    /// Pushes the commits of `opts.refspecs` to `remote` and updates the
    /// server refs.
    ///
    /// The server updates all the refs in one transaction. `remote` is a
    /// configured remote name or an address. [`resolve_push_remote`] reads it
    /// with the config of this repository and `opts.connect`.
    ///
    /// The push makes the transport ready with [`PushSession::prepare`]. The
    /// prepare step refuses the connect options that do not apply. For an
    /// HTTP push, it reads the token file and the TLS files.
    ///
    /// These steps come before the checks and the commit walk of
    /// [`push_over_stream`](Repo::push_over_stream). If the push refuses the
    /// remote or its options, it takes no lock and reads no refspec. After
    /// these steps, the push runs the checks and the walk. It opens the
    /// session with [`PreparedSession::open`](crate::push::PreparedSession::open)
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
    /// # Errors
    ///
    /// - [`Error::Push`] with [`InvalidInput`](crate::push::Error::InvalidInput)
    ///   if `remote` names no configured remote, or if the remote has no push
    ///   address.
    /// - [`Error::Push`] with [`InvalidInput`](crate::push::Error::InvalidInput)
    ///   if an `https://` remote sets `tls-permissive=true`.
    /// - [`Error::Push`] with the error of
    ///   [`PushRemote::parse`](crate::push::PushRemote::parse) if the address
    ///   does not parse.
    /// - [`Error::Core`] if a key of the remote section holds a malformed
    ///   escape sequence, or if `tls-permissive` is not a boolean.
    /// - [`Error::Push`] with the error of [`PushSession::prepare`] if a
    ///   connect option does not apply, or if a token file or a TLS file
    ///   cannot be read. If the HTTP client cannot be built, the push also
    ///   gives this error.
    /// - [`Error::Push`] with the error of
    ///   [`PreparedSession::open`](crate::push::PreparedSession::open) if the
    ///   session does not open.
    /// - Each error of [`push_over_stream`](Repo::push_over_stream).
    pub async fn push(&self, remote: &str, mut opts: RepoPushOptions) -> Result<PushOutcome> {
        let connect = std::mem::take(&mut opts.connect);
        let (address, connect) = resolve_push_remote(Some(self.config()), remote, connect)?;
        let transport = PushSession::prepare(&address, connect).await?;
        let plan = self.plan_push(&opts).await?;
        let session = transport.open(&plan.refs, session_options(&opts)).await?;
        plan.run(session, &opts).await
    }

    /// Pushes the commits of `opts.refspecs` over a pair of byte streams.
    ///
    /// The server updates all the refs in one transaction. `input` comes from
    /// the server, and `output` goes to it. The call does not read
    /// `opts.connect`.
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
    /// # Negotiation
    ///
    /// The session opens with the `DST` of each refspec, in order. Then the
    /// push checks the `ostree.collection-binding` of each source commit. If
    /// the server has a collection id and a binding differs from it, the push
    /// sends no object. It ends the session with `Abort`.
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
    /// objects. The push sends the objects that the server lacks.
    ///
    /// The push also sends the detached metadata of each commit that it sends
    /// and of each source commit. The metadata passes
    /// [`detached_metadata_filter`](RepoPushOptions::detached_metadata_filter)
    /// first.
    ///
    /// # Ref updates
    ///
    /// Each ref update expects the state that the server reported when the
    /// session opened: the commit of the ref, or no ref. If `force` is
    /// `true`, each update expects any state. A refspec `:DST` is an update
    /// with no new commit. If all the refspecs are deletes, the push offers
    /// and sends no object.
    ///
    /// # Failure
    ///
    /// If the push fails after the session opened and before `Commit`, it
    /// ends the session and returns that failure. It writes `Abort` if the
    /// stream is still usable.
    ///
    /// # Errors
    ///
    /// - [`Error::Push`] with [`InvalidInput`](crate::push::Error::InvalidInput)
    ///   if `depth` is less than `-1`.
    /// - [`Error::Push`] with [`InvalidInput`](crate::push::Error::InvalidInput)
    ///   if `refspecs` is empty, or if a refspec is empty, is `:`, or names an
    ///   empty `DST`.
    /// - [`Error::Push`] with [`InvalidInput`](crate::push::Error::InvalidInput)
    ///   if a `SRC` with a `^` suffix or a checksum `SRC` has no `DST`, or if
    ///   two refspecs name the same `DST`.
    /// - [`Error::Push`] with [`InvalidInput`](crate::push::Error::InvalidInput)
    ///   if the local repository marks a source commit partial.
    /// - [`Error::InvalidRefspec`] with the `DST` if
    ///   [`validate_refspec`](crate::validate_refspec) refuses a `DST`, or if
    ///   a `DST` holds a `^`. A `DST` of 64 lowercase hex characters that takes
    ///   a commit also gives this error. A delete (`:DST`) of such a `DST`
    ///   passes.
    /// - [`Error::RefNotFound`], [`Error::AmbiguousRefspec`],
    ///   [`Error::NoParentCommit`], or another error of
    ///   [`resolve_rev`](Repo::resolve_rev) if a `SRC` does not resolve.
    /// - [`Error::Push`] with
    ///   [`BindingMismatch`](crate::push::Error::BindingMismatch) if the
    ///   `ostree.ref-binding` of a source commit is a list that does not hold
    ///   its `DST`. A commit with no binding, or with an empty list, passes.
    /// - [`Error::Push`] with
    ///   [`BindingMismatch`](crate::push::Error::BindingMismatch) if the
    ///   `ostree.collection-binding` of a source commit differs from the
    ///   collection id of the server.
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
    /// - [`Error::Push`] with the error of the server if the server refuses
    ///   the session, an object, or a ref update.
    /// - [`Error::Push`] with the error of the session if the stream or the
    ///   protocol fails. If the reply to `Commit` is lost, the error is
    ///   [`CommitOutcomeUnknown`](crate::push::Error::CommitOutcomeUnknown).
    /// - [`Error::Push`] with [`Source`](crate::push::Error::Source) if a
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
        let plan = self.plan_push(&opts).await?;
        let session =
            PushSession::over_stream(input, output, &plan.refs, session_options(&opts)).await?;
        plan.run(session, &opts).await
    }

    /// Runs the refusals and the commit walk of a push, under the repository
    /// lock held shared.
    async fn plan_push(&self, opts: &RepoPushOptions) -> Result<Plan> {
        if let Some(depth) = opts.depth
            && depth < -1
        {
            return Err(invalid(format!("depth {depth} is below -1")));
        }
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
        let sources = sources
            .into_iter()
            .map(|(checksum, commit)| (checksum, commit.collection_binding().map(str::to_owned)))
            .collect();

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
            refs: targets.iter().map(|t| t.dst.clone()).collect(),
            targets,
            chains,
            sources,
            commits,
        })
    }

    /// Returns the local state of the history commit `checksum`, read once.
    ///
    /// One blocking call reads the object and the partial marker, and parses
    /// the link of the commit.
    async fn history_commit(
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

/// Returns the options of the session of a push.
fn session_options(opts: &RepoPushOptions) -> SessionOptions {
    SessionOptions {
        progress: opts.progress.clone(),
        ..SessionOptions::default()
    }
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
    Err(Error::Push(crate::push::Error::BindingMismatch(format!(
        "commit {checksum} is bound to the refs {bindings:?}, which do not hold '{bare}'"
    ))))
}

impl Plan {
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
        if let Some(id) = &server.collection_id {
            for (checksum, bound) in &self.sources {
                if let Some(bound) = bound
                    && bound != id
                {
                    return Err(Error::Push(crate::push::Error::BindingMismatch(format!(
                        "commit {checksum} is bound to the collection '{bound}', not '{id}'"
                    ))));
                }
            }
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
            let history: &[Checksum] = match (opts.depth, server.tip(&target.dst)) {
                (Some(_), _) => chain,
                (None, Some(tip)) => match chain.iter().position(|c| *c == tip) {
                    Some(at) => &chain[..at],
                    None => &[],
                },
                (None, None) => &[],
            };
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
            let source = RepoSource::new(self.repo.clone(), opts.detached_metadata_filter.clone());
            session
                .send(&source, &needed, &metadata, opts.compression)
                .await?;
        }

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
            .collect())
    }
}
