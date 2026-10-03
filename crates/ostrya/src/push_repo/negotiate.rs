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

/// What [`Repo::push`] and [`Repo::push_over_stream`] push, and how.
///
/// The struct carries no `#[non_exhaustive]`: build it with
/// `..Default::default()`.
#[derive(Debug, Clone, Default)]
pub struct RepoPushOptions {
    /// The refspecs, each `SRC[:DST]`, split at the last `:`. `SRC` is a
    /// revision of the local repository and `DST` the ref of the server that
    /// takes its commit. `:DST` deletes the ref `DST` of the server. `DST`
    /// defaults to `SRC` when `SRC` is a ref with no `^` suffix.
    pub refspecs: Vec<String>,
    /// The parent commits the push reads for each source commit. `None`
    /// sends the parent chain back to the server tip of the ref, the tip
    /// excluded. `Some(0)` reads each source commit alone, `Some(n)` reads
    /// `n` parents more, and `Some(-1)` reads the whole chain that the local
    /// repository holds. A value below `-1` is refused.
    pub depth: Option<i32>,
    /// The encoding of the content objects.
    pub compression: Compression,
    /// Update each ref whatever its state on the server, and ask the server
    /// to allow an update that is not a fast-forward.
    pub force: bool,
    /// How [`Repo::push`] reaches the remote. A field set here wins over the
    /// keys of the remote section. [`Repo::push_over_stream`] does not read
    /// it.
    pub connect: ConnectOptions,
    /// The filter the detached metadata of each commit passes before the
    /// push sends it. Unset, the push sends every key.
    pub detached_metadata_filter: DetachedMetadataFilter,
    /// A handle the session also counts its progress into.
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

/// The parts of a parsed commit that the push reads.
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

impl Repo {
    /// Push the commits that `opts.refspecs` name to `remote`, and update the
    /// refs of the server in one transaction.
    ///
    /// `remote` is a configured remote name or an address, and
    /// [`resolve_push_remote`] reads it with the config of this repository
    /// and `opts.connect`. The push then makes the transport ready with
    /// [`PushSession::prepare`], which refuses the connect options that do
    /// not apply and reads the token file and the TLS files of an HTTP
    /// push. These checks come before the checks and the commit walk of
    /// [`push_over_stream`](Repo::push_over_stream), so a refusal of the
    /// remote or of its options takes no lock and reads no refspec. The push
    /// then runs those checks and the walk, opens the session with
    /// [`PreparedSession::open`](crate::push::PreparedSession::open), and
    /// runs the rest of the work of `push_over_stream`.
    ///
    /// Under the tokio backend, the call must run within a runtime that has
    /// the IO driver and the time driver enabled. These are `enable_io` and
    /// `enable_time` of the runtime builder, or `enable_all`. The ssh child
    /// process and its pipes, and the connections of an HTTP session, need
    /// the IO driver, and the time limits of the session need the time
    /// driver.
    pub async fn push(&self, remote: &str, mut opts: RepoPushOptions) -> Result<PushOutcome> {
        let connect = std::mem::take(&mut opts.connect);
        let (address, connect) = resolve_push_remote(Some(self.config()), remote, connect)?;
        let transport = PushSession::prepare(&address, connect).await?;
        let plan = self.plan_push(&opts).await?;
        let session = transport.open(&plan.refs, session_options(&opts)).await?;
        plan.run(session, &opts).await
    }

    /// Push the commits that `opts.refspecs` name over a pair of byte
    /// streams, and update the refs of the server in one transaction.
    ///
    /// `input` comes from the server, and `output` goes to it. The call does
    /// not read `opts.connect`.
    ///
    /// The push holds the lock of the local repository shared for the whole
    /// call. So a prune of the local repository waits for the push. Before it
    /// writes a byte, the push refuses:
    ///
    /// - a `depth` below `-1`, as [`Error::Push`] with
    ///   [`InvalidInput`](crate::push::Error::InvalidInput);
    /// - each refspec that the reader of refspecs refuses, as [`Error::Push`]
    ///   with [`InvalidInput`](crate::push::Error::InvalidInput) or as the
    ///   error of the resolution of `SRC`;
    /// - a source commit that the local repository marks partial, as
    ///   [`Error::Push`] with
    ///   [`InvalidInput`](crate::push::Error::InvalidInput);
    /// - a source commit whose `ostree.ref-binding` is a list that does not
    ///   hold its `DST`, as [`Error::Push`] with
    ///   [`BindingMismatch`](crate::push::Error::BindingMismatch). A commit
    ///   with no binding, or with an empty list, passes.
    ///
    /// The push then reads commit objects alone. With `depth` `None`, it
    /// reads the parent chain of each source commit to the root. With
    /// `Some(n)`, it reads `n` parents, and with `Some(-1)` the whole chain.
    /// Each chain stops at the first commit that the local repository does
    /// not hold. It also stops at the first commit that the local repository
    /// marks partial. With `Some(n)`, the chain stops before that commit.
    /// With `None`, that commit is the last commit of the chain, and the push
    /// does not walk its tree.
    ///
    /// The session opens with the `DST` of each refspec, in order. The push
    /// then checks the `ostree.collection-binding` of each source commit.
    /// When the server has a collection id and a binding differs from it, the
    /// push sends no object. It ends the session with `Abort` and fails with
    /// [`Error::Push`] with
    /// [`BindingMismatch`](crate::push::Error::BindingMismatch).
    ///
    /// With `depth` `None`, each chain is cut at the server tip of its `DST`,
    /// the tip excluded. A chain that does not hold the tip keeps the source
    /// commit alone. So does a chain whose `DST` the server does not hold.
    /// The server then decides whether the update is a fast-forward.
    ///
    /// The negotiation runs commits first. The first `Have` round offers the
    /// commits. The push then walks the tree of each source commit, also
    /// when the server holds that commit. It walks the tree of each history
    /// commit that the server lacks, and not the tree of a history commit
    /// that the server holds. A dirtree or a dirmeta that the local
    /// repository lacks ends the session with `Abort`. The push then fails
    /// with [`Error::ObjectNotFound`]. The second `Have` round offers the
    /// tree objects. The push sends the objects that the server lacks. It
    /// also sends the detached metadata of each commit that it sends and of
    /// each source commit, after
    /// [`detached_metadata_filter`](RepoPushOptions::detached_metadata_filter).
    ///
    /// Each ref update expects the state that the server reported when the
    /// session opened: the commit of the ref, or no ref. With `force`, each
    /// update expects any state. A refspec `:DST` is an update with no new
    /// commit. A push whose refspecs are all deletes offers and sends no
    /// object.
    ///
    /// A failure of the push after the session opened and before `Commit`
    /// ends the session and returns that failure. The push writes `Abort`
    /// when the stream is still usable. A refusal of the server is
    /// [`Error::Push`] with the error of the server.
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

    /// The refusals and the commit walk of a push, under the repository lock
    /// held shared.
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

    /// The history commit `checksum`, read once. One blocking call reads
    /// the object and the partial marker, and parses the link of the commit.
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

/// The options of the session of a push.
fn session_options(opts: &RepoPushOptions) -> SessionOptions {
    SessionOptions {
        progress: opts.progress.clone(),
        ..SessionOptions::default()
    }
}

/// Refuse a commit whose `ostree.ref-binding` is a list that does not hold
/// `dst`. A commit with no binding, or with an empty list, passes, as on the
/// server.
fn check_ref_binding(checksum: &Checksum, commit: &Commit, dst: &str) -> Result<()> {
    let bindings = commit.ref_bindings();
    if bindings.is_empty() || bindings.contains(&dst) {
        return Ok(());
    }
    Err(Error::Push(crate::push::Error::BindingMismatch(format!(
        "commit {checksum} is bound to the refs {bindings:?}, which do not hold '{dst}'"
    ))))
}

impl Plan {
    /// Run the push over `session`. A failure before `Commit` ends the
    /// session, with `Abort` when the stream is still usable.
    async fn run(mut self, session: PushSession, opts: &RepoPushOptions) -> Result<PushOutcome> {
        match self.negotiate(&session, opts).await {
            Ok(updates) => Ok(session.commit(&updates, opts.force).await?),
            Err(e) => {
                let _ = session.abort().await;
                Err(e)
            }
        }
    }

    /// The checks after `HelloReply`, the two `Have` rounds, and the upload.
    /// The result is the ref updates of `Commit`.
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

        // The commits to offer: each source commit and its chain, cut at the
        // server tip when no depth is set.
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
