//! The push of commits from a repository: the checks before the session
//! opens, the commit walk, the two `Have` rounds, and the ref updates.

use std::collections::{HashMap, HashSet};

use futures_io::{AsyncRead, AsyncWrite};
use ostrya_core::{
    Checksum, Commit, CommitLink, MAX_COLLECTION_ID_LEN, ObjectName, ObjectType, Ref,
};

use super::invalid;
use super::refspec::{PushTarget, in_collection};
use super::source::RepoSource;
use crate::error::{Error, Result};
use crate::lock::{LockGuard, LockKind};
use crate::read::CommitState;
use crate::related::{self, HeldDependency, RelatedField, RelatedRule};
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
    /// The refspecs, each `SRC[:DST]`.
    ///
    /// `SRC` is a revision of the local repository, as
    /// [`resolve_rev`](Repo::resolve_rev) reads it. `DST` is the ref of the
    /// server that takes the commit of `SRC`: a local ref `NAME`, or a ref
    /// `@ID:NAME` of the collection `ID`. `:DST` deletes the ref `DST` of the
    /// server. If `SRC` is a ref with no `^` suffix, `DST` defaults to the
    /// text of `SRC`, so `@ID:NAME` sends `@ID:NAME`.
    ///
    /// `DST` is the last ref of the refspec. If the `:`-separated field
    /// before the last field starts with `@`, `DST` is `@ID:NAME`, the last
    /// two fields. Else `DST` is the last field. If `DST` is the whole
    /// refspec, the refspec has a `SRC` alone. Else `SRC` is the text before
    /// the `:` that comes before `DST`. So `R:main:dst` sends the remote ref
    /// `R:main` to `dst`, `main:@X:a` sends `main` to `@X:a`, `@X:a:b` sends
    /// `@X:a` to `b`, and `:@X:a` deletes `@X:a`. A refspec with no `@` splits
    /// at its last `:`.
    ///
    /// A `SRC` with a `^` suffix needs a `DST`. A `SRC` that resolves as a
    /// full or an abbreviated checksum also needs a `DST`.
    ///
    /// A push names no remote ref of the server. `DST` holds no `^`. A
    /// revision reads 64 lowercase hex characters as a commit checksum, so a
    /// local `DST` that takes a commit is not 64 lowercase hex characters.
    /// This rule also applies to the name part of a `DST` `@OWN:NAME`, where
    /// `OWN` is the collection id of the server, because the server keeps
    /// that ref at `refs/heads/NAME`. A delete can name such a `DST`.
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
    ///
    /// A push sends each dependency at depth 0, whatever this value is. It
    /// sends the dependencies of each commit that it offers, the history
    /// commits included. [`Repo::push_over_stream`] states the rules in
    /// "Dependencies".
    pub depth: Option<i32>,
    /// The collection id that each plain `DST` and each plain tag takes.
    ///
    /// With `Some(ID)`, a plain `DST` or tag `NAME` is the ref `@ID:NAME`. A
    /// `DST` or tag `@ID:NAME` stays. A `DST` or tag `@Y:NAME`, with `Y`
    /// other than `ID`, refuses the push before the session opens. A `DST`
    /// that defaults to a `SRC` `@Y:NAME` is such a `DST`.
    ///
    /// The bindings of the source commits select no namespace. Each `DST`
    /// and each tag names its own namespace, and one push can write the
    /// local refs and the refs of more than one collection. The server
    /// writes the refs of its own collection id as its local refs, under
    /// `refs/heads/`, and the refs of each other collection under
    /// `refs/mirrors/ID/`. A push to a bucket repository takes the `config`
    /// of the bucket in the role of the server.
    pub collection: Option<String>,
    /// The tags that the push creates at the source commit.
    ///
    /// A tag is a local ref `NAME` or a ref `@ID:NAME`, and
    /// [`collection`](RepoPushOptions::collection) applies to it. Each tag is
    /// one more ref update that expects an absent ref, also with
    /// [`force`](RepoPushOptions::force). The refspecs that are not deletes
    /// must give one source commit, and its `ostree.ref-binding` must hold
    /// the name part of each tag, unless
    /// [`disable_verify_bindings`](RepoPushOptions::disable_verify_bindings)
    /// is set. A tag that exists on the server gets
    /// [`RefMismatch`](crate::remote::Error::RefMismatch) after `HelloReply`,
    /// and the push sends no `Have` and no object.
    pub tags: Vec<Ref>,
    /// The switch that skips the checks of `ostree.ref-binding` on the
    /// client.
    ///
    /// If `true`, the push does not check that the `ostree.ref-binding` of
    /// the commit of each `DST` and each tag holds the name part of the ref.
    /// A server then applies its own rule: a client group without the key
    /// `disable-verify-bindings` refuses such a commit. A bucket repository
    /// has no server check, so the switch alone skips the check of a push to
    /// a bucket. The switch skips no check of `ostree.collection-binding`.
    /// A ref that a push writes with the switch fails a pull that checks the
    /// bindings.
    pub disable_verify_bindings: bool,
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
    /// The bound of the requests in flight of one call on a bucket
    /// repository, for tests. `None` takes the
    /// [`max_outstanding`](crate::fetch::FetcherOptions::max_outstanding) of
    /// the HTTP options of the endpoint.
    ///
    /// A push over ssh or HTTP refuses a value.
    #[doc(hidden)]
    pub bucket_max_outstanding: Option<usize>,
}

/// Refuses the fields of `opts` that apply to a push to a bucket repository
/// alone.
fn refuse_bucket_fields(opts: &RepoPushOptions) -> Result<()> {
    let set = [
        ("break_lock", opts.break_lock),
        ("part_size", opts.part_size.is_some()),
        (
            "bucket_max_outstanding",
            opts.bucket_max_outstanding.is_some(),
        ),
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

/// Returns the parts of a parsed commit that the push and the export read.
pub(super) fn link_of(commit: &Commit) -> CommitLink {
    CommitLink {
        parent: commit.parent,
        root_dirtree: commit.root_dirtree,
        root_dirmeta: commit.root_dirmeta,
    }
}

/// The commits that the walk of a push or the load of an export read, and
/// the dependencies that the push or the export resolved.
#[derive(Default)]
pub(super) struct Commits {
    /// The local state of each commit that the walk or the load read, and of
    /// each dependency that the call read.
    pub(super) local: HashMap<Checksum, Local>,
    /// The entries of field 2 of each commit that `local` holds as
    /// [`Local::Held`], as names and checksums in the stored order, or the
    /// [`Error::InvalidRelated`] of the first defective entry. The caller
    /// takes the result at its own point, so it sets the order of the errors.
    /// A held commit with no entry here has an empty field 2.
    fields: HashMap<Checksum, Result<Vec<(String, Checksum)>>>,
    /// The dependencies that the call resolved.
    known: HashSet<Checksum>,
}

impl Commits {
    /// Records the field 2 `field` of the held commit `commit`. An empty
    /// field 2 gets no entry in `fields`.
    pub(super) fn record(&mut self, commit: Checksum, field: Result<Vec<(String, Checksum)>>) {
        if !field.as_ref().is_ok_and(Vec::is_empty) {
            self.fields.insert(commit, field);
        }
    }

    /// Refuses a defective field 2 entry of each commit of `commits`, in
    /// order. A commit that the repository does not hold, or marks partial,
    /// has no field to check.
    pub(super) fn check_fields<'a>(
        &mut self,
        commits: impl IntoIterator<Item = &'a Checksum>,
    ) -> Result<()> {
        for commit in commits {
            if self.fields.get(commit).is_some_and(Result::is_err) {
                // The caller stops at this error, so the result moves out.
                return self
                    .fields
                    .remove(commit)
                    .expect("the field is recorded")
                    .map(drop);
            }
        }
        Ok(())
    }

    /// Returns the dependencies of the commit `commit`, in the stored order.
    ///
    /// The push and the export call it for a commit whose dependencies they
    /// resolved. A commit with no entry in `fields` has an empty field 2 and
    /// gives none.
    pub(super) fn dependencies_of(
        &self,
        commit: &Checksum,
    ) -> impl Iterator<Item = Checksum> + use<'_> {
        self.fields
            .get(commit)
            .into_iter()
            .flat_map(|field| field.iter().flatten())
            .map(|(_, dependency)| *dependency)
    }

    /// Resolves the dependencies of each commit of `commits`, in order, and
    /// refuses a dependency that the push or the export cannot send.
    ///
    /// The repository holds each commit of `commits`, and its field 2 passed
    /// the format check. The call records each dependency with the commit and
    /// the entry name that first named it, and skips a dependency that it
    /// resolved before. A dependency that `local` holds needs no read. One
    /// trip to the blocking pool reads each other dependency: its partial
    /// marker, then its commit object, if its field 2 is empty, and the link
    /// of the commit. The call reads no commit object of a dependency with a
    /// partial marker. No object bytes leave the pool. The call reads no
    /// parent of a dependency. Each dependency that passes is [`Local::Held`]
    /// in `local`, so the walk of the trees finds it.
    ///
    /// # Errors
    ///
    /// For the first refused dependency, in the order of naming:
    ///
    /// - [`Error::ObjectNotFound`] if the repository does not hold the
    ///   dependency.
    /// - [`Error::InvalidRelated`] if the repository marks the dependency
    ///   partial, or if the field 2 of the dependency is not empty. The error
    ///   names the commit that first named the dependency.
    /// - [`Error::Io`] or [`Error::Core`] if the read of a dependency with no
    ///   partial marker fails, or if the tuple frame, field 2, or the parent
    ///   or root checksums of its commit object do not decode. The call
    ///   decodes no other part of the commit object.
    /// - [`Error::Io`] if the lstat of the partial marker of a dependency
    ///   fails, or if the lstat of the commit object of a dependency with a
    ///   partial marker fails.
    pub(super) async fn check_dependencies<'a>(
        &mut self,
        repo: &Repo,
        commits: impl IntoIterator<Item = &'a Checksum>,
    ) -> Result<()> {
        // Each new dependency, the commit that first named it, and the name of
        // that entry.
        let mut named: Vec<(Checksum, Checksum, &str)> = Vec::new();
        for commit in commits {
            let entries = match self.fields.get(commit) {
                Some(Ok(entries)) => entries,
                Some(Err(_)) => {
                    unreachable!("the field 2 of a resolved commit passed the check")
                }
                None => continue,
            };
            for (name, dependency) in entries {
                if self.known.insert(*dependency) {
                    named.push((*dependency, *commit, name));
                }
            }
        }
        let unread: Vec<Checksum> = named
            .iter()
            .map(|(dependency, _, _)| *dependency)
            .filter(|dependency| !self.local.contains_key(dependency))
            .collect();
        let mut loaded: HashMap<_, Result<HeldDependency<CommitLink>>> = if unread.is_empty() {
            HashMap::new()
        } else {
            let repo = repo.clone();
            ostrya_rt::unblock(move || {
                unread
                    .into_iter()
                    .map(|key| {
                        let state = related::held_dependency_blocking(&repo, None, &key, |b| {
                            Ok(Commit::parse_link(b)?)
                        });
                        (key, state)
                    })
                    .collect()
            })
            .await
        };
        for (dependency, naming, name) in named {
            let nested = match loaded.remove(&dependency) {
                Some(result) => {
                    let (local, nested) = match result? {
                        HeldDependency::Absent => (Local::Absent, false),
                        HeldDependency::Partial => (Local::Partial, false),
                        HeldDependency::Complete { nested, value } => (Local::Held(value), nested),
                    };
                    self.local.insert(dependency, local);
                    nested
                }
                // A commit that `local` holds: `fields` holds its field 2 if
                // that field is not empty, valid or not.
                None => self.fields.contains_key(&dependency),
            };
            match self.local[&dependency] {
                Local::Absent => {
                    return Err(Error::ObjectNotFound {
                        checksum: dependency,
                        ty: ObjectType::Commit,
                    });
                }
                Local::Partial => {
                    return Err(related::partial_dependency(naming, name, &dependency));
                }
                Local::Held(_) if nested => {
                    return Err(related::nested_dependency(naming, name, &dependency));
                }
                Local::Held(_) => {}
            }
        }
        Ok(())
    }
}

/// The local work of a push before the session opens.
pub(super) struct Plan {
    pub(super) repo: Repo,
    /// The repository lock, held shared until the push returns.
    pub(super) _lock: LockGuard,
    /// The text of the `DST` of each target, in the order of the refspecs,
    /// then of each tag: the refs of `Hello`.
    pub(super) refs: Vec<String>,
    pub(super) targets: Vec<PushTarget>,
    /// The tags, after [`RepoPushOptions::collection`] applied.
    pub(super) tags: Vec<Ref>,
    /// The source commits, each once, in the order of the targets, with the
    /// `ostree.collection-binding` of each.
    pub(super) sources: Vec<(Checksum, Option<String>)>,
    /// The history commits of each target, from the parent of its source
    /// commit on, as the walk read them. A delete has none. The negotiation
    /// drops the chains when it has the commits to offer.
    pub(super) chains: Vec<Vec<Checksum>>,
    /// Each commit that the walk read, with its field 2, and each dependency
    /// that the push read. The negotiation drops them after the tree walk.
    pub(super) commits: Commits,
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
    /// and does the rest of the work of `push_over_stream`. The push sends
    /// the dependencies of each commit that it offers, as "Dependencies" of
    /// [`push_over_stream`](Repo::push_over_stream) states.
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
    /// The push checks the format of field 2 of each commit that the walk
    /// reads, also of a history commit that it does not offer.
    ///
    /// # Namespace
    ///
    /// Each `DST` and each tag names its own namespace of the server: a local
    /// ref `NAME`, or a ref `@ID:NAME` of the collection `ID`. The server takes
    /// the refs of its own collection id as its local refs, so `@OWN:NAME`
    /// and `NAME` name one ref. The binding of a commit selects no namespace.
    ///
    /// Before the session opens, the push reads the `ostree.collection-binding`
    /// of each source commit. It refuses a binding that names no collection,
    /// and a commit bound to `Y` for a `DST` or a tag `@X:NAME`, with `Y`
    /// other than `X`, before it writes a byte.
    ///
    /// `HelloReply` reports the collection id of the server. Then each
    /// update that writes a commit needs the binding of its namespace: a
    /// bound commit on a local ref must name the collection id of the
    /// server, and a commit on a ref `@X:NAME` of another collection must be
    /// bound to `X`. A commit with no binding goes to the local refs alone.
    /// Two `DST` refs or tags that name one ref of the server, `NAME` and
    /// `@OWN:NAME`, also fail here. An ostrya server refuses such a `Hello`
    /// before `HelloReply`. A `DST` or a tag `@OWN:NAME` that takes a commit
    /// fails here if `NAME` is 64 lowercase hex characters, as a local `DST`
    /// of that form fails before the session opens. On a failure, the push
    /// sends no object and ends the session with `Abort`.
    ///
    /// The `ostree.ref-binding` of the commit of each `DST` must hold the
    /// name part of the `DST`: `stable` for `@X:stable`. A commit with no
    /// `ostree.ref-binding` passes, and an empty list fails. The commit of the
    /// tags must hold the name part of each tag, so a commit with no
    /// `ostree.ref-binding` fails for a tag.
    /// [`disable_verify_bindings`](RepoPushOptions::disable_verify_bindings)
    /// skips these two checks of the client. The push runs them before it
    /// writes a byte.
    ///
    /// # Negotiation
    ///
    /// The session opens with the text of the `DST` of each refspec, in
    /// order, then of each tag.
    ///
    /// If `depth` is `None`, the push cuts each chain at the server tip of
    /// its `DST`, the tip excluded. If the chain does not hold the tip, the
    /// push keeps the source commit alone. It also keeps the source commit
    /// alone if the server does not hold the `DST`. The server then decides
    /// if the update is a fast-forward.
    ///
    /// The negotiation offers the commits first, in the first `Have` round:
    /// each source commit and its history, then the dependencies of each
    /// offered commit. Then the push walks the tree of each source commit,
    /// also when the server holds that commit. It also walks the tree of
    /// each history commit and each dependency that the server lacks. It
    /// does not walk the tree of a history commit or a dependency that the
    /// server holds.
    ///
    /// If the local repository lacks a dirtree or a dirmeta, the push ends
    /// the session with `Abort`. The second `Have` round offers the tree
    /// objects. The push sends the objects that the server lacks.
    ///
    /// The push also sends the detached metadata of each commit that it sends
    /// and of each source commit. It sends the stored `.commitmeta` bytes with
    /// no parse, so the server refuses a `.commitmeta` that is not an `a{sv}`
    /// dict.
    ///
    /// # Dependencies
    ///
    /// Field 2 of a commit names the dependencies of the commit.
    /// [`read_commit_related`](Repo::read_commit_related) reads them. The push
    /// sends the dependencies of each commit that it offers: each source
    /// commit, and each history commit of the offer.
    ///
    /// - The push sends each dependency at depth 0, so a dependency entry
    ///   adds no parent to the push. The push offers a dependency one time,
    ///   also if several commits name it.
    /// - The push sets no ref for a dependency.
    /// - A dependency is a commit of the offer for each other rule. For a
    ///   dependency that the server lacks, the push sends the commit object,
    ///   the objects of its tree, and its detached metadata.
    /// - The push makes no ref-binding check and no collection-binding check
    ///   on a dependency.
    /// - The push does not send a build source: a commit that the detached
    ///   metadata key `ostrya.related` names. The key goes with the detached
    ///   metadata of its commit.
    ///
    /// These cases refuse the push:
    ///
    /// - An entry of field 2 of a commit of the walk has an empty name or a
    ///   checksum that is not 32 bytes.
    /// - The local repository does not hold a dependency, or marks it
    ///   partial. This is also true for a parent that ends a chain, if a
    ///   commit of the push names that parent as a dependency.
    /// - A dependency names dependencies of its own: its own field 2 is not
    ///   empty, also if that field 2 holds a defective entry.
    ///
    /// If `depth` is `Some`, the push finds each case before it writes a
    /// byte. If `depth` is `None`, the push finds a defective entry and each
    /// defect of a dependency of a source commit before it writes a byte. It
    /// finds a defect of a dependency of a history commit after the cut at
    /// the server tip, which comes after `HelloReply`. It then ends the
    /// session with `Abort` and sends no object. The push reads no dependency
    /// of a history commit that it does not offer.
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
    /// - [`Error::InvalidRefspec`] with the text of the tag if a tag fails
    ///   [`Ref::validate`], is a remote ref, or is a local ref of 64 lowercase
    ///   hex characters.
    /// - [`Error::Remote`] with [`InvalidInput`](crate::remote::Error::InvalidInput)
    ///   if a `DST` or a tag names a collection other than `collection`.
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
    /// - [`Error::InvalidRefspec`] with the `DST` if a `DST` is not `NAME` or
    ///   `@ID:NAME` under [`Ref::validate`], or if a `DST` holds a `^`. A
    ///   local `DST` of 64 lowercase hex characters that takes a commit also
    ///   gives this error. A delete (`:DST`) of such a `DST` passes.
    /// - [`Error::InvalidRefspec`] with the text of the ref if a `DST` or a
    ///   tag `@OWN:NAME` takes a commit and `NAME` is 64 lowercase hex
    ///   characters, where `OWN` is the collection id of the server, after
    ///   `HelloReply`.
    /// - [`Error::RefNotFound`], [`Error::AmbiguousRefspec`],
    ///   [`Error::NoParentCommit`], or another error of
    ///   [`resolve_rev`](Repo::resolve_rev) if a `SRC` does not resolve.
    /// - [`Error::Remote`] with
    ///   [`BindingMismatch`](crate::remote::Error::BindingMismatch) if the
    ///   `ostree.ref-binding` of a source commit is a list that does not hold
    ///   the name part of its `DST`, an empty list included, or if the
    ///   `ostree.ref-binding` of the source commit of a tag does not hold the
    ///   name part of the tag, as "Namespace" states. A commit with no ref
    ///   binding fails for a tag. `disable_verify_bindings` skips these
    ///   checks.
    /// - [`Error::Remote`] with
    ///   [`BindingMismatch`](crate::remote::Error::BindingMismatch) if the
    ///   `ostree.collection-binding` of a source commit does not agree with
    ///   the namespace of its `DST` or of a tag, as "Namespace" states.
    /// - [`Error::Remote`] with [`InvalidInput`](crate::remote::Error::InvalidInput)
    ///   if two `DST` refs or tags name one ref of the server, after
    ///   `HelloReply`.
    /// - [`Error::ObjectNotFound`] if the local repository lacks a source
    ///   commit, or a dirtree or a dirmeta of a tree that the push walks.
    /// - [`Error::InvalidRelated`] if an entry of field 2 of a commit of the
    ///   walk has an empty name or a checksum that is not 32 bytes, or if a
    ///   dependency of an offered commit is partial in the local repository
    ///   or names dependencies of its own. [`Error::ObjectNotFound`] if the
    ///   local repository lacks such a dependency. "Dependencies" states when
    ///   the push finds each case.
    /// - [`Error::LockTimeout`] if the wait for the lock passes
    ///   `[core] lock-timeout-secs`.
    /// - [`Error::InvalidFormat`] if `[core] lock-timeout-secs` is less than
    ///   `-1`.
    /// - [`Error::Core`] if `[core] locking` is not a boolean or
    ///   `[core] lock-timeout-secs` is not an integer, or if a source commit
    ///   or a dirtree object does not parse. For the commit object of a
    ///   parent or of a dependency, the push decodes the tuple frame, the
    ///   parent and root checksums, and field 2 alone, and gives this error
    ///   if one of them does not decode.
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
        let collection = opts.collection.as_deref();
        if let Some(reason) = collection.and_then(collection_id_refusal) {
            return Err(invalid(reason));
        }
        let tags = check_tag_names(&opts.tags, collection)?;
        let lock = self.lock_repo(LockKind::Shared).await?;
        let targets = self.push_targets(&opts.refspecs, collection).await?;

        let mut sources: Vec<(Checksum, Commit)> = Vec::new();
        let mut commits = Commits::default();
        for target in &targets {
            let Some(checksum) = target.commit else {
                continue;
            };
            let position = match sources.iter().position(|(c, _)| *c == checksum) {
                Some(position) => position,
                None => {
                    let (mut commit, state) = self.load_commit(&checksum).await?;
                    if state == CommitState::Partial {
                        return Err(invalid(format!(
                            "commit {checksum} for '{}' is marked partial in the local \
                             repository",
                            target.dst
                        )));
                    }
                    commits
                        .local
                        .insert(checksum, Local::Held(link_of(&commit)));
                    let related = std::mem::take(&mut commit.related);
                    commits.record(checksum, related::checked_dependencies(&checksum, related));
                    sources.push((checksum, commit));
                    sources.len() - 1
                }
            };
            if !opts.disable_verify_bindings {
                check_ref_binding(&checksum, &sources[position].1, &target.dst)?;
            }
        }
        check_tags(&tags, &targets, &sources, opts.disable_verify_bindings)?;
        let sources: Vec<(Checksum, Option<String>)> = sources
            .into_iter()
            .map(|(checksum, commit)| (checksum, commit.collection_binding().map(str::to_owned)))
            .collect();
        check_binding_ids(&sources)?;
        // The checks that need the collection id of the server come after
        // `HelloReply`. A commit bound to `Y` fails a ref `@X:NAME` on each
        // server.
        for (name, commit) in updates(&targets, &tags, &sources) {
            check_named_collection(&commit, binding(&sources, &commit), name, false)?;
        }

        // With no depth the chain runs to the root, and the cut at the
        // server tip comes after `HelloReply`.
        let depth = opts.depth.unwrap_or(-1);
        let mut chains = Vec::with_capacity(targets.len());
        for target in &targets {
            let mut chain = Vec::new();
            if let Some(source) = target.commit {
                let mut next = match commits.local[&source] {
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

        // The format of field 2 of each commit that the walk read, then the
        // dependencies. With no depth, the cut at the server tip comes after
        // `HelloReply`, so the negotiation resolves the dependencies of the
        // history that it offers.
        let walked = sources
            .iter()
            .map(|(checksum, _)| checksum)
            .chain(chains.iter().flatten());
        commits.check_fields(walked.clone())?;
        match opts.depth {
            Some(_) => commits.check_dependencies(self, walked).await?,
            None => {
                let sources = sources.iter().map(|(checksum, _)| checksum);
                commits.check_dependencies(self, sources).await?;
            }
        }

        Ok(Plan {
            repo: self.clone(),
            _lock: lock,
            refs: targets
                .iter()
                .map(|t| &t.dst)
                .chain(&tags)
                .map(Ref::to_string)
                .collect(),
            targets,
            tags,
            chains,
            sources,
            commits,
        })
    }

    /// Returns the local state of the history commit `checksum`, read once.
    ///
    /// One blocking call reads the object and the partial marker, parses the
    /// link of the commit, and checks the format of its field 2. The result
    /// of the check goes into `commits` for a later point of the push.
    pub(super) async fn history_commit(
        &self,
        checksum: &Checksum,
        commits: &mut Commits,
    ) -> Result<Local> {
        if let Some(local) = commits.local.get(checksum) {
            return Ok(*local);
        }
        let repo = self.clone();
        let key = *checksum;
        let (local, field) = ostrya_rt::unblock(move || {
            let bytes = match repo.load_object_bytes_blocking(ObjectType::Commit, &key) {
                Ok(bytes) => bytes,
                Err(Error::ObjectNotFound { .. }) => return Ok((Local::Absent, None)),
                Err(e) => return Err(e),
            };
            Ok(match repo.commit_state_blocking(&key)? {
                CommitState::Normal => {
                    let field = related::parse_dependencies(&bytes).and_then(|entries| {
                        related::checked_entries(RelatedField::Dependencies, Some(key), entries)
                    });
                    (Local::Held(Commit::parse_link(&bytes)?), Some(field))
                }
                CommitState::Partial => (Local::Partial, None),
            })
        })
        .await?;
        commits.local.insert(*checksum, local);
        if let Some(field) = field {
            commits.record(*checksum, field);
        }
        Ok(local)
    }
}

/// Refuses a tag that a push cannot create, and returns the tags after the
/// collection `collection` of the push applied, in order.
///
/// A tag passes [`Ref::validate`], is not a remote ref, and is not a local
/// ref of 64 lowercase hex characters. Each refusal of the form is
/// [`Error::InvalidRefspec`] with the text of the tag. Then
/// [`in_collection`] applies to each tag. A tag named twice after that is
/// [`InvalidInput`](crate::remote::Error::InvalidInput).
pub(super) fn check_tag_names(tags: &[Ref], collection: Option<&str>) -> Result<Vec<Ref>> {
    let mut checked = Vec::with_capacity(tags.len());
    for tag in tags {
        tag.validate()?;
        match tag {
            Ref::Remote { .. } => return Err(Error::InvalidRefspec(tag.to_string())),
            Ref::Local { name } if ostrya_core::is_checksum_shaped(name) => {
                return Err(Error::InvalidRefspec(tag.to_string()));
            }
            _ => {}
        }
        checked.push(in_collection(tag.clone(), collection, "tag")?);
    }
    let mut seen = HashSet::new();
    for tag in &checked {
        if !seen.insert(tag) {
            return Err(invalid(format!("the tag '{tag}' is named twice")));
        }
    }
    Ok(checked)
}

/// Refuses tags that the targets and the source commits of a push cannot
/// carry.
///
/// A tag is not the `DST` of a refspec. With one tag or more, the refspecs
/// that are not deletes give exactly one source commit. Unless
/// `skip_ref_binding` is set, the `ostree.ref-binding` of that commit holds
/// the name part of each tag, so a commit with no ref binding fails.
fn check_tags(
    tags: &[Ref],
    targets: &[PushTarget],
    sources: &[(Checksum, Commit)],
    skip_ref_binding: bool,
) -> Result<()> {
    if tags.is_empty() {
        return Ok(());
    }
    let dsts: HashSet<&Ref> = targets.iter().map(|t| &t.dst).collect();
    if let Some(tag) = tags.iter().find(|tag| dsts.contains(tag)) {
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
    if skip_ref_binding {
        return Ok(());
    }
    let bindings = commit.ref_bindings();
    for tag in tags {
        if !bindings.contains(&tag.name()) {
            return Err(binding_mismatch(format!(
                "commit {checksum} is bound to the refs {bindings:?}, which do not hold the \
                 tag '{}'",
                tag.name()
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

/// Refuses a source commit whose `ostree.collection-binding` names no
/// namespace: an id that [`collection_id_refusal`] refuses. The error is
/// [`InvalidInput`](crate::remote::Error::InvalidInput).
///
/// No ref of a server takes such a commit, so the push refuses it before
/// the session opens.
fn check_binding_ids(sources: &[(Checksum, Option<String>)]) -> Result<()> {
    for (checksum, binding) in sources {
        if let Some(reason) = binding.as_deref().and_then(collection_id_refusal) {
            return Err(invalid(format!(
                "commit {checksum} has a collection binding that a push cannot name: {reason}"
            )));
        }
    }
    Ok(())
}

/// Returns the ref and the new commit of each update of a push that writes
/// a commit: each target that is not a delete, in order, then each tag with
/// the one source commit.
fn updates<'a>(
    targets: &'a [PushTarget],
    tags: &'a [Ref],
    sources: &'a [(Checksum, Option<String>)],
) -> impl Iterator<Item = (&'a Ref, Checksum)> {
    let written = targets
        .iter()
        .filter_map(|t| t.commit.map(|commit| (&t.dst, commit)));
    let tagged = sources
        .first()
        .into_iter()
        .flat_map(move |(commit, _)| tags.iter().map(move |tag| (tag, *commit)));
    written.chain(tagged)
}

/// Returns the `ostree.collection-binding` of the source commit `commit`.
pub(super) fn binding<'a>(
    sources: &'a [(Checksum, Option<String>)],
    commit: &Checksum,
) -> Option<&'a str> {
    sources
        .iter()
        .find(|(c, _)| c == commit)
        .and_then(|(_, binding)| binding.as_deref())
}

/// Refuses the commit `checksum`, bound to the collection `bound`, for a
/// ref `@X:NAME` whose `X` is not `bound`.
///
/// The check needs no collection id of the server: a commit bound to `Y`
/// fails the ref `@X:NAME` on each server, with `Y` other than `X`. A commit
/// with no binding fails too if `refuse_unbound` is set. Such a commit
/// passes the ref `@X:NAME` of a server whose collection id is `X`, so a
/// caller that does not know the collection id of the server and sends the
/// commit with no other check sets it. A ref of another form passes. Each
/// refusal is [`BindingMismatch`](crate::remote::Error::BindingMismatch).
pub(super) fn check_named_collection(
    checksum: &Checksum,
    bound: Option<&str>,
    name: &Ref,
    refuse_unbound: bool,
) -> Result<()> {
    let Ref::Collection { id, .. } = name else {
        return Ok(());
    };
    match bound {
        Some(bound) if bound != id => Err(binding_mismatch(format!(
            "commit {checksum} is bound to the collection '{bound}', not '{id}' of ref '{name}'"
        ))),
        None if refuse_unbound => Err(unbound_in_collection(checksum, name)),
        _ => Ok(()),
    }
}

/// Refuses the commit `checksum`, bound to the collection `bound`, for the
/// ref `name` of a server or a bucket repository whose collection id is
/// `own`.
///
/// A local ref `NAME`, and a ref `@OWN:NAME`, is a local ref of the server,
/// and a bound commit must name `own`. So a bound commit fails each local
/// ref of a server with no collection id. A ref `@X:NAME` of another
/// collection takes a commit bound to `X` alone, so a commit with no
/// binding fails it. A commit with no binding passes a local ref. A remote
/// ref `REMOTE:NAME` takes `own` as a local ref does, and passes with no
/// check if `own` is `None`. Each refusal is
/// [`BindingMismatch`](crate::remote::Error::BindingMismatch).
pub(super) fn check_collection_binding(
    checksum: &Checksum,
    bound: Option<&str>,
    name: &Ref,
    own: Option<&str>,
) -> Result<()> {
    if matches!(name, Ref::Remote { .. }) && own.is_none() {
        return Ok(());
    }
    let collection = match name {
        Ref::Collection { id, .. } if Some(id.as_str()) != own => Some(id.as_str()),
        _ => None,
    };
    match (bound, collection.or(own)) {
        (Some(bound), Some(id)) if bound == id => Ok(()),
        (Some(bound), Some(id)) => Err(binding_mismatch(format!(
            "commit {checksum} is bound to the collection '{bound}', not '{id}' of ref '{name}'"
        ))),
        (Some(bound), None) => Err(binding_mismatch(format!(
            "commit {checksum} is bound to the collection '{bound}', and ref '{name}' is a \
             local ref of a repository with no collection id"
        ))),
        (None, _) if collection.is_some() => Err(unbound_in_collection(checksum, name)),
        (None, _) => Ok(()),
    }
}

/// Returns the error for a commit with no collection binding on the ref
/// `name` of a collection.
fn unbound_in_collection(checksum: &Checksum, name: &Ref) -> Error {
    binding_mismatch(format!(
        "commit {checksum} has no collection binding, which a ref of the collection of ref \
         '{name}' needs"
    ))
}

/// Runs the checks of a push after `HelloReply`, against the collection id
/// of `server`.
///
/// Two refs of `targets` and `tags` that name one ref of the server, `NAME`
/// and `@OWN:NAME`, are
/// [`InvalidInput`](crate::remote::Error::InvalidInput). An ostrya server
/// refuses such a `Hello` before `HelloReply`. Then
/// [`check_written_shape`] runs for the refs that take a commit, and
/// [`check_collection_binding`] runs for each update that writes a commit.
fn check_namespaces(
    server: &ServerInfo,
    targets: &[PushTarget],
    tags: &[Ref],
    sources: &[(Checksum, Option<String>)],
) -> Result<()> {
    let own = server.collection_id.as_deref();
    check_distinct(own, targets.iter().map(|t| &t.dst).chain(tags))?;
    check_written_shape(own, updates(targets, tags, sources).map(|(name, _)| name))?;
    for (name, commit) in updates(targets, tags, sources) {
        check_collection_binding(&commit, binding(sources, &commit), name, own)?;
    }
    Ok(())
}

/// Refuses two refs of `names` that name one ref of a server whose
/// collection id is `own`: `NAME` and `@OWN:NAME`.
///
/// # Errors
///
/// [`Error::Remote`] with
/// [`InvalidInput`](crate::remote::Error::InvalidInput) for the first ref
/// that names the ref of an earlier ref.
pub(super) fn check_distinct<'a>(
    own: Option<&str>,
    names: impl IntoIterator<Item = &'a Ref>,
) -> Result<()> {
    let mut seen: HashMap<Ref, &Ref> = HashMap::new();
    for name in names {
        if let Some(first) = seen.insert(name.clone().canonical(own), name) {
            return Err(invalid(format!(
                "the refs '{first}' and '{name}' name one ref of the server"
            )));
        }
    }
    Ok(())
}

/// Refuses a ref of `written` that is a local ref of 64 lowercase hex
/// characters on a server or a bucket repository whose collection id is
/// `own`: a local ref `NAME`, or a ref `@OWN:NAME`.
///
/// A revision reads such a name as a commit checksum, so a push writes no
/// commit to it. The caller gives the refs that take a commit alone, so a
/// delete passes.
///
/// # Errors
///
/// [`Error::InvalidRefspec`] with the text of the first such ref.
pub(super) fn check_written_shape<'a>(
    own: Option<&str>,
    written: impl IntoIterator<Item = &'a Ref>,
) -> Result<()> {
    for r in written {
        let name = match r {
            Ref::Local { name } => name,
            Ref::Collection { id, name } if Some(id.as_str()) == own => name,
            _ => continue,
        };
        if ostrya_core::is_checksum_shaped(name) {
            return Err(Error::InvalidRefspec(r.to_string()));
        }
    }
    Ok(())
}

fn binding_mismatch(message: String) -> Error {
    Error::Remote(crate::remote::Error::BindingMismatch(message))
}

/// Refuses a commit whose `ostree.ref-binding` does not hold the name part
/// of `dst`.
///
/// The check compares the name of `dst` without the `@ID:` part of a
/// collection ref or the `REMOTE:` part of a remote ref: `stable` for
/// `@X:stable`. A commit with no `ostree.ref-binding` passes. A commit with
/// an empty list fails, because the list holds no name.
pub(super) fn check_ref_binding(checksum: &Checksum, commit: &Commit, dst: &Ref) -> Result<()> {
    if commit.metadata_value("ostree.ref-binding").is_none() {
        return Ok(());
    }
    let bindings = commit.ref_bindings();
    let name = dst.name();
    if bindings.contains(&name) {
        return Ok(());
    }
    Err(binding_mismatch(format!(
        "commit {checksum} is bound to the refs {bindings:?}, which do not hold '{name}'"
    )))
}

impl Plan {
    /// Returns the options of the session of the push.
    fn session_options(&self, opts: &RepoPushOptions) -> SessionOptions {
        SessionOptions {
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
        check_namespaces(server, &self.targets, &self.tags, &self.sources)?;
        // A tag expects an absent ref, so a tag that the server holds fails
        // before any `Have`. The server refuses it at `Commit` too.
        if let Some((tag, current)) = self.tags.iter().find_map(|tag| {
            let tag = tag.to_string();
            server.tip(&tag).map(|tip| (tag, tip))
        }) {
            return Err(Error::Remote(crate::remote::Error::RefMismatch {
                message: format!("ref '{tag}' is at {current}"),
                name: tag,
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
            let tip = server.tip(&target.dst.to_string());
            let history = offered_history(opts.depth, tip, chain);
            for commit in std::iter::once(&source).chain(history) {
                if offered.insert(*commit) {
                    names.push(ObjectName::new(*commit, ObjectType::Commit));
                }
            }
        }
        drop(chains);

        // Then the dependencies of each offered commit, each once. With no
        // depth, the push resolves the dependencies of the offered history
        // here, before the first upload.
        if opts.depth.is_none() {
            let offer = names.iter().map(|name| &name.checksum);
            self.commits.check_dependencies(&self.repo, offer).await?;
        }
        let resolved = names.len();
        for at in 0..resolved {
            let commit = names[at].checksum;
            for dependency in self.commits.dependencies_of(&commit) {
                if offered.insert(dependency) {
                    names.push(ObjectName::new(dependency, ObjectType::Commit));
                }
            }
        }

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
                let Local::Held(link) = commits.local[commit] else {
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
            let source = RepoSource::new(self.repo.clone(), RelatedRule::default());
            session
                .send(&source, &needed, &metadata, opts.compression)
                .await?;
        }

        // A tag expects an absent ref, also under `force`, so the push never
        // moves a tag. Each tag takes the one source commit.
        let tags = self.tags.iter().map(|tag| RefUpdate {
            name: tag.to_string(),
            expected: Expected::Absent,
            new: self.sources.first().map(|(c, _)| *c),
        });
        Ok(self
            .targets
            .iter()
            .map(|target| {
                let name = target.dst.to_string();
                let expected = match (opts.force, server.tip(&name)) {
                    (true, _) => Expected::Any,
                    (false, Some(tip)) => Expected::Commit(tip),
                    (false, None) => Expected::Absent,
                };
                RefUpdate {
                    name,
                    expected,
                    new: target.commit,
                }
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

    fn server(collection_id: Option<&str>) -> ServerInfo {
        ServerInfo {
            version: 1,
            mode: "archive".into(),
            collection_id: collection_id.map(str::to_owned),
            max_frame: 1 << 20,
            max_have: 16_384,
            encodings: Vec::new(),
            parallel_uploads: 1,
            refs: Vec::new(),
        }
    }

    fn invalid_input<T: std::fmt::Debug>(result: Result<T>) -> String {
        match result {
            Err(Error::Remote(crate::remote::Error::InvalidInput(message))) => message,
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    fn r(text: &str) -> Ref {
        text.parse().unwrap()
    }

    /// A binding that fails the collection-id rule, or that is longer than
    /// 255 bytes, is `InvalidInput`. A binding of 255 bytes passes.
    #[test]
    fn a_binding_that_names_no_namespace_is_invalid_input() {
        let longest = format!("org.{}", "a".repeat(251));
        let over = format!("org.{}", "a".repeat(252));
        assert_eq!(collection_id_refusal(&longest), None);
        check_binding_ids(&sources(&[None, Some(&longest)])).unwrap();
        for (binding, needle) in [("no-dot", "'no-dot'"), (over.as_str(), "256 bytes")] {
            let message = invalid_input(check_binding_ids(&sources(&[None, Some(binding)])));
            assert!(message.contains(needle), "{message}");
            assert!(message.contains(&csum(2).to_string()), "{message}");
            assert!(
                collection_id_refusal(binding).is_some_and(|reason| reason.contains(needle)),
                "{binding}"
            );
        }
    }

    /// Before the session, a commit bound to `Y` fails a ref `@X:NAME`. A
    /// commit with no binding fails it only on request. Other refs pass.
    #[test]
    fn a_ref_of_a_collection_needs_a_commit_of_that_collection() {
        let c = csum(1);
        let x = r("@org.example.X:a");
        check_named_collection(&c, Some("org.example.X"), &x, true).unwrap();
        check_named_collection(&c, None, &x, false).unwrap();
        let message = mismatch(check_named_collection(&c, None, &x, true));
        assert!(message.contains("no collection binding"), "{message}");
        assert!(message.contains("'@org.example.X:a'"), "{message}");
        let message = mismatch(check_named_collection(&c, Some("org.example.Y"), &x, false));
        assert!(
            message.contains("'org.example.Y', not 'org.example.X'"),
            "{message}"
        );
        for name in [r("main"), r("o:main")] {
            for bound in [None, Some("org.example.Y")] {
                check_named_collection(&c, bound, &name, true).unwrap();
            }
        }
    }

    /// The collection binding of each ref against the collection id of the
    /// server: a local ref, and a ref of the own id, take the own id, a ref
    /// of another collection takes its id, and a remote ref takes the own
    /// id, with no check if the server has no collection id.
    #[test]
    fn each_ref_takes_the_binding_of_its_namespace() {
        let c = csum(1);
        let x = Some("org.example.X");
        let y = Some("org.example.Y");
        let check = |bound, name: &str, own| check_collection_binding(&c, bound, &r(name), own);
        // A local ref.
        check(None, "main", None).unwrap();
        check(None, "main", x).unwrap();
        check(x, "main", x).unwrap();
        let message = mismatch(check(x, "main", None));
        assert!(message.contains("no collection id"), "{message}");
        let message = mismatch(check(y, "main", x));
        assert!(message.contains("not 'org.example.X'"), "{message}");
        // A ref of the own id is a local ref.
        check(None, "@org.example.X:a", x).unwrap();
        check(x, "@org.example.X:a", x).unwrap();
        mismatch(check(y, "@org.example.X:a", x));
        // A ref of another collection.
        check(x, "@org.example.X:a", None).unwrap();
        check(x, "@org.example.X:a", y).unwrap();
        let message = mismatch(check(None, "@org.example.X:a", y));
        assert!(message.contains("no collection binding"), "{message}");
        mismatch(check(None, "@org.example.X:a", None));
        mismatch(check(y, "@org.example.X:a", y));
        // A remote ref takes the own id, and has no check with no own id.
        check(x, "o:main", None).unwrap();
        check(x, "o:main", x).unwrap();
        let message = mismatch(check(y, "o:main", x));
        assert!(message.contains("not 'org.example.X'"), "{message}");
    }

    /// After `HelloReply`, two texts of one ref are refused, and each update
    /// gets the check of its namespace.
    #[test]
    fn the_checks_after_hello_reply_use_the_collection_id_of_the_server() {
        let target = |dst: &str, commit| PushTarget {
            dst: r(dst),
            commit,
        };
        let x = Some("org.example.X");
        let os = sources(&[x]);
        let targets = [
            target("main", Some(csum(1))),
            target("@org.example.X:b", Some(csum(1))),
        ];
        check_namespaces(&server(x), &targets, &[r("t")], &os).unwrap();
        let message = invalid_input(check_namespaces(
            &server(x),
            &targets,
            &[r("@org.example.X:main")],
            &os,
        ));
        assert!(
            message.contains("'main' and '@org.example.X:main' name one ref"),
            "{message}"
        );
        // With no collection id on the server, both refs are distinct, and
        // the bound commit fails the local ref.
        let message = mismatch(check_namespaces(&server(None), &targets, &[], &os));
        assert!(message.contains("ref 'main'"), "{message}");
        // A delete gets no binding check.
        check_namespaces(&server(None), &[target("main", None)], &[], &[]).unwrap();
        // A tag takes the one source commit.
        let unbound = sources(&[None]);
        let message = mismatch(check_namespaces(
            &server(x),
            &[target("main", Some(csum(1)))],
            &[r("@org.example.Y:t")],
            &unbound,
        ));
        assert!(message.contains("'@org.example.Y:t'"), "{message}");
    }

    /// After `HelloReply`, a ref `@OWN:NAME` that takes a commit is the
    /// local ref `NAME` of the server, so a `NAME` of 64 lowercase hex
    /// characters is refused, as a `DST` and as a tag. A delete passes, and
    /// so does such a ref of another collection.
    #[test]
    fn a_written_ref_of_the_own_id_and_64_hex_is_refused() {
        let own = format!("@org.example.X:{}", "ab".repeat(32));
        let target = |dst: &str, commit| PushTarget {
            dst: r(dst),
            commit,
        };
        let x = Some("org.example.X");
        let os = sources(&[x]);
        let refused = |result: Result<()>| match result {
            Err(Error::InvalidRefspec(text)) => assert_eq!(text, own),
            other => panic!("expected InvalidRefspec, got {other:?}"),
        };
        let written = [target(&own, Some(csum(1)))];
        refused(check_namespaces(&server(x), &written, &[], &os));
        let main = [target("main", Some(csum(1)))];
        refused(check_namespaces(&server(x), &main, &[r(&own)], &os));
        // A delete writes no commit.
        check_namespaces(&server(x), &[target(&own, None)], &[], &[]).unwrap();
        // With another collection id on the server, or with none, the ref is
        // no local ref of the server.
        check_namespaces(&server(None), &written, &[], &os).unwrap();
        check_namespaces(&server(Some("org.example.Y")), &written, &[], &os).unwrap();
    }

    /// A tag is a local ref or a collection ref. The collection of the push
    /// applies before the check of a repeated tag.
    #[test]
    fn a_tag_takes_the_collection_of_the_push() {
        let hex = "ab".repeat(32);
        let x = Some("org.example.X");
        assert_eq!(
            check_tag_names(&[r("a"), r("@org.example.X:b")], x).unwrap(),
            [r("@org.example.X:a"), r("@org.example.X:b")]
        );
        assert_eq!(
            check_tag_names(&[r("a"), r("@org.example.Y:b")], None).unwrap(),
            [r("a"), r("@org.example.Y:b")]
        );
        for tag in [
            Ref::remote("o", "a"),
            Ref::local(hex.as_str()),
            Ref::local("a b"),
        ] {
            match check_tag_names(std::slice::from_ref(&tag), None) {
                Err(Error::InvalidRefspec(text)) => assert_eq!(text, tag.to_string()),
                other => panic!("{tag}: {other:?}"),
            }
        }
        let message = invalid_input(check_tag_names(&[r("@org.example.Y:b")], x));
        assert!(
            message.contains("names the collection 'org.example.Y'"),
            "{message}"
        );
        let message = invalid_input(check_tag_names(&[r("a"), r("@org.example.X:a")], x));
        assert!(
            message.contains("'@org.example.X:a' is named twice"),
            "{message}"
        );
        // A collection ref of 64 lowercase hex characters passes before
        // `HelloReply`, because its id can name another collection than the
        // collection id of the server.
        check_tag_names(&[Ref::collection("org.example.X", hex.as_str())], None).unwrap();
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
            (
                RepoPushOptions {
                    bucket_max_outstanding: Some(2),
                    ..RepoPushOptions::default()
                },
                "bucket_max_outstanding",
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
