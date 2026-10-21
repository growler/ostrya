//! The pull of the refs of one collection from the remotes that serve it.
//!
//! [`Repo::pull_collection`] is the entry point and states the rules. The
//! pull runs in three parts:
//!
//! 1. The checks of the options, and the endpoint, the trust, and the
//!    transport of each remote. A failure stops the pull before its first
//!    request.
//! 2. The probe of each remote, in the given order: the commit and the
//!    timestamp of each ref, from the ref listing or from the summary. The
//!    pull skips a remote that fails.
//! 3. The selection of a remote for each ref, and then one pull from each
//!    selected remote, in the given order, through the engine of
//!    [`Repo::pull`], over the session of its probe.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ostrya_core::{Checksum, RefSelector, Value, is_collection_id};

use crate::endpoint::{EndpointOverrides, resolve_pull};
use crate::error::{Error, Result};
use crate::fetch::{Fetcher, Priority};
use crate::refs::{MAX_COLLECTION_ID_LEN, check_ref_path};
use crate::remote::proto::{MAX_REF_ENTRY_LEN, MAX_REF_ENTRY_PARTS, MAX_REF_PATTERNS};
use crate::remote::{Endpoint, PullSession, StreamSession, StreamSessionOptions};
use crate::repo::Repo;
use crate::send::write_escaped;
use crate::summary::{
    COLLECTION_ID_KEY, COMMIT_TIMESTAMP_KEY, SUMMARY_FILE, Summary, SummaryRef,
    collection_map_refs, parse_ref_list,
};
use crate::verify::PullTrust;

use super::http::{MAX_ROOT_FILE, Pinned, Wanted, connect, session_options};
use super::source::RemoteSource;
use super::subpath::Subpaths;
use super::verify::Verification;
use super::{
    PullFlags, PullOptions, PullStats, PullVerify, RefPlace, check_depth, refuse_remote_collection,
};

/// The path of the ref listing under the base URL of a remote.
const LISTING_PATH: &str = "_ostrya/refs/v1";

/// The longest request target of a ref listing that the HTTP client sends:
/// 16 KiB, from the path of the listing to the end of the query.
///
/// [`PullSession::fetch_refs`] refuses a longer target before it sends the
/// request.
const MAX_LISTING_TARGET: usize = 16 * 1024;

/// The most bytes that the pairs of the names of one HTTP listing request
/// fill, each pair with the `&` before it ([`name_cost`]).
///
/// The target is the path, `?`, and the pairs with no `&` before the first
/// pair. So the target fits when the sum of the costs is at most this value.
const LISTING_BUDGET: usize = MAX_LISTING_TARGET - LISTING_PATH.len();

/// The options of [`Repo::pull_collection`].
///
/// The struct is `#[non_exhaustive]`, so a caller starts from
/// [`CollectionPullOptions::default`] and sets the fields.
#[derive(Default)]
#[non_exhaustive]
pub struct CollectionPullOptions {
    /// The options of the pull from each selected remote.
    ///
    /// [`refs`](PullOptions::refs) names the refs of the collection. An empty
    /// list takes each ref of the collection that a remote lists.
    /// [`Repo::pull_collection`] states the fields that it refuses, and the
    /// fields that apply to each remote.
    pub pull: PullOptions,
    /// The callback for each [`CollectionPullEvent`] of the pull, or `None`.
    ///
    /// The pull calls it on its own task, so the callback must return soon.
    /// A command writes the [`Display`](fmt::Display) text of the event as a
    /// warning on standard error. The default is `None`, which drops each
    /// event.
    pub on_event: Option<Box<dyn FnMut(CollectionPullEvent) + Send>>,
}

/// The debug text shows a callback that is set as `<callback>`.
impl fmt::Debug for CollectionPullOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CollectionPullOptions")
            .field("pull", &self.pull)
            .field("on_event", &self.on_event.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

/// An event of [`Repo::pull_collection`], which
/// [`CollectionPullOptions::on_event`] receives.
///
/// [`Display`](fmt::Display) writes one line. It writes each ASCII control
/// character as an escape sequence, for example `\n`, so the line holds no
/// line break.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CollectionPullEvent {
    /// The pull skipped a remote, because the remote failed to tell the
    /// commits of the refs.
    ///
    /// The pull selects no ref from this remote. The causes are a failed
    /// connection or request, a listing or a summary that does not parse, a
    /// listed ref with no valid timestamp, and a summary that the policy of
    /// the remote refuses.
    #[non_exhaustive]
    RemoteSkipped {
        /// The name of the remote.
        remote: String,
        /// The text of the failure.
        message: String,
    },
}

impl fmt::Display for CollectionPullEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CollectionPullEvent::RemoteSkipped { remote, message } => {
                f.write_str("remote ")?;
                write_escaped(f, remote)?;
                f.write_str(" skipped: ")?;
                write_escaped(f, message)
            }
        }
    }
}

/// The result of [`Repo::pull_collection`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CollectionPullStats {
    /// Each pulled ref, with the remote that the pull selected for it.
    ///
    /// The order is the order of [`refs`](PullOptions::refs), or the
    /// byte-wise order of the names for a pull of each ref of the
    /// collection.
    pub refs: Vec<CollectionPullRef>,
    /// The sum of the statistics of the pulls from the selected remotes.
    ///
    /// [`elapsed`](PullStats::elapsed) is the run time of the whole call.
    pub stats: PullStats,
}

/// One ref of a collection pull, and the remote that the pull selected for
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CollectionPullRef {
    /// The ref name.
    pub name: String,
    /// The name of the selected remote.
    pub remote: String,
    /// The commit that the selected remote listed for the ref.
    pub commit: Checksum,
    /// The commit timestamp that the selected remote listed for the ref, in
    /// seconds since the Unix epoch.
    pub timestamp: u64,
}

/// A remote of a collection pull: its name, its endpoint, and its trust.
struct Candidate<'a> {
    name: &'a str,
    transport: Transport,
    trust: PullTrust,
}

/// How the pull reaches a remote.
enum Transport {
    /// The fetcher of an HTTP remote. The pull builds it before its first
    /// request.
    Http(Fetcher),
    /// An ssh endpoint and the options of its session. The pull checks the
    /// command line of its ssh client before its first request.
    Ssh(Box<Endpoint>, StreamSessionOptions),
}

impl Transport {
    /// Returns the transport of `endpoint`, with the request limit
    /// `max_outstanding` of the caller.
    ///
    /// For an HTTP endpoint, the call builds the fetcher. For an ssh
    /// endpoint, it checks the command line of the ssh client. It sends no
    /// request and starts no ssh client.
    async fn new(endpoint: Endpoint, max_outstanding: Option<usize>) -> Result<Transport> {
        let (endpoint, stream) = session_options(endpoint, max_outstanding);
        Ok(match endpoint {
            Endpoint::Http(_) => {
                let PullSession::Http(fetcher) = connect(endpoint, stream).await? else {
                    unreachable!("an HTTP endpoint opens an HTTP session");
                };
                Transport::Http(fetcher)
            }
            Endpoint::Ssh {
                ref address,
                ref options,
            } => {
                StreamSession::check_command_line(address, options)?;
                Transport::Ssh(Box::new(endpoint), stream)
            }
            _ => {
                return Err(crate::endpoint::neither_ssh_nor_http(
                    "a pull of collection refs",
                ));
            }
        })
    }

    /// Opens a session to the remote.
    async fn open(&self) -> Result<PullSession> {
        match self {
            Transport::Http(fetcher) => Ok(PullSession::Http(fetcher.clone())),
            Transport::Ssh(endpoint, stream) => {
                connect(Endpoint::clone(endpoint), stream.clone()).await
            }
        }
    }
}

/// One ref that a remote lists for the collection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listed {
    name: String,
    commit: Checksum,
    timestamp: u64,
}

/// What the probe of one remote gives.
struct Probed {
    /// The refs of the collection that the remote lists.
    listed: Vec<Listed>,
    /// The `summary` of the remote, if the probe read the refs from it.
    summary: Option<Arc<Vec<u8>>>,
    /// The open session to the remote, for the pull from it.
    session: PullSession,
}

/// The remote that the pull selected for one ref.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Selected {
    /// The position of the remote in the list of candidates.
    remote: usize,
    listed: Listed,
}

/// Methods that pull the refs of a collection.
impl Repo {
    /// Pulls refs of the collection `collection_id` from the remotes
    /// `remotes`.
    ///
    /// Each name in `remotes` is a `[remote "<name>"]` section of the config
    /// of this repository. These are the candidates: remotes that serve the
    /// collection. The call does not read the `collection-id` key of a
    /// remote. The `ostrya` command gives the remotes whose `collection-id`
    /// is `collection_id`, in the order of the config. The order of
    /// `remotes` is the order of the probe, of the ties, and of the pulls. A
    /// name that occurs again in `remotes` adds nothing.
    ///
    /// [`refs`](PullOptions::refs) of [`CollectionPullOptions::pull`] names
    /// the refs. An empty list takes each ref of the collection that a
    /// remote lists. A name that occurs again adds nothing.
    ///
    /// # Address and trust
    ///
    /// Before its first request, the pull resolves the endpoint of each
    /// remote with [`resolve_pull`], with
    /// [`overrides`](PullOptions::overrides), and the trust of each remote
    /// with [`PullTrust::from_remote`], with [`verify`](PullOptions::verify).
    /// It also builds the fetcher of each HTTP remote, which sends no
    /// request, and checks the command line of the ssh client of each ssh
    /// remote, which starts no ssh client. So an error in the config of one
    /// remote, for example a TLS file that does not parse or an empty
    /// `send-command`, stops the pull before the first request. Each pull
    /// from a remote applies the keys of that remote: `gpg-verify`,
    /// `sign-verify`, and their key sources.
    ///
    /// # Probe
    ///
    /// The pull asks each remote in turn for the commit of each ref. It
    /// opens one session to each remote: an ssh client over ssh, or the
    /// fetcher and its connections over HTTP. The pull from a selected
    /// remote uses the same session. The pull ends the session of each other
    /// remote after the selection, and an error of that end has no effect.
    ///
    /// - If the policy of the remote covers the summary
    ///   (`gpg-verify-summary`, `sign-verify-summary`), the pull reads the
    ///   `summary` and the `summary.sig` of the remote, and verifies the
    ///   summary before it reads the refs from it. The ref listing has no
    ///   signature, so the pull does not read it.
    /// - Otherwise, the pull reads the ref listing of the remote, through
    ///   [`PullSession::fetch_refs`](crate::remote::PullSession::fetch_refs).
    ///   The first selector holds the names, and the second selector holds
    ///   each name under the collection id, `ID/NAME`. A request holds at
    ///   most [`MAX_REF_PATTERNS`] entries, and over HTTP a request target of
    ///   at most 16 KiB. So a long list of names takes more than one request.
    /// - A pull of each ref first sends the first selector `!**`, which
    ///   selects no ref, and the second selector `ID/**`. If the listing
    ///   states `collection_id` as the collection id of the remote, a second
    ///   request sends an empty first selector, which selects each ref, and
    ///   no second selector.
    /// - If the remote serves no ref listing, the pull reads the `summary`
    ///   of the remote. An HTTP remote serves no listing when it answers the
    ///   request with a status from 400 to 499. A remote with no listing and
    ///   no summary lists no ref.
    ///
    /// If the `ostree.summary.collection-id` of the listing or of the
    /// summary is `collection_id`, the refs of the collection are in the ref
    /// list, field 0. Otherwise, they are in `ostree.summary.collection-map`
    /// under `collection_id`, and the pull ignores field 0. The commit
    /// timestamp of a ref is its `ostree.commit.timestamp`.
    ///
    /// A remote that fails the probe is skipped:
    /// [`on_event`](CollectionPullOptions::on_event) gets a
    /// [`RemoteSkipped`](CollectionPullEvent::RemoteSkipped) event, and the
    /// pull asks the next remote. The causes are a connection or a request
    /// that fails, for example a listing request that gets a status from 500
    /// to 599, a listing or a summary that does not parse, a summary that the
    /// policy refuses, a listed name that the ref-name rule refuses, and a
    /// listed ref with no `ostree.commit.timestamp` of type `t`.
    ///
    /// # Selection
    ///
    /// For each ref, the pull selects the remote that lists the newest
    /// commit, by the listed timestamp. If two remotes list the same
    /// timestamp, the earlier remote in `remotes` wins.
    ///
    /// # Pull
    ///
    /// The pull then takes all objects of each ref from the selected remote,
    /// as [`Repo::pull`] does, at the commit that the probe listed. It reads
    /// no ref of the remote again. If the probe read the refs from the
    /// summary, the pull uses those bytes and does not read the summary
    /// again. The remotes pull in the order of `remotes`, each with its own
    /// transaction. A remote with no selected ref is not asked again.
    ///
    /// So a failure of a later remote leaves the objects and the refs of the
    /// earlier remotes in place. A failure of a selected remote stops the
    /// whole pull. The pull does not take the ref from the next remote.
    ///
    /// For each pulled commit, the pull makes these checks, and a commit that
    /// fails one fails the pull with [`Error::Pull`]:
    ///
    /// - The `ostree.collection-binding` of the commit must be
    ///   `collection_id`. A commit with no collection binding fails.
    /// - The `ostree.ref-binding` of the commit must hold the ref. A commit
    ///   with no ref binding passes, as in each other pull.
    /// - The timestamp of the commit must be the timestamp that the remote
    ///   listed for the ref.
    ///
    /// # Refs
    ///
    /// The pull writes each ref as the collection ref
    /// `refs/mirrors/<collection_id>/<name>`. If the `[core] collection-id`
    /// of this repository is `collection_id`, it writes the local ref
    /// `refs/heads/<name>`. It writes no ref under `refs/remotes/`. Delta
    /// discovery and
    /// [`TimestampCheck::CurrentRef`](crate::TimestampCheck::CurrentRef) read
    /// the current commit of a ref at the same place.
    ///
    /// # Options
    ///
    /// Each field of [`PullOptions`] that [`Repo::pull`] reads applies to
    /// the pull from each selected remote, with these exceptions:
    ///
    /// - [`refs`](PullOptions::refs) selects the refs, as stated above.
    /// - [`overrides`](PullOptions::overrides),
    ///   [`verify`](PullOptions::verify), and
    ///   [`max_outstanding_fetches`](PullOptions::max_outstanding_fetches)
    ///   apply to the probe and the pull of each remote.
    /// - [`progress`](PullOptions::progress) gets the counters of each pull
    ///   from a remote, and no count of the probe.
    ///
    /// # Errors
    ///
    /// These errors stop the pull before its first request. The pull writes
    /// no object and no ref:
    ///
    /// - [`Error::InvalidInput`] if `collection_id` fails the collection-id
    ///   rule ([`is_collection_id`]) or is longer than 255 bytes.
    /// - [`Error::InvalidInput`] if `remotes` is empty.
    /// - [`Error::Pull`] if a subpath does not start with `/`.
    /// - [`Error::InvalidInput`] if [`depth`](PullOptions::depth) is below
    ///   `-1`.
    /// - [`Error::Unsupported`] if
    ///   [`collection_id`](PullOptions::collection_id) is set.
    /// - [`Error::InvalidInput`] if [`remote`](PullOptions::remote) is set,
    ///   if [`flags`](PullOptions::flags) holds
    ///   [`MIRROR`](PullFlags::MIRROR) or
    ///   [`DISABLE_VERIFY_BINDINGS`](PullFlags::DISABLE_VERIFY_BINDINGS), if
    ///   [`static_deltas`](PullOptions::static_deltas) is set, or if
    ///   [`overrides`](PullOptions::overrides) holds a `url`.
    /// - [`Error::InvalidRefspec`] if a name in [`refs`](PullOptions::refs)
    ///   is not a valid ref name.
    /// - [`Error::InvalidInput`] if a name in [`refs`](PullOptions::refs)
    ///   does not fit in a ref listing request alone: if its entry `ID/NAME`
    ///   is longer than [`MAX_REF_ENTRY_LEN`] bytes or has more than
    ///   [`MAX_REF_ENTRY_PARTS`] parts, or if the request target of the name
    ///   alone over HTTP is longer than 16 KiB.
    /// - The errors of [`resolve_pull`] and of [`PullTrust::from_remote`],
    ///   for each remote.
    /// - For each HTTP remote, the errors of [`Repo::pull`] that come from
    ///   the build of its fetcher: [`Error::Unsupported`] for a mirror
    ///   scheme other than `http` and `https` or a refused proxy, and
    ///   [`Error::Fetch`] for a mirror that is not a valid absolute URL, an
    ///   invalid header, or TLS material that does not parse.
    /// - For each ssh remote, [`Error::Remote`] if the ssh command or the
    ///   send command is empty or holds only white space, or if the
    ///   `OSTRYA_SSH_COMMAND` environment variable is not UTF-8.
    ///
    /// These errors stop the pull after the probe, before its first object
    /// request:
    ///
    /// - [`Error::Pull`] if each remote failed the probe.
    /// - [`Error::Pull`] if no remote lists a requested ref.
    /// - [`Error::Pull`] if [`refs`](PullOptions::refs) is empty and no
    ///   remote lists a ref of the collection.
    ///
    /// After these checks, the pull from each selected remote has the errors
    /// of [`Repo::pull`] that stop it before it fetches an object, while it
    /// fetches, and at any request or write. [`Error::Pull`] also comes from
    /// the checks of each commit above.
    ///
    /// # Examples
    ///
    /// Pull one ref of a collection from the remotes that serve it:
    ///
    /// ```no_run
    /// # async fn run() -> ostrya::Result<()> {
    /// let repo = ostrya::Repo::open("/srv/repo".as_ref()).await?;
    /// let mut opts = ostrya::CollectionPullOptions::default();
    /// opts.pull.refs = vec!["exampleos/stable".to_owned()];
    /// opts.on_event = Some(Box::new(|event| eprintln!("warning: {event}")));
    /// let pulled = repo
    ///     .pull_collection("org.example.Os", &["mirror1", "mirror2"], opts)
    ///     .await?;
    /// for r in &pulled.refs {
    ///     println!("{} from {}: {}", r.name, r.remote, r.commit);
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [`MAX_REF_PATTERNS`]: crate::MAX_REF_PATTERNS
    /// [`MAX_REF_ENTRY_LEN`]: crate::MAX_REF_ENTRY_LEN
    /// [`MAX_REF_ENTRY_PARTS`]: crate::MAX_REF_ENTRY_PARTS
    pub async fn pull_collection(
        &self,
        collection_id: &str,
        remotes: &[&str],
        opts: CollectionPullOptions,
    ) -> Result<CollectionPullStats> {
        let started = Instant::now();
        let CollectionPullOptions {
            pull: opts,
            mut on_event,
        } = opts;
        let subpaths = check_collection_pull(collection_id, remotes, &opts)?;
        let names = first_of_each(opts.refs.iter().map(String::as_str));

        // The endpoint, the trust, and the transport of each remote come
        // before the first request, so an error in the config of one remote
        // stops the pull.
        let mut candidates = Vec::with_capacity(remotes.len());
        for name in first_of_each(remotes.iter().copied()) {
            let endpoint = resolve_pull(Some(self.config()), name, opts.overrides.clone()).await?;
            let trust = PullTrust::from_remote(self, name, &opts.verify).await?;
            let transport = Transport::new(endpoint, opts.max_outstanding_fetches).await?;
            candidates.push(Candidate {
                name,
                transport,
                trust,
            });
        }

        // The session and the summary of each remote that answered, by the
        // position of the remote.
        let mut answers = Vec::with_capacity(candidates.len());
        let mut sessions = Vec::with_capacity(candidates.len());
        let mut summaries = Vec::with_capacity(candidates.len());
        for candidate in &candidates {
            let probed = Box::pin(probe(candidate, collection_id, &names)).await;
            match probed {
                Ok(probed) => {
                    answers.push(Some(probed.listed));
                    sessions.push(Some(probed.session));
                    summaries.push(probed.summary);
                }
                Err(e) => {
                    if let Some(on_event) = on_event.as_mut() {
                        on_event(CollectionPullEvent::RemoteSkipped {
                            remote: candidate.name.to_owned(),
                            message: e.to_string(),
                        });
                    }
                    answers.push(None);
                    sessions.push(None);
                    summaries.push(None);
                }
            }
        }
        let selected = match select(collection_id, &names, &answers) {
            Ok(selected) => selected,
            Err(e) => {
                end_sessions(sessions.into_iter().flatten()).await;
                return Err(e);
            }
        };
        drop(answers);
        // A remote with no selected ref is not asked again.
        let unselected = take_unselected(&mut sessions, &mut summaries, |index| {
            selected.iter().any(|s| s.remote == index)
        });
        end_sessions(unselected).await;

        let place = if self.config().collection_id() == Some(collection_id) {
            RefPlace::Heads
        } else {
            RefPlace::Collection(collection_id)
        };
        let candidate_names: Vec<&str> = candidates.iter().map(|c| c.name).collect();
        let mut stats = PullStats::default();
        for (index, candidate) in candidates.into_iter().enumerate() {
            let Some(session) = sessions[index].take() else {
                continue;
            };
            let mine: Vec<&Listed> = selected
                .iter()
                .filter(|selected| selected.remote == index)
                .map(|selected| &selected.listed)
                .collect();
            let pinned = Pinned {
                targets: mine.iter().map(|l| (l.name.clone(), l.commit)).collect(),
                listed: mine.iter().map(|l| (l.name.clone(), l.timestamp)).collect(),
                collection: collection_id,
                place,
                summary: Mutex::new(summaries[index].take()),
            };
            // The trust and the session hold what these fields gave.
            let run = PullOptions {
                refs: pinned
                    .targets
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect(),
                verify: PullVerify::default(),
                max_outstanding_fetches: None,
                overrides: EndpointOverrides::default(),
                ..opts.clone()
            };
            let pulled = self
                .run_session(
                    session,
                    candidate.trust,
                    run,
                    Wanted::Pinned(&pinned),
                    subpaths.clone(),
                    None,
                    Instant::now(),
                )
                .await;
            match pulled {
                Ok(pulled) => add_stats(&mut stats, &pulled),
                Err(e) => {
                    end_sessions(sessions.into_iter().flatten()).await;
                    return Err(e);
                }
            }
        }
        stats.elapsed = started.elapsed();

        let refs = selected
            .into_iter()
            .map(|selected| CollectionPullRef {
                name: selected.listed.name,
                remote: candidate_names[selected.remote].to_owned(),
                commit: selected.listed.commit,
                timestamp: selected.listed.timestamp,
            })
            .collect();
        Ok(CollectionPullStats { refs, stats })
    }
}

/// Returns the first appearance of each value of `values`, in order.
fn first_of_each<'a>(values: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut seen = HashSet::new();
    values.filter(|value| seen.insert(*value)).collect()
}

/// Takes out of `sessions` the session of each remote for whose position
/// `selected` returns `false`, and drops the summary of that remote in
/// `summaries`.
///
/// `sessions` and `summaries` hold one slot for each remote, by its
/// position. The pull reads nothing more from a remote with no selected ref,
/// so its summary does not stay in memory for the rest of the pull.
fn take_unselected<S, M>(
    sessions: &mut [Option<S>],
    summaries: &mut [Option<M>],
    selected: impl Fn(usize) -> bool,
) -> Vec<S> {
    sessions
        .iter_mut()
        .zip(summaries.iter_mut())
        .enumerate()
        .filter(|(index, _)| !selected(*index))
        .filter_map(|(_, (session, summary))| {
            *summary = None;
            session.take()
        })
        .collect()
}

/// Ends each session of `sessions`.
///
/// The pull reads nothing more from these remotes, so an error of an end has
/// no effect, and the call drops it.
async fn end_sessions(sessions: impl IntoIterator<Item = PullSession>) {
    for session in sessions {
        let _ = session.finish().await;
    }
}

/// Makes the checks of [`Repo::pull_collection`] that read the arguments
/// alone, in the order of its `# Errors`, and returns the parsed subpaths.
fn check_collection_pull(
    collection_id: &str,
    remotes: &[&str],
    opts: &PullOptions,
) -> Result<Option<Subpaths>> {
    if !is_collection_id(collection_id) || collection_id.len() > MAX_COLLECTION_ID_LEN {
        return Err(Error::InvalidInput(format!(
            "invalid collection id: {collection_id}"
        )));
    }
    if remotes.is_empty() {
        return Err(Error::InvalidInput(
            "a collection pull needs at least one remote".into(),
        ));
    }
    let subpaths = Subpaths::parse(&opts.subpaths)?;
    check_depth(opts.depth)?;
    refuse_remote_collection(opts)?;
    if opts.remote.is_some() {
        return Err(Error::InvalidInput(
            "a collection pull writes the refs of the collection, and takes no remote option"
                .into(),
        ));
    }
    if opts.flags.contains(PullFlags::MIRROR) {
        return Err(Error::InvalidInput(
            "a collection pull takes no MIRROR flag".into(),
        ));
    }
    if opts.flags.contains(PullFlags::DISABLE_VERIFY_BINDINGS) {
        return Err(Error::InvalidInput(
            "a collection pull checks the bindings of each commit, and takes no \
             DISABLE_VERIFY_BINDINGS flag"
                .into(),
        ));
    }
    if opts.static_deltas.is_some() {
        return Err(Error::InvalidInput(
            "a collection pull takes no static_deltas list".into(),
        ));
    }
    if opts.overrides.url.is_some() {
        return Err(Error::InvalidInput(
            "a collection pull reads the address of each remote from the config, and takes \
             no url override"
                .into(),
        ));
    }
    for name in &opts.refs {
        check_ref_path(name)?;
    }
    for name in &opts.refs {
        check_listing_name(collection_id, name)?;
    }
    Ok(subpaths)
}

/// Checks that a ref listing request of the collection `id` can hold the
/// valid ref name `name` alone.
///
/// The entry `ID/NAME` must have at most [`MAX_REF_ENTRY_LEN`] bytes and at
/// most [`MAX_REF_ENTRY_PARTS`] parts. The id holds no `/`, so it adds one
/// part. The request target of the name alone over HTTP must be at most
/// [`MAX_LISTING_TARGET`] bytes. The entry `NAME` is shorter than `ID/NAME`.
///
/// # Errors
///
/// - [`Error::InvalidInput`] if a limit refuses the name.
fn check_listing_name(id: &str, name: &str) -> Result<()> {
    let entry_len = id.len() + 1 + name.len();
    let parts = 1 + name.split('/').count();
    if entry_len > MAX_REF_ENTRY_LEN
        || parts > MAX_REF_ENTRY_PARTS
        || name_cost(id, name) > LISTING_BUDGET
    {
        return Err(Error::InvalidInput(format!(
            "the ref name '{name}' is too long for a ref listing request of the collection \
             '{id}'"
        )));
    }
    Ok(())
}

/// Returns the length of `value` in the query of a ref listing request.
///
/// Each byte outside `A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, and `~` is `%XX`,
/// as [`PullSession::fetch_refs`] writes it.
fn encoded_len(value: &str) -> usize {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                1
            } else {
                3
            }
        })
        .sum()
}

/// Returns the bytes that the name `name` adds to the query of an HTTP ref
/// listing request of the collection `id`.
///
/// These are the pairs `pattern=NAME` and `collection=ID/NAME`, each with
/// its value encoded and the `&` before it.
fn name_cost(id: &str, name: &str) -> usize {
    let pattern = "pattern=".len() + encoded_len(name);
    let collection = "collection=".len() + encoded_len(id) + encoded_len("/") + encoded_len(name);
    pattern + collection + 2
}

/// Asks the remote of `candidate` for the commit of each ref of `names` in
/// the collection `id`, or of each ref of the collection if `names` is
/// empty.
///
/// The probe opens a session. If the probe fails, it ends the session. If
/// the probe succeeds, it gives the session back for the pull.
async fn probe(candidate: &Candidate<'_>, id: &str, names: &[&str]) -> Result<Probed> {
    let session = candidate.transport.open().await?;
    let http = matches!(session, PullSession::Http(_));
    // The probe reads files that a pull reads before its count starts, so it
    // counts no byte.
    let source = RemoteSource::new(session, Vec::new());
    let verification = Verification::from_trust(candidate.trust.clone());
    match probe_source(&source, &verification, id, names, http).await {
        Ok((listed, summary)) => Ok(Probed {
            listed,
            summary,
            session: source.into_session(),
        }),
        Err(e) => source.finish(Err(e)).await,
    }
}

/// The refs that a probe read, and the `summary` if the refs come from it.
type Refs = (Vec<Listed>, Option<Arc<Vec<u8>>>);

/// Reads the refs of `names` in the collection `id` from `source`, or each
/// ref of the collection if `names` is empty.
///
/// If `verification` checks the summary, the refs come from the summary,
/// after its check. Otherwise they come from the ref listing, or from the
/// summary of a remote with no ref listing. `http` applies the byte limit of
/// an HTTP request to the listing requests.
async fn probe_source(
    source: &RemoteSource,
    verification: &Verification,
    id: &str,
    names: &[&str],
    http: bool,
) -> Result<Refs> {
    // No signature covers the ref listing. So under a policy that covers the
    // summary, the summary alone tells the refs.
    if verification.checks_summary() {
        return summary_refs(source, verification, id, names).await;
    }
    if names.is_empty() {
        return every_ref(source, verification, id).await;
    }
    let mut listed = Vec::new();
    for chunk in listing_chunks(id, names, http) {
        let refs = RefSelector::parse(chunk.iter().copied())?;
        let entries: Vec<String> = chunk.iter().map(|name| format!("{id}/{name}")).collect();
        let collections = RefSelector::parse(entries.iter().map(String::as_str))?;
        let Some(bytes) = read_listing(source, &refs, Some(&collections)).await? else {
            return summary_refs(source, verification, id, names).await;
        };
        listed.extend(parse_refs(Arc::new(bytes), id, chunk).await?.1);
    }
    Ok((listed, None))
}

/// Reads each ref of the collection `id` from the ref listing of `source`,
/// or from the summary of a remote with no ref listing.
///
/// The first request selects no local ref, with the entry `!**`, and each
/// ref of the collection, with the entry `ID/**`. If the listing states `id`
/// as the collection id of the remote, the refs of the collection are its
/// local refs. A second request then selects each local ref, and no
/// collection ref. So a remote of another collection sends no local ref.
async fn every_ref(source: &RemoteSource, verification: &Verification, id: &str) -> Result<Refs> {
    let no_local = RefSelector::parse(["!**"])?;
    let entry = format!("{id}/**");
    let collections = RefSelector::parse([entry.as_str()])?;
    let Some(bytes) = read_listing(source, &no_local, Some(&collections)).await? else {
        return summary_refs(source, verification, id, &[]).await;
    };
    let (own, listed) = parse_refs(Arc::new(bytes), id, &[]).await?;
    if !own {
        return Ok((listed, None));
    }
    let each_local = RefSelector::parse(std::iter::empty())?;
    let Some(bytes) = read_listing(source, &each_local, None).await? else {
        return summary_refs(source, verification, id, &[]).await;
    };
    Ok((parse_refs(Arc::new(bytes), id, &[]).await?.1, None))
}

/// Reads the ref listing of `refs` and `collections` from `source`, or
/// returns `None` if the remote serves no ref listing.
///
/// An HTTP remote serves no listing when it answers with a status from 400
/// to 499. [`RemoteSource::ref_listing`] gives `None` for 404. A static
/// server answers 404, and another server can refuse a query that it does
/// not know with another status of the range.
async fn read_listing(
    source: &RemoteSource,
    refs: &RefSelector,
    collections: Option<&RefSelector>,
) -> Result<Option<Vec<u8>>> {
    match source.ref_listing(refs, collections).await {
        Err(Error::HttpStatus {
            status: 400..=499, ..
        }) => Ok(None),
        other => other,
    }
}

/// Reads the refs of `names` in the collection `id` from the summary of
/// `source`, or each ref of the collection if `names` is empty, and returns
/// them with the summary.
///
/// If `verification` checks the summary, the call reads `summary.sig` too,
/// and verifies the summary before it reads the refs. Otherwise it reads
/// `summary` alone. A remote with no summary lists no ref, if no policy
/// applies to its summary.
async fn summary_refs(
    source: &RemoteSource,
    verification: &Verification,
    id: &str,
    names: &[&str],
) -> Result<Refs> {
    let summary = if verification.checks_summary() {
        let (summary, signature) = source.summary_files().await?;
        verification
            .check_summary(summary.as_deref(), signature)
            .await?;
        summary
    } else {
        source
            .read_optional(SUMMARY_FILE, Priority::High, MAX_ROOT_FILE)
            .await?
    };
    let Some(bytes) = summary else {
        return Ok((Vec::new(), None));
    };
    let bytes = Arc::new(bytes);
    let (_, listed) = parse_refs(Arc::clone(&bytes), id, names).await?;
    Ok((listed, Some(bytes)))
}

/// Parses the listing or the summary `bytes`, and returns the refs of the
/// collection `id` that `names` names, or each ref of the collection if
/// `names` is empty.
///
/// The result also tells if the bytes state `id` as the collection id of the
/// remote. A summary can be as large as its read cap, so the parse runs on
/// the blocking pool.
async fn parse_refs(bytes: Arc<Vec<u8>>, id: &str, names: &[&str]) -> Result<(bool, Vec<Listed>)> {
    let id = id.to_owned();
    let wanted: Option<HashSet<String>> =
        (!names.is_empty()).then(|| names.iter().map(|name| (*name).to_owned()).collect());
    ostrya_rt::unblock(move || collection_refs(&bytes, &id, wanted.as_ref())).await
}

/// Returns the refs of the collection `id` in the listing or the summary
/// `bytes` that `wanted` names, or each ref of the collection if `wanted` is
/// `None`, and tells if the bytes state `id` as the collection id of the
/// remote.
///
/// The call reads the global metadata first. If it states `id` as the
/// collection id, the refs are in field 0, and the call parses field 0.
/// Otherwise they are in the entry of `id` of the collection map, and the
/// call parses that entry alone and leaves field 0 undecoded. A name that
/// occurs again keeps its first entry.
///
/// # Errors
///
/// - [`Error::Core`] or [`Error::InvalidFormat`] if the bytes do not parse,
///   or if the collection map is malformed.
/// - [`Error::InvalidFormat`] if a ref has no `ostree.commit.timestamp` of
///   type `t`.
/// - [`Error::InvalidRefspec`] if a name fails the ref-name rule.
fn collection_refs(
    bytes: &[u8],
    id: &str,
    wanted: Option<&HashSet<String>>,
) -> Result<(bool, Vec<Listed>)> {
    let metadata = Summary::parse_metadata(bytes)?;
    let own = metadata
        .dict_get(COLLECTION_ID_KEY)
        .and_then(Value::as_variant)
        .and_then(|(_, value)| value.as_str())
        == Some(id);
    let entries = if own {
        drop(metadata);
        parse_ref_list(bytes)?
    } else {
        collection_map_refs(&metadata, id)?
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in &entries {
        if wanted.is_some_and(|wanted| !wanted.contains(&entry.name))
            || !seen.insert(entry.name.as_str())
        {
            continue;
        }
        check_ref_path(&entry.name)?;
        out.push(Listed {
            name: entry.name.clone(),
            commit: entry.commit,
            timestamp: listed_timestamp(entry)?,
        });
    }
    Ok((own, out))
}

/// Returns the `ostree.commit.timestamp` of a listed ref.
///
/// The value is a big-endian `t`, so one byte swap of the decoded number
/// gives the timestamp.
fn listed_timestamp(entry: &SummaryRef) -> Result<u64> {
    match entry
        .metadata
        .dict_get(COMMIT_TIMESTAMP_KEY)
        .and_then(Value::as_variant)
    {
        Some((ty, Value::U64(raw))) if ty.signature() == "t" => Ok(raw.swap_bytes()),
        _ => Err(Error::InvalidFormat(format!(
            "the ref '{}' is listed with no {COMMIT_TIMESTAMP_KEY} of type t",
            entry.name
        ))),
    }
}

/// Splits `names` into the names of each ref listing request.
///
/// Each name adds two entries to a request: the name, and the name under the
/// collection id `id`. A request holds at most [`MAX_REF_PATTERNS`] entries.
/// If `http` is `true`, the pairs of the names of a request also fill at
/// most [`LISTING_BUDGET`] bytes, so the request target is at most
/// [`MAX_LISTING_TARGET`] bytes. A stream session has no such limit.
/// [`check_listing_name`] makes sure that each name fits in a request alone.
fn listing_chunks<'n, 'a>(id: &str, names: &'n [&'a str], http: bool) -> Vec<&'n [&'a str]> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut cost = 0;
    for (index, name) in names.iter().enumerate() {
        let this = if http { name_cost(id, name) } else { 0 };
        if index > start
            && (2 * (index - start) >= MAX_REF_PATTERNS || cost + this > LISTING_BUDGET)
        {
            chunks.push(&names[start..index]);
            start = index;
            cost = 0;
        }
        cost += this;
    }
    if start < names.len() {
        chunks.push(&names[start..]);
    }
    chunks
}

/// Selects the remote of each ref: the remote that lists the newest commit,
/// by the listed timestamp, with a tie to the earlier remote.
///
/// `answers` holds the refs that each candidate listed, in the order of the
/// candidates, and `None` for a candidate that the pull skipped. The result
/// follows the order of `names`. If `names` is empty, the result holds each
/// listed ref, in byte-wise order of the names.
///
/// # Errors
///
/// - [`Error::Pull`] if each candidate was skipped.
/// - [`Error::Pull`] if no candidate lists a name of `names`.
/// - [`Error::Pull`] if `names` is empty and no candidate lists a ref.
fn select(id: &str, names: &[&str], answers: &[Option<Vec<Listed>>]) -> Result<Vec<Selected>> {
    if answers.iter().all(Option::is_none) {
        return Err(Error::Pull(format!(
            "no remote of collection '{id}' answered"
        )));
    }
    let mut best: HashMap<&str, (usize, &Listed)> = HashMap::new();
    for (remote, listed) in answers.iter().enumerate() {
        for listed in listed.iter().flatten() {
            best.entry(listed.name.as_str())
                .and_modify(|current| {
                    if listed.timestamp > current.1.timestamp {
                        *current = (remote, listed);
                    }
                })
                .or_insert((remote, listed));
        }
    }
    let order: Vec<&str> = if names.is_empty() {
        if best.is_empty() {
            return Err(Error::Pull(format!(
                "no remote lists a ref of collection '{id}'"
            )));
        }
        let mut all: Vec<&str> = best.keys().copied().collect();
        all.sort_unstable();
        all
    } else {
        names.to_vec()
    };
    order
        .into_iter()
        .map(|name| match best.get(name) {
            Some((remote, listed)) => Ok(Selected {
                remote: *remote,
                listed: (*listed).clone(),
            }),
            None => Err(Error::Pull(format!(
                "no remote of collection '{id}' lists the ref '{name}'"
            ))),
        })
        .collect()
}

/// Adds the counts of `pulled` to `total`. The run time stays as it is.
fn add_stats(total: &mut PullStats, pulled: &PullStats) {
    total.metadata_imported += pulled.metadata_imported;
    total.content_imported += pulled.content_imported;
    total.content_bytes_written += pulled.content_bytes_written;
    total.content_bytes_unpacked += pulled.content_bytes_unpacked;
    total.metadata_fetched += pulled.metadata_fetched;
    total.content_fetched += pulled.content_fetched;
    total.delta_parts += pulled.delta_parts;
    total.bytes_transferred += pulled.bytes_transferred;
}

/// A compile-time check that the future of a collection pull is `Send`, and
/// that its result is `Send` and `Sync`.
const _: fn() = || {
    fn assert_send<T: Send>(_: &T) {}
    fn assert_send_sync<T: Send + Sync>() {}
    let _ = |repo: &Repo| {
        assert_send(&repo.pull_collection(
            "org.example.Os",
            &["origin"],
            CollectionPullOptions::default(),
        ))
    };
    assert_send_sync::<CollectionPullStats>();
    assert_send_sync::<CollectionPullEvent>();
};

#[cfg(test)]
mod tests {
    use ostrya_core::{Type, to_bytes};

    use super::*;
    use crate::fetch::FetcherOptions;

    fn csum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    fn listed(name: &str, byte: u8, timestamp: u64) -> Listed {
        Listed {
            name: name.to_owned(),
            commit: csum(byte),
            timestamp,
        }
    }

    /// Test refs, each `(name, commit byte, timestamp)`.
    type TestRefs<'a> = &'a [(&'a str, u8, u64)];

    /// Returns a ref entry `(s, (t, ay, a{sv}))` with the metadata dict
    /// `metadata`.
    fn ref_value(name: &str, byte: u8, metadata: Value) -> Value {
        Value::Tuple(vec![
            Value::Str(name.to_owned()),
            Value::Tuple(vec![
                Value::U64(1),
                Value::Bytes(csum(byte).as_bytes().to_vec()),
                metadata,
            ]),
        ])
    }

    /// Returns the ref entries of `refs`, each with its timestamp.
    fn ref_values(refs: TestRefs<'_>) -> Vec<Value> {
        refs.iter()
            .map(|(name, byte, ts)| {
                let timestamp = Value::Tuple(vec![
                    Value::Str(COMMIT_TIMESTAMP_KEY.to_owned()),
                    Value::Variant(Box::new((
                        Type::parse("t").unwrap(),
                        Value::U64(ts.swap_bytes()),
                    ))),
                ]);
                ref_value(name, *byte, Value::Array(vec![timestamp]))
            })
            .collect()
    }

    /// Returns the bytes of a summary with the ref entries `field0` in field
    /// 0, the refs `map` under their ids in the collection map, and `own` as
    /// its collection id.
    fn summary_of(field0: Vec<Value>, map: &[(&str, TestRefs<'_>)], own: Option<&str>) -> Vec<u8> {
        let mut metadata = Vec::new();
        if !map.is_empty() {
            let entries = map
                .iter()
                .map(|(id, refs)| {
                    Value::Tuple(vec![
                        Value::Str((*id).to_owned()),
                        Value::Array(ref_values(refs)),
                    ])
                })
                .collect();
            metadata.push(Value::Tuple(vec![
                Value::Str("ostree.summary.collection-map".to_owned()),
                Value::Variant(Box::new((
                    Type::parse("a{sa(s(taya{sv}))}").unwrap(),
                    Value::Array(entries),
                ))),
            ]));
        }
        if let Some(own) = own {
            metadata.push(Value::Tuple(vec![
                Value::Str(COLLECTION_ID_KEY.to_owned()),
                Value::Variant(Box::new((
                    Type::parse("s").unwrap(),
                    Value::Str(own.to_owned()),
                ))),
            ]));
        }
        let value = Value::Tuple(vec![Value::Array(field0), Value::Array(metadata)]);
        to_bytes(&Type::parse("(a(s(taya{sv}))a{sv})").unwrap(), &value).unwrap()
    }

    /// Returns the bytes of a summary with the refs `field0` in field 0, the
    /// refs `map` under their ids in the collection map, and `own` as its
    /// collection id.
    fn summary(field0: TestRefs<'_>, map: &[(&str, TestRefs<'_>)], own: Option<&str>) -> Vec<u8> {
        summary_of(ref_values(field0), map, own)
    }

    /// The sessions of the remotes with no selected ref leave their slots,
    /// and the summaries of these remotes are dropped. The slots of the
    /// selected remotes keep their sessions and their summaries.
    #[test]
    fn the_unselected_remotes_leave_their_sessions_and_summaries() {
        let mut sessions = vec![Some('a'), None, Some('c'), Some('d')];
        let mut summaries = vec![Some(1), None, Some(3), Some(4)];
        let taken = take_unselected(&mut sessions, &mut summaries, |index| index == 2);
        assert_eq!(taken, ['a', 'd']);
        assert_eq!(sessions, [None, None, Some('c'), None]);
        assert_eq!(summaries, [None, None, Some(3), None]);
    }

    /// A summary whose own collection id is the pulled id gives the refs of
    /// field 0, and the collection map is not read for that id.
    #[test]
    fn the_own_collection_reads_field_0() {
        let s = summary(
            &[("os/stable", 1, 10), ("os/next", 2, 20)],
            &[("org.example.Os", &[("os/stable", 9, 99)])],
            Some("org.example.Os"),
        );
        let refs = collection_refs(&s, "org.example.Os", None).unwrap();
        assert_eq!(
            refs,
            (
                true,
                vec![listed("os/stable", 1, 10), listed("os/next", 2, 20)]
            )
        );
    }

    /// Another collection reads the entry of the map, ignores field 0, and
    /// keeps only the wanted names. The entry of another collection is not
    /// parsed, so a malformed entry after the entry of the id is not read.
    #[test]
    fn another_collection_reads_the_map_and_ignores_field_0() {
        let s = summary(
            &[("os/stable", 1, 10)],
            &[
                ("org.example.Other", &[("os/stable", 7, 70)]),
                (
                    "org.example.Os",
                    &[("os/stable", 3, 30), ("os/next", 4, 40)],
                ),
            ],
            Some("org.example.Mine"),
        );
        let wanted: HashSet<String> = ["os/stable".to_owned()].into();
        let refs = collection_refs(&s, "org.example.Os", Some(&wanted)).unwrap();
        assert_eq!(refs, (false, vec![listed("os/stable", 3, 30)]));
        // A summary with no collection id and no map entry lists nothing.
        let s = summary(&[("os/stable", 1, 10)], &[], None);
        assert_eq!(
            collection_refs(&s, "org.example.Os", None).unwrap(),
            (false, Vec::new())
        );
    }

    /// A ref with no timestamp, or with a timestamp of another type, fails
    /// the read.
    #[test]
    fn a_ref_with_no_valid_timestamp_fails() {
        let no_key = summary_of(
            vec![ref_value("os/stable", 1, Value::Array(Vec::new()))],
            &[],
            Some("org.example.Os"),
        );
        let other_type = summary_of(
            vec![ref_value(
                "os/stable",
                1,
                Value::Array(vec![Value::Tuple(vec![
                    Value::Str(COMMIT_TIMESTAMP_KEY.to_owned()),
                    Value::Variant(Box::new((Type::parse("u").unwrap(), Value::U32(1)))),
                ])]),
            )],
            &[],
            Some("org.example.Os"),
        );
        for s in [no_key, other_type] {
            assert!(matches!(
                collection_refs(&s, "org.example.Os", None),
                Err(Error::InvalidFormat(_))
            ));
        }
    }

    /// The newest timestamp wins, a tie goes to the earlier remote, and a
    /// skipped remote takes no part.
    #[test]
    fn the_newest_commit_wins_and_a_tie_goes_to_the_earlier_remote() {
        let answers = vec![
            Some(vec![listed("a", 1, 10), listed("b", 2, 20)]),
            None,
            Some(vec![listed("a", 3, 30), listed("b", 4, 20)]),
        ];
        let selected = select("org.example.Os", &["b", "a"], &answers).unwrap();
        assert_eq!(
            selected,
            [
                Selected {
                    remote: 0,
                    listed: listed("b", 2, 20)
                },
                Selected {
                    remote: 2,
                    listed: listed("a", 3, 30)
                },
            ]
        );
    }

    /// With no names, each listed ref is selected, in byte-wise order. A
    /// named ref that no remote lists fails, and so does a pull in which each
    /// remote was skipped. With no names, a pull in which no remote lists a
    /// ref fails.
    #[test]
    fn selection_takes_each_listed_ref_or_fails_a_missing_one() {
        let answers = vec![
            Some(vec![listed("b", 2, 20)]),
            Some(vec![listed("a", 1, 10)]),
        ];
        let names: Vec<String> = select("org.example.Os", &[], &answers)
            .unwrap()
            .into_iter()
            .map(|s| s.listed.name)
            .collect();
        assert_eq!(names, ["a", "b"]);
        let err = select("org.example.Os", &["c"], &answers).unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m.contains("'c'") && m.contains("org.example.Os")),
            "{err:?}"
        );
        let err = select("org.example.Os", &["a"], &[None, None]).unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err:?}");
        let err = select("org.example.Os", &[], &[Some(Vec::new()), None]).unwrap_err();
        assert!(
            matches!(&err, Error::Pull(m) if m == "no remote lists a ref of collection 'org.example.Os'"),
            "{err:?}"
        );
    }

    /// A long list of names splits into requests of at most the entry limit.
    /// Over HTTP, long names also split by the byte budget. Over a stream
    /// session, the entry limit alone applies.
    #[test]
    fn the_names_split_by_the_entry_limit_and_the_byte_budget() {
        let short: Vec<String> = (0..300).map(|n| format!("r{n}")).collect();
        let short: Vec<&str> = short.iter().map(String::as_str).collect();
        for http in [true, false] {
            let chunks = listing_chunks("org.example.Os", &short, http);
            assert_eq!(
                chunks.iter().map(|c| c.len()).collect::<Vec<_>>(),
                [
                    MAX_REF_PATTERNS / 2,
                    MAX_REF_PATTERNS / 2,
                    300 - MAX_REF_PATTERNS
                ]
            );
        }
        // Each long name costs about 8 KiB on the wire, so two fill a
        // request.
        let long = "x".repeat(4000);
        let names = [long.as_str(), long.as_str(), long.as_str(), "a"];
        let chunks = listing_chunks("org.example.Os", &names, true);
        assert_eq!(chunks.iter().map(|c| c.len()).collect::<Vec<_>>(), [2, 2]);
        assert_eq!(listing_chunks("org.example.Os", &names, false).len(), 1);
        assert!(listing_chunks("org.example.Os", &[], true).is_empty());
    }

    /// The byte budget is exact: names whose pairs fill it make a request
    /// target of 16 KiB, which the client sends. One more byte splits the
    /// names into two requests, and the client refuses the one request.
    #[test]
    fn the_byte_budget_matches_the_request_target_of_the_client() {
        ostrya_rt::block_on(async {
            // An id of odd length makes the cost of each name odd, so five
            // names can fill the odd budget.
            let id = "org.example.Oss";
            let mut opts = FetcherOptions::new("http://127.0.0.1:1/");
            opts.max_retries = 0;
            let session = PullSession::Http(Fetcher::new(opts).await.unwrap());
            let fetch = |names: Vec<String>| {
                let session = &session;
                async move {
                    let refs = RefSelector::parse(names.iter().map(String::as_str)).unwrap();
                    let entries: Vec<String> =
                        names.iter().map(|name| format!("{id}/{name}")).collect();
                    let collections =
                        RefSelector::parse(entries.iter().map(String::as_str)).unwrap();
                    session.fetch_refs(&refs, Some(&collections)).await
                }
            };
            let fill = |last: usize| -> Vec<String> {
                let mut names: Vec<String> =
                    (0..4).map(|n| format!("{n}{}", "x".repeat(1616))).collect();
                names.push("y".repeat(last));
                names
            };
            let exact = fill(1619);
            let cost: usize = exact.iter().map(|name| name_cost(id, name)).sum();
            assert_eq!(cost, LISTING_BUDGET);
            let names: Vec<&str> = exact.iter().map(String::as_str).collect();
            assert_eq!(listing_chunks(id, &names, true).len(), 1);
            let sent = fetch(exact.clone()).await;
            assert!(
                !matches!(sent, Err(crate::remote::Error::InvalidInput(_))),
                "{sent:?}"
            );

            let over = fill(1620);
            let names: Vec<&str> = over.iter().map(String::as_str).collect();
            assert_eq!(listing_chunks(id, &names, true).len(), 2);
            let refused = fetch(over.clone()).await;
            assert!(
                matches!(refused, Err(crate::remote::Error::InvalidInput(_))),
                "{refused:?}"
            );
        });
    }

    /// A name whose entry under the id passes the byte limit or the part
    /// limit, or whose request target alone passes 16 KiB, is refused before
    /// the first request. A name at each limit passes.
    #[test]
    fn a_name_that_no_listing_request_can_hold_is_refused() {
        let id = "org.example.Os";
        let at_len = "x".repeat(MAX_REF_ENTRY_LEN - id.len() - 1);
        let over_len = format!("{at_len}x");
        let at_parts = vec!["p"; MAX_REF_ENTRY_PARTS - 1].join("/");
        let over_parts = format!("{at_parts}/p");
        // Each `é` is two bytes, and each byte is `%XX` on the wire.
        let wide = "é".repeat(2000);
        assert!(id.len() + 1 + wide.len() <= MAX_REF_ENTRY_LEN);
        for name in [&at_len, &at_parts] {
            check_listing_name(id, name).unwrap();
        }
        for name in [&over_len, &over_parts, &wide] {
            let err = check_listing_name(id, name).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidInput(m) if m.contains("too long")),
                "{err:?}"
            );
        }
    }

    /// The text of an event escapes each control character.
    #[test]
    fn the_skip_event_escapes_control_characters() {
        let event = CollectionPullEvent::RemoteSkipped {
            remote: "mirror".to_owned(),
            message: "bad\nline".to_owned(),
        };
        assert_eq!(event.to_string(), "remote mirror skipped: bad\\nline");
    }
}
