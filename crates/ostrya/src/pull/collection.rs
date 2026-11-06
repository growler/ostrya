//! The pull of the refs of one collection from the remotes that serve it.
//!
//! [`Repo::pull_collection`] is the entry point and states the rules. The
//! pull runs in three parts:
//!
//! 1. The checks of the options, and the endpoint, the trust, and the
//!    transport of each remote. A failure stops the pull before its first
//!    request.
//! 2. The find step: the probe of each remote, in the given order. The probe
//!    reads the commit and the timestamp of each ref, from the ref listing or
//!    from the summary. The probe of a remote at a `file://` address reads
//!    the ref files of the local repository, or its summary. The probe skips
//!    each listed ref whose name fails the ref-name rule. The find step
//!    gives the refs, the names of the skipped refs, and the session of each
//!    remote that answers, and the error of each other remote. If the probe
//!    of a remote read the refs from its `summary`, the find step also gives
//!    these bytes. The pull from that remote reads them in place of the
//!    `summary` and the `summary.sig`. The probe of a local repository gives
//!    no summary. The pull skips a remote that fails. It reports each
//!    skipped remote and each skipped ref through its event callback.
//! 3. The selection of a remote for each ref, and then one pull from each
//!    selected remote, in the given order, through the engine of
//!    [`Repo::pull`], over the session of its probe. A local repository goes
//!    through the engine of [`Repo::pull_local`].
//!
//! [`Repo::remote_list_collection_refs_with`] makes the checks of part 1 and
//! the find step of part 2 for its one remote. The error of that remote is
//! the error of the call. The call returns the name and the commit of each
//! ref that the find step read, and drops the timestamps. Its event callback
//! gets the name of each ref that the probe skipped.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ostrya_core::{Checksum, Commit, ObjectType, RefSelector, Value};

use crate::endpoint::{EndpointOverrides, local_pull_path, resolve_pull};
use crate::error::{Error, Result};
use crate::fetch::Fetcher;
use crate::refs::{check_ref_path, is_ref_path, is_valid_collection_id};
use crate::related::RelatedRule;
use crate::remote::proto::{MAX_REF_ENTRY_LEN, MAX_REF_ENTRY_PARTS, MAX_REF_PATTERNS};
#[cfg(feature = "s3")]
use crate::remote::s3::{Bucket, S3Endpoint};
use crate::remote::{Endpoint, PullSession, StreamSession, StreamSessionOptions};
use crate::repo::Repo;
use crate::send::write_escaped;
use crate::summary::{
    COLLECTION_ID_KEY, COMMIT_TIMESTAMP_KEY, SUMMARY_FILE, Summary, SummaryRef,
    collection_map_refs, parse_ref_list,
};
use crate::verify::PullTrust;
use crate::verify::trust::FieldGroup;

#[cfg(feature = "s3")]
use super::http::s3_fetcher;
use super::http::{Wanted, connect, session_options};
use super::source::{Connection, RemoteSource};
use super::subpath::Subpaths;
use super::verify::Verification;
use super::{
    LocalWanted, Pinned, PullFlags, PullOptions, PullStats, PullVerify, RefPlace, check_depth,
    read_checked_local_summary, refuse_remote_collection,
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
    /// The pull gives it each remote and each listed ref that the probe
    /// skips, after the probe of the remote and before the probe of the next
    /// remote. The pull calls it on its own task, so the callback must return
    /// soon.
    /// A command writes the [`Display`](fmt::Display) text of the event as a
    /// warning on standard error. The default is `None`, which drops each
    /// event.
    pub on_event: Option<Box<dyn FnMut(CollectionPullEvent) + Send>>,
    /// `true` if a tip commit with no `ostree.collection-binding` key passes
    /// the collection-binding check.
    ///
    /// The default is `false`, and such a tip fails the pull. The switch
    /// applies only when the key is absent. A tip whose binding is not a
    /// string, or names another collection, fails with either value. The
    /// switch does not change the `ostree.ref-binding` check, the check of
    /// the listed timestamp, or the timestamp check.
    ///
    /// Apart from the ref binding, the pull does not check a commit against
    /// the name of its ref. So a remote can serve, for a name, any commit with
    /// no binding of either kind. The trust of the remote and a check of the
    /// content by the caller after the pull are the protection.
    pub allow_unbound: bool,
}

/// The debug text shows a callback that is set as `<callback>`.
impl fmt::Debug for CollectionPullOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CollectionPullOptions")
            .field("pull", &self.pull)
            .field("on_event", &self.on_event.as_ref().map(|_| "<callback>"))
            .field("allow_unbound", &self.allow_unbound)
            .finish()
    }
}

/// An event of [`Repo::pull_collection`], which
/// [`CollectionPullOptions::on_event`] receives, or of
/// [`Repo::remote_list_collection_refs_with`], which its parameter `on_event`
/// receives.
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
    /// listed ref with no valid timestamp, a summary that the policy of the
    /// remote refuses, and a bucket repository with no summary. For a remote
    /// at a `file://` address, the causes also include a path with no
    /// repository, and a directory or a ref file of the selection that
    /// cannot be read. Without a summary policy, they also include a ref
    /// whose commit the repository does not hold. The message then names the
    /// path. Under a summary policy, the probe reads no commit, and a listed
    /// commit that the repository does not hold fails the pull from it, as
    /// for a remote.
    #[non_exhaustive]
    RemoteSkipped {
        /// The name of the remote.
        remote: String,
        /// The text of the failure.
        message: String,
    },
    /// The probe of a remote skipped a ref that the remote lists, because
    /// the name of the ref fails the ref-name rule. An example is
    /// `origin:main`.
    ///
    /// The other refs of the remote stay in the selection. The probe reads
    /// no commit and no timestamp of a skipped ref. A name that the caller
    /// gives passes the ref-name rule before the first request, so the probe
    /// skips a ref only when the caller gives no name.
    #[non_exhaustive]
    RefSkipped {
        /// The name of the remote.
        remote: String,
        /// The name of the ref, as the remote lists it.
        name: String,
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
            CollectionPullEvent::RefSkipped { remote, name } => {
                f.write_str("remote ")?;
                write_escaped(f, remote)?;
                f.write_str(" skipped the ref ")?;
                write_escaped(f, name)?;
                f.write_str(": the name fails the ref-name rule")
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
    /// [`elapsed`](PullStats::elapsed) is the run time of the whole call. A
    /// pull from a local repository adds its import counts, and no fetch
    /// count unless it reads static deltas. [`local`](Self::local) holds the
    /// part of these counts that the pulls from local repositories gave.
    pub stats: PullStats,
    /// The part of [`stats`](Self::stats) that the pulls from local
    /// repositories (`file://` candidates) gave.
    ///
    /// [`elapsed`](PullStats::elapsed) is the sum of the run times of those
    /// pulls. Each count is zero if the pull selected no local repository.
    pub local: PullStats,
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
    /// The signed fetcher of a bucket repository at an `s3://` address, and
    /// its endpoint, which gives the bucket client of each session. The pull
    /// builds the fetcher before its first request.
    #[cfg(feature = "s3")]
    S3(Fetcher, Box<S3Endpoint>),
    /// The path of a local repository, from a `file://` address. The pull
    /// opens the repository in the probe.
    Local(PathBuf),
}

impl Transport {
    /// Returns the transport of `endpoint`, with the request limit
    /// `max_outstanding` of the caller.
    ///
    /// For an HTTP endpoint and an S3 endpoint, the call builds the fetcher.
    /// For an ssh endpoint, it checks the command line of the ssh client. It
    /// sends no request and starts no ssh client.
    async fn new(endpoint: Endpoint, max_outstanding: Option<usize>) -> Result<Transport> {
        let (endpoint, stream) = session_options(endpoint, max_outstanding);
        Ok(match endpoint {
            Endpoint::Http(_) => {
                let PullSession::Http(fetcher) = connect(endpoint, stream).await?.session else {
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
            #[cfg(feature = "s3")]
            Endpoint::S3(s3) => Transport::S3(s3_fetcher(&s3, stream).await?, Box::new(s3)),
            _ => {
                return Err(crate::endpoint::neither_ssh_nor_http(
                    "a read of collection refs",
                ));
            }
        })
    }

    /// Opens a session to the remote.
    ///
    /// The connection to a bucket repository holds a bucket client over the
    /// fetcher of the session. The session of a local repository is the open
    /// repository.
    async fn open(&self) -> Result<Session> {
        match self {
            Transport::Http(fetcher) => {
                Ok(Session::Remote(PullSession::Http(fetcher.clone()).into()))
            }
            Transport::Ssh(endpoint, stream) => connect(Endpoint::clone(endpoint), stream.clone())
                .await
                .map(Session::Remote),
            #[cfg(feature = "s3")]
            Transport::S3(fetcher, s3) => Ok(Session::Remote(Connection {
                session: PullSession::Http(fetcher.clone()),
                bucket: Some(Bucket::from_fetcher(s3, fetcher.clone())),
            })),
            Transport::Local(path) => Repo::open(path).await.map(Session::Local),
        }
    }
}

/// An open session to a remote of a collection pull.
enum Session {
    /// The session to a server, and its bucket client.
    Remote(Connection),
    /// The repository at the `file://` address of a local candidate.
    Local(Repo),
}

/// One ref that a remote lists for the collection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listed {
    name: String,
    commit: Checksum,
    timestamp: u64,
}

/// What the probe of one remote gives if the remote answers. [`find_refs`]
/// gives a `Result<Probed>` for each candidate: this value for a candidate
/// that answers, or the error that skips the candidate.
struct Probed {
    /// The refs of the collection that the remote lists, with names that
    /// pass the ref-name rule.
    listed: Vec<Listed>,
    /// Each name of a ref of the collection that the remote lists and that
    /// fails the ref-name rule, in the listed order. The probe skipped these
    /// refs. [`report_skipped_refs`] takes the list out after the probe, so
    /// the list is empty after the find step.
    skipped: Vec<String>,
    /// The `summary` of a remote, if the probe read the refs from it. `None`
    /// for a local candidate.
    summary: Option<Arc<Vec<u8>>>,
    /// The open session to the remote, for the pull from it.
    session: Session,
}

/// The refs of the collection that a listing, a summary, or the ref files
/// of a local repository give.
#[derive(Debug, Default, PartialEq, Eq)]
struct ListedRefs {
    /// Each ref whose name passes the ref-name rule.
    listed: Vec<Listed>,
    /// Each name that fails the ref-name rule, in the listed order. The
    /// find step skips these refs, and reads no commit and no timestamp of
    /// them.
    skipped: Vec<String>,
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
    /// with [`PullTrust::from_remote`], with [`verify`](PullOptions::verify)
    /// and [`trust_group`](PullOptions::trust_group).
    /// It also builds the fetcher of each HTTP remote and of each remote at
    /// an `s3://` address, which sends no request, and checks the command
    /// line of the ssh client of each ssh remote, which starts no ssh client.
    /// So an error in the config of one remote, for example a TLS file that
    /// does not parse, an empty `send-command`, or an `s3://` remote with no
    /// key pair, stops the pull before the first request. Each pull from a
    /// remote applies the keys of that remote: `gpg-verify`, `sign-verify`,
    /// and their key sources. With `trust_group`, or with the key `trust` of
    /// the remote, the trust group supplies the commit keys.
    ///
    /// A remote whose `pull-url`, or else `url`, has the scheme `file` is a
    /// local repository, and the pull does not call [`resolve_pull`] for it.
    /// "Local repository" below states the rules.
    ///
    /// # Probe
    ///
    /// The pull asks each remote in turn for the commit of each ref. It
    /// opens one session to each remote: an ssh client over ssh, the
    /// fetcher and its connections over HTTP and to an `s3://` address, or
    /// the open repository at a `file://` address. The pull from a selected
    /// remote uses the same session. The pull ends the
    /// session of each other remote after the selection, and an error of
    /// that end has no effect.
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
    /// - A remote at an `s3://` address is a bucket repository, which serves
    ///   no ref listing. The pull sends it no listing request, and reads the
    ///   refs from its `summary` alone, with the S3 client of the bucket, as
    ///   [`Repo::pull`] reads the `summary`, the `summary.sig`, and the
    ///   `config` of a bucket repository. A bucket repository with no
    ///   `summary` fails the probe. The pull takes the commit that the
    ///   summary lists, also when the ref file of the bucket names a newer
    ///   commit.
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
    /// policy refuses, a listed ref with no `ostree.commit.timestamp` of type
    /// `t`, and a bucket repository with no `summary`.
    ///
    /// A listed ref whose name fails the ref-name rule, for example
    /// `origin:main`, is skipped: `on_event` gets a
    /// [`RefSkipped`](CollectionPullEvent::RefSkipped) event, and the other
    /// refs of the remote stay in the selection. The probe reads no commit and
    /// no timestamp of a skipped ref. Each name in
    /// [`refs`](PullOptions::refs) passes the ref-name rule before the first
    /// request, so the probe skips a ref only when `refs` is empty.
    ///
    /// # Access
    ///
    /// A remote that `ostrya serve` serves identifies the client of each
    /// request: by the client certificate of the keys `tls-client-cert-path`
    /// and `tls-client-key-path` of the remote, by the client address, or as
    /// `anonymous`. When `http_headers` of
    /// [`overrides`](PullOptions::overrides) holds an `Authorization` header,
    /// each HTTP request carries the bearer token or the Basic credential of
    /// that header, which gives a `token-sha256` or a `basic-sha256` item.
    /// Over ssh, `ostrya send` identifies the client by its `ssh:NAME` item.
    /// The listing holds a ref when the client group of the item in the
    /// namespace of the ref has `r` on its name. With
    /// `tls-accept-claim=true`, the claims of the certificate for that
    /// namespace replace the rules of the group. The namespace of the own
    /// collection id of the remote is its local namespace. So the local group
    /// of the remote applies, with the `ostrya:ref:` claims and the
    /// `ostrya:collection:ID:` claims of that id.
    ///
    /// So the probe cannot tell a ref that the remote does not hold from a
    /// ref that the client cannot read. When one remote hides a ref, the pull
    /// takes the ref from another remote that lists it. Else the pull fails,
    /// because no remote lists the ref.
    ///
    /// A remote that refuses the client answers the listing request with 401
    /// or 403. The probe then reads the `summary`, by the rule of the status
    /// from 400 to 499, and the remote refuses that request with the same
    /// status. So the pull skips the remote.
    ///
    /// Under a summary policy, the probe reads the summary of the item alone.
    /// That summary holds no ref of a namespace whose group has
    /// `summary=false`, and claims never apply to a summary. A group with
    /// `tls-accept-claim=true` cannot set `summary=true`. So from such a
    /// remote, a client whose right comes from claims, or from a group with
    /// `summary=false`, gets no ref of that namespace. The policy refuses ref
    /// data that no signature covers, so the probe does not read the listing
    /// in place of the summary.
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
    /// transaction. A remote with no selected ref is not asked again. The
    /// pull fetches the dependencies of each commit from the remote of the
    /// commit, as [`Repo::pull`] states in "Dependencies".
    ///
    /// So a failure of a later remote leaves the objects and the refs of the
    /// earlier remotes in place. A failure of a selected remote stops the
    /// whole pull. The pull does not take the ref from the next remote.
    ///
    /// For each pulled commit, the pull makes these checks, and a commit that
    /// fails one fails the pull with [`Error::Pull`]:
    ///
    /// - The `ostree.collection-binding` of the commit must be
    ///   `collection_id`. A commit with no `ostree.collection-binding` key
    ///   fails, unless [`allow_unbound`](CollectionPullOptions::allow_unbound)
    ///   is set. A key whose value is not a string fails always.
    /// - The `ostree.ref-binding` of the commit must hold the ref. A commit
    ///   with no ref binding passes, as in each other pull.
    /// - The timestamp of the commit must be the timestamp that the remote
    ///   listed for the ref.
    ///
    /// The pull makes none of these checks on a dependency.
    ///
    /// # Refs
    ///
    /// The pull writes each ref as the collection ref
    /// `refs/mirrors/<collection_id>/<name>`. It writes no ref under
    /// `refs/remotes/`.
    ///
    /// If the `[core] collection-id` of this repository is `collection_id`,
    /// the pull writes the local ref `refs/heads/<name>`, and it does not
    /// touch `refs/mirrors/<collection_id>/`.
    ///
    /// Delta discovery and
    /// [`TimestampCheck::CurrentRef`](crate::TimestampCheck::CurrentRef) read
    /// the current commit of a ref at the same place, as
    /// [`resolve_ref_tip`](Repo::resolve_ref_tip) reads it.
    ///
    /// # Local repository
    ///
    /// The address of a local repository is `file://` followed by an
    /// absolute path, with the scheme in ASCII letters of either case. The
    /// pull takes the path as written, and decodes no `%` escape. A
    /// `pull-url` with another address wins over a `file://` value of
    /// `url`. The pull ignores the TLS keys, the key `proxy`, and the ssh
    /// keys of the remote. The trust of the remote applies, as for each
    /// remote.
    ///
    /// The probe opens the repository at the path with [`Repo::open`], and
    /// the repository stays open until the pull from it ends. The probe
    /// takes the refs as follows:
    ///
    /// - If the policy of the remote covers the summary, the probe reads the
    ///   `summary` and the `summary.sig` of the repository, verifies the
    ///   summary, and reads the refs from it, as from a remote.
    /// - Otherwise, the probe reads the ref files of the collection with
    ///   [`Repo::list_collection_refs_in`]. So a repository whose
    ///   `[core] collection-id` is `collection_id` gives its `refs/heads`
    ///   refs. The probe reads only the directories that the names can
    ///   reach. It skips each ref whose name fails the ref-name rule, as
    ///   "Probe" states. The timestamp of each other ref is the timestamp of
    ///   the commit that the probe pins. The probe reads each such commit for
    ///   its timestamp, and keeps no bytes of it for the pull.
    ///
    /// The client groups of the repository do not apply, because they govern
    /// `ostrya serve` and `ostrya send` alone. The file permissions are the
    /// access. A directory outside the selection that the probe cannot read
    /// fails nothing. A directory or a ref file inside the selection that the
    /// probe cannot read skips the remote, as each other error of the open
    /// and of the probe does. The message of the event names the path.
    ///
    /// The pull from a selected local repository is a pull of
    /// [`Repo::pull_local`] at the commits that the probe read. It reads no
    /// ref file again. It reads each tip commit from the repository, and
    /// makes the checks of "Pull" and the timestamp check of
    /// [`timestamp_check`](PullOptions::timestamp_check). So a tip commit
    /// whose timestamp changed between the probe and the pull fails the
    /// pull. Under a summary policy, the listed timestamps come from the
    /// verified summary, and the pull reads and checks the `summary` and the
    /// `summary.sig` of the repository again. A listed commit that the
    /// repository does not hold fails the pull.
    ///
    /// If the trust of the remote checks the signatures of the commits or of
    /// the summary, the pull hashes each object that it imports and compares
    /// the result with the name of the object, as with
    /// [`UNTRUSTED`](PullFlags::UNTRUSTED). A signature covers the commit or
    /// the summary alone, and the hash carries the proof to the objects of
    /// the tree. Otherwise the flags of the caller apply: without
    /// [`UNTRUSTED`](PullFlags::UNTRUSTED), the pull links, clones, or copies
    /// an object with no hash, and an object that it writes again in another
    /// form always gets a hash. The counts of the pull go to
    /// [`CollectionPullStats::stats`] as the counts of a local pull: the
    /// import counts, and no fetch count unless it reads static deltas.
    /// [`CollectionPullStats::local`] also gets these counts.
    ///
    /// # Options
    ///
    /// Each field of [`PullOptions`] that [`Repo::pull`] reads applies to
    /// the pull from each selected remote, with these exceptions:
    ///
    /// - [`refs`](PullOptions::refs) selects the refs, as stated above.
    /// - [`overrides`](PullOptions::overrides),
    ///   [`verify`](PullOptions::verify),
    ///   [`trust_group`](PullOptions::trust_group), and
    ///   [`max_outstanding_fetches`](PullOptions::max_outstanding_fetches)
    ///   apply to the probe and the pull of each remote.
    /// - [`progress`](PullOptions::progress) gets the counters of each pull
    ///   from a remote, and no count of the probe. A pull from a local
    ///   repository does not use it.
    /// - [`flags`](PullOptions::flags) of a pull from a local repository
    ///   also hold [`UNTRUSTED`](PullFlags::UNTRUSTED) if the trust of the
    ///   remote checks signatures, as "Local repository" states.
    ///
    /// # Errors
    ///
    /// These errors stop the pull before its first request. The pull writes
    /// no object and no ref:
    ///
    /// - [`Error::InvalidInput`] if `collection_id` fails the collection-id
    ///   rule ([`is_collection_id`](crate::is_collection_id)) or is longer than
    ///   255 bytes.
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
    /// - [`Error::Core`] if `[ex-ostrya] keep-detached-related` of this
    ///   repository is not a boolean.
    /// - The errors of
    ///   [`RepoConfig::generate_composefs`](crate::RepoConfig::generate_composefs)
    ///   for this repository.
    /// - The errors of [`resolve_pull`] and of [`PullTrust::from_remote`],
    ///   for each remote, and the errors of
    ///   [`trust_group`](PullOptions::trust_group).
    /// - For each remote at a `file:` address, [`Error::Pull`] if the
    ///   address does not start with `file://`, names a host (`localhost`
    ///   too), has no path, or holds `%`, `?`, or `#`. Also
    ///   [`Error::InvalidInput`] if [`overrides`](PullOptions::overrides)
    ///   sets a field of another transport, for example a TLS path, a
    ///   header, or a retry count above 0. The message names the field.
    /// - [`Error::Unsupported`] if [`subpaths`](PullOptions::subpaths) is not
    ///   empty and a remote is at a `file://` address.
    /// - For each HTTP remote and each remote at an `s3://` address, the
    ///   errors of [`Repo::pull`] that come from the build of its fetcher:
    ///   [`Error::Unsupported`] for a mirror scheme other than `http` and
    ///   `https` or a refused proxy, and [`Error::Fetch`] for a mirror that is
    ///   not a valid absolute URL, an invalid header, or TLS material that
    ///   does not parse.
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
    /// the checks of each commit above. [`Error::ChecksumMismatch`] comes
    /// from an object of a local repository that does not hash to its name.
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
            allow_unbound,
        } = opts;
        let subpaths = check_collection_pull(collection_id, remotes, &opts)?;
        // The pull reads the rule one time, here. A value that is not a
        // boolean stops the pull before its first request. Each run of each
        // remote takes this value.
        let related = RelatedRule::of(self.config())?;
        // The commit of each transaction reads the key again. This read fails
        // a bad value before the first request.
        self.config().generate_composefs()?;
        let names = first_of_each(opts.refs.iter().map(String::as_str));

        // The endpoint, the trust, and the transport of each remote come
        // before the first request, so an error in the config of one remote
        // stops the pull.
        let mut candidates = Vec::with_capacity(remotes.len());
        // The trust group of the options keeps its commit policy, so the pull
        // reads the key sources of the group one time for all the remotes.
        let mut group = opts.trust_group.as_deref().map(FieldGroup::new);
        for name in first_of_each(remotes.iter().copied()) {
            let trust = TrustScope::Pull(group.as_mut());
            candidates.push(resolve_candidate(self, name, &opts, trust).await?);
        }
        // A local pull copies whole trees.
        if !opts.subpaths.is_empty()
            && let Some(local) = candidates
                .iter()
                .find(|candidate| matches!(candidate.transport, Transport::Local(_)))
        {
            return Err(Error::Unsupported(format!(
                "the pull address of remote '{}' is a local repository, and a pull of \
                 collection refs from a local repository takes no subpath",
                local.name
            )));
        }

        // The pull reports each remote and each ref that it skips before it
        // probes the next remote.
        let found = find_refs(
            &candidates,
            collection_id,
            &names,
            |candidate, probed| match probed {
                Ok(probed) => report_skipped_refs(&mut on_event, candidate, probed),
                Err(e) => {
                    let Some(on_event) = on_event.as_mut() else {
                        return;
                    };
                    let message = match &candidate.transport {
                        Transport::Local(path) => {
                            format!("local repository '{}': {e}", path.display())
                        }
                        _ => e.to_string(),
                    };
                    on_event(CollectionPullEvent::RemoteSkipped {
                        remote: candidate.name.to_owned(),
                        message,
                    });
                }
            },
        )
        .await;
        // The session and the summary of each remote that answered, by the
        // position of the remote.
        let mut answers = Vec::with_capacity(found.len());
        let mut sessions = Vec::with_capacity(found.len());
        let mut summaries = Vec::with_capacity(found.len());
        for probed in found {
            match probed {
                Ok(probed) => {
                    answers.push(Some(probed.listed));
                    sessions.push(Some(probed.session));
                    summaries.push(probed.summary);
                }
                Err(_) => {
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

        let place = RefPlace::of_collection(self, collection_id);
        let candidate_names: Vec<&str> = candidates.iter().map(|c| c.name).collect();
        let mut stats = PullStats::default();
        let mut local = PullStats::default();
        for (index, candidate) in candidates.into_iter().enumerate() {
            let Some(session) = sessions[index].take() else {
                continue;
            };
            let from_local = matches!(session, Session::Local(_));
            let mine: Vec<&Listed> = selected
                .iter()
                .filter(|selected| selected.remote == index)
                .map(|selected| &selected.listed)
                .collect();
            let targets: Vec<(String, Checksum)> =
                mine.iter().map(|l| (l.name.clone(), l.commit)).collect();
            let listed: HashMap<String, u64> =
                mine.iter().map(|l| (l.name.clone(), l.timestamp)).collect();
            let summary = summaries[index].take();
            // The trust and the session hold what these fields gave.
            let run = PullOptions {
                refs: targets.iter().map(|(name, _)| name.clone()).collect(),
                verify: PullVerify::default(),
                trust_group: None,
                max_outstanding_fetches: None,
                overrides: EndpointOverrides::default(),
                ..opts.clone()
            };
            let pinned = Pinned {
                targets,
                listed,
                collection: collection_id,
                allow_unbound,
                place,
                summary: Mutex::new(summary),
            };
            let pulled = match session {
                Session::Remote(connection) => {
                    self.run_session(
                        connection,
                        candidate.trust,
                        related,
                        run,
                        Wanted::Pinned(&pinned),
                        subpaths.clone(),
                        None,
                        Instant::now(),
                    )
                    .await
                }
                // The pull reads each tip commit from the source again, and
                // checks it against the listed timestamp. Under a summary
                // policy, it also reads and checks the summary of the source
                // again.
                Session::Local(src) => {
                    self.pull_local_candidate(&src, candidate.trust, related, run, &pinned)
                        .await
                }
            };
            match pulled {
                Ok(pulled) => {
                    add_stats(&mut stats, &pulled);
                    if from_local {
                        add_stats(&mut local, &pulled);
                        local.elapsed += pulled.elapsed;
                    }
                }
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
        Ok(CollectionPullStats { refs, stats, local })
    }

    /// Lists the refs of the collection `collection_id` that the remote
    /// `remote` serves, as
    /// [`remote_list_collection_refs_with`](Repo::remote_list_collection_refs_with)
    /// does with the default overrides and no event callback.
    ///
    /// The default overrides do not set `allow_cleartext_credentials`, so the
    /// call refuses an `http://` S3 endpoint.
    ///
    /// # Errors
    ///
    /// The errors of
    /// [`remote_list_collection_refs_with`](Repo::remote_list_collection_refs_with).
    pub async fn remote_list_collection_refs(
        &self,
        remote: &str,
        collection_id: &str,
        names: &[&str],
    ) -> Result<Vec<(String, Checksum)>> {
        self.remote_list_collection_refs_with(
            remote,
            collection_id,
            names,
            EndpointOverrides::default(),
            None,
        )
        .await
    }

    /// Lists the refs of the collection `collection_id` that the remote
    /// `remote` serves, with the overrides `overrides` of the caller.
    ///
    /// `remote` is a `[remote "<name>"]` section of the config of this
    /// repository. The call does not read the `collection-id` key of the
    /// remote. `names` holds exact ref names. An empty slice selects each ref
    /// of the collection. A name that occurs again adds nothing.
    ///
    /// The result holds the name and the commit of each ref that the remote
    /// lists, sorted byte-wise by name. A name that the remote does not hold
    /// is absent from the result. The call writes nothing to this repository,
    /// and checks no commit signature.
    ///
    /// The call skips a listed ref whose name fails the ref-name rule, for
    /// example `origin:main`, and reads no commit of it. The ref is absent
    /// from the result, and `on_event`, if it is set, gets a
    /// [`RefSkipped`](CollectionPullEvent::RefSkipped) event for it, in the
    /// listed order, before the call returns. Each name in `names` passes the
    /// ref-name rule before the first request, so the call skips a ref only
    /// when `names` is empty. The call gives `on_event` no other event: the
    /// error of the probe is the error of the call. For an ssh remote, the
    /// call can fail after it gave the events, when the end of the session
    /// fails.
    ///
    /// # Address and trust
    ///
    /// The call resolves the remote as [`Repo::pull_collection`] resolves a
    /// remote, before its first request. A remote whose `pull-url`, or else
    /// `url`, has the scheme `file` is a local repository, as "Local
    /// repository" of [`Repo::pull_collection`] states. For each other
    /// remote, the call resolves the endpoint with [`resolve_pull`] and
    /// `overrides`. So over HTTP, the TLS keys and the key `proxy` of the
    /// remote apply. Over ssh, the ssh command and the send command of the
    /// remote apply. For an `s3://` address, the S3 keys of the remote apply,
    /// and `allow_cleartext_credentials` permits an `http://` S3 endpoint.
    /// The trust of the remote is its summary policy alone: the keys
    /// `gpg-verify-summary` and `sign-verify-summary` of the remote and the
    /// key sources that they read, as [`PullTrust::from_remote`] reads them.
    /// The call checks no commit signature, so it does not read `gpg-verify`,
    /// `sign-verify`, the key `trust`, or a trust group.
    ///
    /// # Probe
    ///
    /// The call reads the refs as the probe of [`Repo::pull_collection`]
    /// does, with its one remote, in one session:
    ///
    /// - Under a summary policy (`gpg-verify-summary`,
    ///   `sign-verify-summary`), the call reads the `summary` and the
    ///   `summary.sig` of the remote, and verifies the summary before it
    ///   reads the refs from it. It does not read the ref listing.
    /// - Otherwise, the call reads the ref listing, in one or more requests.
    ///   With no names, it asks for the local refs of the remote when the
    ///   listing states `collection_id` as the collection id of the remote.
    /// - If the remote serves no ref listing, the call reads the `summary`.
    ///   An HTTP remote serves no listing when it answers with a status from
    ///   400 to 499. A remote with no listing and no summary gives an empty
    ///   vector.
    /// - A bucket repository at an `s3://` address gives the refs of its
    ///   `summary` alone.
    /// - A local repository gives the refs of its ref files, or of its
    ///   verified summary under a summary policy. Without a summary policy,
    ///   the call reads the tip commit of each ref for its timestamp.
    ///
    /// A commit that the source does not hold fails the call when the source
    /// reads the commit. The ref files of a local repository give
    /// [`Error::ObjectNotFound`]. `ostrya serve` answers the listing request
    /// with the status 500, and the call returns [`Error::HttpStatus`] after
    /// the retries of the request. `ostrya send` answers with an error, and
    /// the call returns [`Error::Remote`]. A ref that the call reads from a
    /// summary gives the commit that the summary lists.
    ///
    /// The call ends the session before it returns.
    ///
    /// # Access
    ///
    /// A remote that `ostrya serve` serves identifies the client by the client
    /// certificate of the keys `tls-client-cert-path` and
    /// `tls-client-key-path` of the remote, by the client address, or as
    /// `anonymous`. When `http_headers` of `overrides` holds an
    /// `Authorization` header, each HTTP request carries the bearer token or
    /// the Basic credential of that header, which gives a `token-sha256` or a
    /// `basic-sha256` item. Over ssh, `ostrya send` identifies the client by
    /// its `ssh:NAME` item.
    /// The result holds a ref when the client group of the item in the
    /// namespace of the ref has `r` on its name. With
    /// `tls-accept-claim=true`, the claims of the certificate for that
    /// namespace replace the rules of the group. The namespace of the own
    /// collection id of the remote is its local namespace. So the local group
    /// of the remote applies, with the `ostrya:ref:` claims and the
    /// `ostrya:collection:ID:` claims of that id. So a ref that the client
    /// cannot read is absent from the result, as a ref that the remote does
    /// not hold is.
    ///
    /// A remote that refuses the client answers the listing request and the
    /// `summary` request with 401 or 403, and the call returns
    /// [`Error::HttpStatus`].
    ///
    /// Under a summary policy, the call reads the summary of the item alone.
    /// That summary holds no ref of a namespace whose group has
    /// `summary=false`, and claims never apply to a summary. So from such a
    /// remote, a client whose right comes from claims, or from a group with
    /// `summary=false`, gets no ref of that namespace.
    ///
    /// A local repository applies no client group. The file permissions are
    /// the access.
    ///
    /// # Errors
    ///
    /// These errors come before the first request:
    ///
    /// - [`Error::InvalidInput`] if `collection_id` fails the collection-id
    ///   rule ([`is_collection_id`](crate::is_collection_id)) or is longer than
    ///   255 bytes.
    /// - [`Error::InvalidRefspec`] if a name in `names` is not a valid ref
    ///   name.
    /// - [`Error::InvalidInput`] if a name in `names` does not fit in a ref
    ///   listing request alone, as for [`Repo::pull_collection`].
    /// - [`Error::InvalidInput`] if `overrides` holds a `url`.
    /// - The errors of [`resolve_pull`].
    /// - The errors of [`PullTrust::from_remote`] that come from the summary
    ///   policy:
    ///   - [`Error::Core`] if `gpg-verify-summary` is not a boolean, if a
    ///     value holds a malformed escape sequence, or if a sign-api key is
    ///     not valid base64.
    ///   - [`Error::Signature`] if `sign-verify-summary` names an engine that
    ///     has no trusted key, if `sign-verify-summary=true` finds no engine
    ///     with a trusted key, or if a keyring or a key file of the policy
    ///     cannot be read or is not valid for its engine.
    ///   - [`Error::Unsupported`] if the policy asks for an engine that this
    ///     build does not verify with.
    ///   - [`Error::Io`] if a directory of keys cannot be listed.
    /// - For a remote at a `file:` address, the errors of the address and of
    ///   `overrides` that [`Repo::pull_collection`] states.
    /// - For an HTTP remote and a remote at an `s3://` address, the errors of
    ///   the build of its fetcher that [`Repo::pull_collection`] states. For
    ///   an ssh remote, the errors of its ssh command and of its send command.
    ///
    /// These errors come from the probe:
    ///
    /// - [`Error::HttpStatus`] if the remote refuses the client, or if a
    ///   request gets a status from 500 to 599 after its retries.
    /// - [`Error::Fetch`] and the other errors of an HTTP request that fails.
    /// - [`Error::Remote`] if the ssh session fails, also at its end, or if
    ///   a read from a bucket repository fails.
    /// - [`Error::Signature`] if the summary fails the policy, or if the
    ///   remote has no `summary` or no `summary.sig` under the policy.
    /// - [`Error::Pull`] if a bucket repository has no `summary` and no
    ///   summary policy applies.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if the listing or the
    ///   summary does not parse, and [`Error::InvalidFormat`] if a listed ref
    ///   has no `ostree.commit.timestamp` of type `t`.
    /// - For a local repository, the errors of [`Repo::open`],
    ///   [`Error::Io`] if a directory or a ref file that the names reach
    ///   cannot be read, and, without a summary policy,
    ///   [`Error::ObjectNotFound`] if the repository does not hold the commit
    ///   of a ref.
    ///
    /// # Examples
    ///
    /// List each ref of a collection on one remote, with a warning for each
    /// skipped ref:
    ///
    /// ```no_run
    /// # async fn run() -> ostrya::Result<()> {
    /// let repo = ostrya::Repo::open("/srv/repo".as_ref()).await?;
    /// let refs = repo
    ///     .remote_list_collection_refs_with(
    ///         "mirror1",
    ///         "org.example.Os",
    ///         &[],
    ///         ostrya::endpoint::EndpointOverrides::default(),
    ///         Some(Box::new(|event| eprintln!("warning: {event}"))),
    ///     )
    ///     .await?;
    /// for (name, commit) in &refs {
    ///     println!("{name} {commit}");
    /// }
    /// # Ok(()) }
    /// ```
    pub async fn remote_list_collection_refs_with(
        &self,
        remote: &str,
        collection_id: &str,
        names: &[&str],
        overrides: EndpointOverrides,
        mut on_event: Option<Box<dyn FnMut(CollectionPullEvent) + Send>>,
    ) -> Result<Vec<(String, Checksum)>> {
        check_collection_id(collection_id)?;
        check_ref_names(collection_id, names)?;
        if overrides.url.is_some() {
            return Err(Error::InvalidInput(
                "a listing of collection refs reads the address of the remote from the \
                 config, and takes no url override"
                    .into(),
            ));
        }
        let names = first_of_each(names.iter().copied());
        let opts = PullOptions {
            overrides,
            ..PullOptions::default()
        };
        let candidate = resolve_candidate(self, remote, &opts, TrustScope::Summary).await?;
        let Some(found) = find_refs(
            std::slice::from_ref(&candidate),
            collection_id,
            &names,
            |candidate, probed| {
                if let Ok(probed) = probed {
                    report_skipped_refs(&mut on_event, candidate, probed);
                }
            },
        )
        .await
        .pop() else {
            unreachable!("the find step gives one result for each candidate");
        };
        // The summary goes before the end of the session, which waits for the
        // ssh client.
        let Probed {
            listed, session, ..
        } = found?;
        // A local repository has no session to end.
        if let Session::Remote(connection) = session {
            RemoteSource::new(connection, Vec::new())
                .finish(Ok(()))
                .await?;
        }
        let mut refs: Vec<(String, Checksum)> = listed
            .into_iter()
            .map(|listed| (listed.name, listed.commit))
            .collect();
        refs.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        Ok(refs)
    }

    /// Pulls the selected refs `pinned` of a local candidate of
    /// [`Repo::pull_collection`] from the repository `src` that its probe
    /// opened, under the trust `trust` of the candidate, with the rule
    /// `related` and the options `run`.
    ///
    /// If `trust` checks the signatures of the commits or of the summary, the
    /// call adds [`UNTRUSTED`](PullFlags::UNTRUSTED) to the flags. A
    /// signature covers the commit or the checksum of the summary alone, and
    /// the hash of each imported object against its name carries the proof
    /// to the objects of the tree.
    async fn pull_local_candidate(
        &self,
        src: &Repo,
        trust: PullTrust,
        related: RelatedRule,
        run: PullOptions,
        pinned: &Pinned<'_>,
    ) -> Result<PullStats> {
        let started = Instant::now();
        let flags = if trust.checks_signatures() {
            run.flags | PullFlags::UNTRUSTED
        } else {
            run.flags
        };
        let run = PullOptions { flags, ..run };
        self.pull_local_from(
            src,
            trust,
            related,
            run,
            LocalWanted::Pinned(pinned),
            None,
            started,
        )
        .await
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
/// position. The pull reads nothing more from a remote with no selected
/// ref, so its summary does not stay in memory for the rest of the pull.
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
/// no effect, and the call drops it. A local repository has no session to
/// end, and the call drops its handle.
async fn end_sessions(sessions: impl IntoIterator<Item = Session>) {
    for session in sessions {
        if let Session::Remote(connection) = session {
            let _ = connection.session.finish().await;
        }
    }
}

/// The trust that [`resolve_candidate`] reads for a remote.
enum TrustScope<'g, 'f> {
    /// The trust of a pull, with the trust group of the options, which
    /// [`PullTrust::for_pull`] reads.
    Pull(Option<&'g mut FieldGroup<'f>>),
    /// The summary policy of the remote alone, which
    /// [`PullTrust::for_summary`] reads.
    Summary,
}

/// Resolves the remote `name` of `repo` to a candidate of a collection pull,
/// with the options `opts` and the trust that `trust` gives.
///
/// The call resolves the address, then the trust, then the transport. A
/// `file://` address gives a local candidate. Each other address goes
/// through [`resolve_pull`] and [`Transport::new`]. The call sends no
/// request and opens no repository.
async fn resolve_candidate<'a>(
    repo: &Repo,
    name: &'a str,
    opts: &PullOptions,
    trust: TrustScope<'_, '_>,
) -> Result<Candidate<'a>> {
    /// The address of a candidate.
    enum Address {
        Local(PathBuf),
        Endpoint(Box<Endpoint>),
    }
    let address = match local_pull_path(repo.config(), name, &opts.overrides)? {
        Some(path) => Address::Local(path),
        None => Address::Endpoint(Box::new(
            resolve_pull(Some(repo.config()), name, opts.overrides.clone()).await?,
        )),
    };
    let trust = match trust {
        TrustScope::Pull(group) => PullTrust::for_pull(repo, name, &opts.verify, group).await?,
        TrustScope::Summary => PullTrust::for_summary(repo, name).await?,
    };
    let transport = match address {
        Address::Local(path) => Transport::Local(path),
        Address::Endpoint(endpoint) => {
            Transport::new(*endpoint, opts.max_outstanding_fetches).await?
        }
    };
    Ok(Candidate {
        name,
        transport,
        trust,
    })
}

/// Makes the checks of [`Repo::pull_collection`] that read the arguments
/// alone, in the order of its `# Errors`, and returns the parsed subpaths.
fn check_collection_pull(
    collection_id: &str,
    remotes: &[&str],
    opts: &PullOptions,
) -> Result<Option<Subpaths>> {
    check_collection_id(collection_id)?;
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
    check_ref_names(collection_id, &opts.refs)?;
    Ok(subpaths)
}

/// Checks the collection id `collection_id` of a pull or a listing of
/// collection refs.
///
/// # Errors
///
/// - [`Error::InvalidInput`] if `collection_id` fails
///   [`is_valid_collection_id`]: the collection-id rule or the length limit.
fn check_collection_id(collection_id: &str) -> Result<()> {
    if !is_valid_collection_id(collection_id) {
        return Err(Error::InvalidInput(format!(
            "invalid collection id: {collection_id}"
        )));
    }
    Ok(())
}

/// Checks the ref names `names` of a pull or a listing of the collection
/// `collection_id`: first the ref-name rule of each name, then the size of
/// each name in a ref listing request.
///
/// # Errors
///
/// - [`Error::InvalidRefspec`] if a name is not a valid ref name.
/// - [`Error::InvalidInput`] if a ref listing request cannot hold a name
///   alone ([`check_listing_name`]).
fn check_ref_names<S: AsRef<str>>(collection_id: &str, names: &[S]) -> Result<()> {
    for name in names {
        check_ref_path(name.as_ref())?;
    }
    for name in names {
        check_listing_name(collection_id, name.as_ref())?;
    }
    Ok(())
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
/// the probe succeeds, it gives the session back for the pull. The session
/// of a local candidate is the open repository at its `file://` address.
///
/// [`find_refs`] calls the probe for each candidate.
async fn probe(candidate: &Candidate<'_>, id: &str, names: &[&str]) -> Result<Probed> {
    let connection = match candidate.transport.open().await? {
        Session::Remote(connection) => connection,
        Session::Local(src) => {
            let verification = Verification::from_trust(candidate.trust.clone());
            let ListedRefs { listed, skipped } =
                probe_local(&src, &verification, id, names).await?;
            return Ok(Probed {
                listed,
                skipped,
                summary: None,
                session: Session::Local(src),
            });
        }
    };
    let http = matches!(connection.session, PullSession::Http(_));
    // The probe reads files that a pull reads before its count starts, so it
    // counts no byte.
    let source = RemoteSource::new(connection, Vec::new());
    let verification = Verification::from_trust(candidate.trust.clone());
    match probe_source(&source, &verification, id, names, http).await {
        Ok((ListedRefs { listed, skipped }, summary)) => Ok(Probed {
            listed,
            skipped,
            summary,
            session: Session::Remote(source.into_connection()),
        }),
        Err(e) => source.finish(Err(e)).await,
    }
}

/// The find step of a collection pull: probes each of `candidates` for the
/// refs of `names` in the collection `id`, or for each ref of the collection
/// if `names` is empty.
///
/// The step probes the candidates one at a time, in their order, through
/// [`probe`]. After each probe, and before the next one, it calls
/// `on_probed` with the candidate and the result of its probe. `on_probed`
/// can change the result, for example to take the skipped names out of it.
///
/// The result holds the result of each candidate, at the position of the
/// candidate: the [`Probed`] of a candidate that answered, or the error that
/// skips the candidate.
async fn find_refs(
    candidates: &[Candidate<'_>],
    id: &str,
    names: &[&str],
    mut on_probed: impl FnMut(&Candidate<'_>, &mut Result<Probed>),
) -> Vec<Result<Probed>> {
    let mut found = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let mut probed = Box::pin(probe(candidate, id, names)).await;
        on_probed(candidate, &mut probed);
        found.push(probed);
    }
    found
}

/// Takes the skipped names out of the probe `probed` of `candidate`, and
/// gives `on_event` a [`RefSkipped`](CollectionPullEvent::RefSkipped) event
/// for each of them, in the listed order.
///
/// Without `on_event`, the function drops the names. So the names do not
/// stay in memory while the find step probes the next candidate.
fn report_skipped_refs(
    on_event: &mut Option<Box<dyn FnMut(CollectionPullEvent) + Send>>,
    candidate: &Candidate<'_>,
    probed: &mut Probed,
) {
    let skipped = std::mem::take(&mut probed.skipped);
    let Some(on_event) = on_event.as_mut() else {
        return;
    };
    for name in skipped {
        on_event(CollectionPullEvent::RefSkipped {
            remote: candidate.name.to_owned(),
            name,
        });
    }
}

/// The refs and the skipped names that a probe read, and the `summary` if
/// the refs come from it.
type Refs = (ListedRefs, Option<Arc<Vec<u8>>>);

/// Reads the refs of `names` in the collection `id` from the local
/// repository `src`, or each ref of the collection if `names` is empty.
///
/// If `verification` checks the summary, the refs come from the `summary`
/// of `src`, after the check of the summary and its `summary.sig`, as from a
/// remote. [`read_checked_local_summary`] reads these files under the size
/// cap of a summary. The probe drops the bytes of the summary after the parse
/// of the refs.
///
/// Otherwise the refs come from the ref files of `src`, through
/// [`Repo::list_collection_refs_in`]. So the collection id of `src` puts its
/// `refs/heads` refs in the collection, and the probe reads only the
/// directories that the names can reach. The probe puts each ref whose name
/// fails the ref-name rule in the skipped names before it reads a commit. The
/// timestamp of each other ref is the timestamp of its commit in `src`. The
/// probe reads each commit one time, on the blocking pool, under the size cap
/// of a metadata object, and drops its bytes before it reads the next commit.
///
/// The result holds the refs and the skipped names alone.
///
/// # Errors
///
/// - [`Error::Signature`] if the summary fails the policy, or if `src` has
///   no `summary` or no `summary.sig` under the policy.
/// - [`Error::InvalidFormat`] if the `summary` or the `summary.sig` of `src`
///   is not a regular file or is larger than the size cap of a summary, or if
///   a ref of the summary has no `ostree.commit.timestamp` of type `t`.
/// - [`Error::Core`] or [`Error::InvalidFormat`] if the summary does not
///   parse.
/// - [`Error::ObjectNotFound`] if `src` does not hold the commit of a ref.
/// - [`Error::Io`] if a directory or a ref file that the names reach cannot
///   be read, and the errors of the read of a ref file or a commit.
async fn probe_local(
    src: &Repo,
    verification: &Verification,
    id: &str,
    names: &[&str],
) -> Result<ListedRefs> {
    if verification.checks_summary() {
        let Some(bytes) = read_checked_local_summary(src, verification, false).await? else {
            unreachable!("the summary check needs a summary");
        };
        let (_, refs) = parse_refs(bytes, id, names).await?;
        return Ok(refs);
    }
    let refs = src
        .list_collection_refs_in(id, &RefSelector::parse(names.iter().copied())?)
        .await?;
    let (refs, invalid): (Vec<_>, Vec<_>) =
        refs.into_iter().partition(|(name, _)| is_ref_path(name));
    let skipped = invalid.into_iter().map(|(name, _)| name).collect();
    let src = src.clone();
    let listed = ostrya_rt::unblock(move || {
        let mut timestamps: HashMap<Checksum, u64> = HashMap::new();
        refs.into_iter()
            .map(|(name, commit)| {
                let timestamp = match timestamps.entry(commit) {
                    Entry::Occupied(known) => *known.get(),
                    Entry::Vacant(slot) => {
                        let bytes = src.load_object_bytes_blocking(ObjectType::Commit, &commit)?;
                        *slot.insert(Commit::parse_timestamp(&bytes)?)
                    }
                };
                Ok(Listed {
                    name,
                    commit,
                    timestamp,
                })
            })
            .collect::<Result<Vec<Listed>>>()
    })
    .await?;
    Ok(ListedRefs { listed, skipped })
}

/// Reads the refs of `names` in the collection `id` from `source`, or each
/// ref of the collection if `names` is empty.
///
/// If `verification` checks the summary, the refs come from the summary,
/// after its check. A bucket repository serves no ref listing, so its refs
/// come from its summary. Otherwise they come from the ref listing, or from
/// the summary of a remote with no ref listing. `http` applies the byte limit
/// of an HTTP request to the listing requests.
async fn probe_source(
    source: &RemoteSource,
    verification: &Verification,
    id: &str,
    names: &[&str],
    http: bool,
) -> Result<Refs> {
    // No signature covers the ref listing. So under a policy that covers the
    // summary, the summary alone tells the refs. A bucket repository serves
    // no ref listing.
    if verification.checks_summary() || source.has_bucket() {
        return summary_refs(source, verification, id, names).await;
    }
    if names.is_empty() {
        return every_ref(source, verification, id).await;
    }
    let mut listed = ListedRefs::default();
    for chunk in listing_chunks(id, names, http) {
        let refs = RefSelector::parse(chunk.iter().copied())?;
        let entries: Vec<String> = chunk.iter().map(|name| format!("{id}/{name}")).collect();
        let collections = RefSelector::parse(entries.iter().map(String::as_str))?;
        let Some(bytes) = read_listing(source, &refs, Some(&collections)).await? else {
            return summary_refs(source, verification, id, names).await;
        };
        let (_, parsed) = parse_refs(Arc::new(bytes), id, chunk).await?;
        listed.listed.extend(parsed.listed);
        listed.skipped.extend(parsed.skipped);
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
/// collection ref. So a remote of another collection sends no local ref. The
/// skipped names come from the listing of the refs that the call returns.
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
/// `summary` alone. If no policy applies to its summary, a remote with no
/// summary lists no ref. A bucket repository with no summary fails the call,
/// because its summary is the one source of its refs.
async fn summary_refs(
    source: &RemoteSource,
    verification: &Verification,
    id: &str,
    names: &[&str],
) -> Result<Refs> {
    let summary = if verification.checks_summary() {
        let (summary, signature) = source.summary_files().await?;
        let summary = summary.map(Arc::new);
        verification
            .check_summary(summary.as_ref(), signature)
            .await?;
        summary
    } else {
        source.read_root(SUMMARY_FILE).await?.map(Arc::new)
    };
    let Some(bytes) = summary else {
        if source.has_bucket() {
            return Err(Error::Pull(
                "the bucket repository has no summary, and the summary is the one source of \
                 the refs of a bucket repository"
                    .into(),
            ));
        }
        return Ok((ListedRefs::default(), None));
    };
    let (_, listed) = parse_refs(Arc::clone(&bytes), id, names).await?;
    Ok((listed, Some(bytes)))
}

/// Parses the listing or the summary `bytes`, and returns the refs of the
/// collection `id` that `names` names, or each ref of the collection if
/// `names` is empty, as [`collection_refs`] returns them.
///
/// The result also tells if the bytes state `id` as the collection id of the
/// remote. A summary can be as large as its read cap, so the parse runs on
/// the blocking pool.
async fn parse_refs(bytes: Arc<Vec<u8>>, id: &str, names: &[&str]) -> Result<(bool, ListedRefs)> {
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
/// The call puts each name that fails the ref-name rule in the skipped names,
/// one time, and reads no timestamp of its ref.
///
/// # Errors
///
/// - [`Error::Core`] or [`Error::InvalidFormat`] if the bytes do not parse,
///   or if the collection map is malformed.
/// - [`Error::InvalidFormat`] if a ref with a valid name has no
///   `ostree.commit.timestamp` of type `t`.
fn collection_refs(
    bytes: &[u8],
    id: &str,
    wanted: Option<&HashSet<String>>,
) -> Result<(bool, ListedRefs)> {
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
    let mut out = ListedRefs::default();
    for entry in &entries {
        if wanted.is_some_and(|wanted| !wanted.contains(&entry.name))
            || !seen.insert(entry.name.as_str())
        {
            continue;
        }
        if !is_ref_path(&entry.name) {
            out.skipped.push(entry.name.clone());
            continue;
        }
        out.listed.push(Listed {
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

/// A compile-time check that the futures of a collection pull and of a
/// listing of collection refs are `Send`, and that the result of a pull is
/// `Send` and `Sync`.
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
    let _ = |repo: &Repo| {
        assert_send(&repo.remote_list_collection_refs("origin", "org.example.Os", &[]))
    };
    let _ = |repo: &Repo| {
        assert_send(&repo.remote_list_collection_refs_with(
            "origin",
            "org.example.Os",
            &[],
            EndpointOverrides::default(),
            None,
        ))
    };
    assert_send_sync::<CollectionPullStats>();
    assert_send_sync::<CollectionPullEvent>();
};

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ostrya_core::{Type, to_bytes};

    use super::*;
    use crate::fetch::FetcherOptions;

    /// The transport of an S3 endpoint builds its fetcher and connects to no
    /// server. Each session that it opens holds a bucket client.
    #[cfg(feature = "s3")]
    #[test]
    fn the_transport_of_an_s3_endpoint_sends_no_request() {
        use crate::remote::s3::{Address, Credentials, Location, S3Endpoint};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let location = Location::new(
            Address::parse("s3://bkt/repo").unwrap(),
            "us-east-1",
            Some(&url),
            None,
        )
        .unwrap();
        let credentials =
            Credentials::new("AKIDEXAMPLE".into(), "SECRETEXAMPLE".into(), None).unwrap();
        let mut s3 = S3Endpoint::new(location, credentials);
        s3.http.allow_cleartext_credentials = true;
        s3.http.proxy = crate::fetch::Proxy::None;
        ostrya_rt::block_on(async {
            let transport = Transport::new(Endpoint::S3(s3), None).await.unwrap();
            assert!(matches!(transport, Transport::S3(..)));
            let Session::Remote(connection) = transport.open().await.unwrap() else {
                panic!("an S3 transport opens a remote session");
            };
            assert!(matches!(connection.session, PullSession::Http(_)));
            assert!(connection.bucket.is_some());
        });
        assert_eq!(
            listener.accept().map(drop).map_err(|e| e.kind()),
            Err(std::io::ErrorKind::WouldBlock),
            "the transport connects to no server"
        );
    }

    /// A pull of collection refs resolves a remote at an `s3://` address,
    /// and so applies the rules of the S3 endpoint before its first request.
    /// The endpoint of the remote here is `http://`, and the pull does not
    /// allow cleartext credentials. So the pull fails with
    /// [`Error::InvalidInput`] and connects to no server, whatever the AWS
    /// environment and files hold: with no key pair, and with a key pair.
    #[cfg(feature = "s3")]
    #[test]
    fn a_collection_pull_resolves_an_s3_remote() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "ostrya-collection-s3-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ostrya_rt::block_on(async {
            drop(
                Repo::create(&dir, crate::CreateOptions::new(crate::RepoMode::Archive))
                    .await
                    .unwrap(),
            );
            let mut config = std::fs::read_to_string(dir.join("config")).unwrap();
            config.push_str(&format!(
                "\n[remote \"bkt\"]\npull-url=s3://bkt/repo\ns3-endpoint=http://{}\n",
                listener.local_addr().unwrap()
            ));
            std::fs::write(dir.join("config"), config).unwrap();
            let repo = Repo::open(&dir).await.unwrap();
            let mut opts = CollectionPullOptions::default();
            opts.pull.refs = vec!["exampleos/stable".to_owned()];
            match repo.pull_collection("org.example.Os", &["bkt"], opts).await {
                Err(Error::InvalidInput(_)) => {}
                Err(e) => panic!("{e:?}"),
                Ok(_) => panic!("a collection pull over a refused endpoint"),
            }
        });
        assert_eq!(
            listener.accept().map(drop).map_err(|e| e.kind()),
            Err(std::io::ErrorKind::WouldBlock),
            "the refusal connects to no server"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        assert!(refs.0);
        assert_eq!(
            refs.1.listed,
            [listed("os/stable", 1, 10), listed("os/next", 2, 20)]
        );
        assert!(refs.1.skipped.is_empty());
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
        assert_eq!(
            refs,
            (
                false,
                ListedRefs {
                    listed: vec![listed("os/stable", 3, 30)],
                    skipped: Vec::new(),
                }
            )
        );
        // A summary with no collection id and no map entry lists nothing.
        let s = summary(&[("os/stable", 1, 10)], &[], None);
        assert_eq!(
            collection_refs(&s, "org.example.Os", None).unwrap(),
            (false, ListedRefs::default())
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

    /// A name that fails the ref-name rule goes to the skipped names one
    /// time, in the listed order, and the other refs stay. The read takes no
    /// timestamp of a skipped ref, so a skipped ref with no timestamp fails
    /// nothing. This is true in field 0 and in the collection map.
    #[test]
    fn a_name_that_fails_the_ref_name_rule_is_skipped() {
        let mut field0 = ref_values(&[
            ("origin:main", 1, 10),
            ("os/stable", 2, 20),
            ("origin:main", 3, 30),
        ]);
        field0.push(ref_value("bad name", 4, Value::Array(Vec::new())));
        let own = summary_of(field0, &[], Some("org.example.Os"));
        let expected = ListedRefs {
            listed: vec![listed("os/stable", 2, 20)],
            skipped: vec!["origin:main".to_owned(), "bad name".to_owned()],
        };
        assert_eq!(
            collection_refs(&own, "org.example.Os", None).unwrap(),
            (true, expected)
        );

        let map = summary(
            &[],
            &[("org.example.Os", &[("os/next", 5, 50), ("a/../b", 6, 60)])],
            None,
        );
        let expected = ListedRefs {
            listed: vec![listed("os/next", 5, 50)],
            skipped: vec!["a/../b".to_owned()],
        };
        assert_eq!(
            collection_refs(&map, "org.example.Os", None).unwrap(),
            (false, expected)
        );
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

    /// The text of a ref skip event names the remote and the ref, and
    /// escapes each control character.
    #[test]
    fn the_ref_skip_event_escapes_control_characters() {
        let event = CollectionPullEvent::RefSkipped {
            remote: "mir\tror".to_owned(),
            name: "origin:main\n".to_owned(),
        };
        assert_eq!(
            event.to_string(),
            "remote mir\\tror skipped the ref origin:main\\n: the name fails the ref-name rule"
        );
    }

    /// The collection of the local tests.
    const LOCAL_ID: &str = "org.example.Os";
    /// The base64 of a 64-byte ed25519 secret key (seed, then public key).
    const SECRET_B64: &str =
        "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
    /// The matching 32-byte ed25519 public key.
    const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

    /// The ed25519 key [`PUBLIC_B64`] as a trusted set.
    fn ed25519_keys() -> crate::verify::TrustedKeys {
        use crate::sign::{Ed25519Verifier, Verifier};
        let verifier = Ed25519Verifier::new(
            [ostrya_core::base64::decode(PUBLIC_B64).unwrap()],
            Vec::<Vec<u8>>::new(),
        )
        .unwrap();
        crate::verify::TrustedKeys::new(vec![Arc::new(verifier) as Arc<dyn Verifier>]).unwrap()
    }

    /// The signer of the key [`SECRET_B64`].
    fn ed25519_signer() -> crate::sign::Ed25519Signer {
        crate::sign::Ed25519Signer::from_base64(SECRET_B64).unwrap()
    }

    /// A scratch directory that the value removes when it drops.
    struct Scratch {
        root: PathBuf,
    }

    impl Scratch {
        fn new() -> Scratch {
            let root = std::env::temp_dir().join(format!(
                "ostrya-collection-local-{}-{}",
                std::process::id(),
                crate::write::unique()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Scratch { root }
        }

        /// Creates an archive repository at `name` in the directory.
        async fn create(&self, name: &str) -> Repo {
            let mode = crate::CreateOptions::new(crate::RepoMode::Archive);
            Repo::create(&self.root.join(name), mode).await.unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Writes a commit with the parent `parent` and the timestamp
    /// `timestamp` whose tree holds the file `f` with `content`, points the
    /// collection ref of each name of `names` in [`LOCAL_ID`] at it, and
    /// returns it.
    async fn local_commit(
        repo: &Repo,
        names: &[&str],
        parent: Option<Checksum>,
        timestamp: u64,
        content: &[u8],
    ) -> Checksum {
        let txn = repo.transaction().await.unwrap();
        let dirmeta = ostrya_core::DirMeta {
            uid: 0,
            gid: 0,
            mode: 0o40755,
            xattrs: Default::default(),
        };
        let dirmeta = txn
            .write_metadata(ObjectType::DirMeta, None, &dirmeta.serialize().unwrap())
            .await
            .unwrap();
        let file = txn
            .write_regfile_inline(None, &crate::write::FileMeta::regular(0, 0, 0o644), content)
            .await
            .unwrap();
        let mut mtree = crate::mtree::MutableTree::new();
        mtree.set_metadata_checksum(dirmeta);
        mtree.replace_file("f", file).unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();
        let options = crate::commit::CommitOptions {
            parent,
            timestamp: Some(timestamp),
            ..crate::commit::CommitOptions::default()
        };
        let commit = txn.write_commit(options, &root).await.unwrap();
        txn.commit().await.unwrap();
        for name in names {
            let cref = crate::Ref::collection(LOCAL_ID, *name);
            repo.set_ref_immediate(&cref, Some(&commit)).await.unwrap();
        }
        commit
    }

    /// Probes the local repository `src` under `trust` for the refs `names`,
    /// and pulls the refs into `dst` with the flags `flags` and the depth
    /// `depth`, as a pull of collection refs pulls from a selected local
    /// candidate.
    async fn probe_and_pull(
        dst: &Repo,
        src: &Repo,
        trust: PullTrust,
        names: &[&str],
        flags: PullFlags,
        depth: i32,
    ) -> Result<PullStats> {
        let verification = Verification::from_trust(trust.clone());
        let listed = probe_local(src, &verification, LOCAL_ID, names)
            .await?
            .listed;
        let run = PullOptions {
            refs: listed.iter().map(|l| l.name.clone()).collect(),
            flags,
            depth,
            ..PullOptions::default()
        };
        let pinned = pinned_of(dst, &listed);
        let related = RelatedRule::of(dst.config()).unwrap();
        dst.pull_local_candidate(src, trust, related, run, &pinned)
            .await
    }

    /// The refs `listed` of a local candidate in [`LOCAL_ID`], at the place
    /// of the collection refs of `dst`, as the pull of collection refs pins
    /// them. A tip with no collection binding passes.
    fn pinned_of<'a>(dst: &Repo, listed: &[Listed]) -> Pinned<'a> {
        Pinned {
            targets: listed.iter().map(|l| (l.name.clone(), l.commit)).collect(),
            listed: listed
                .iter()
                .map(|l| (l.name.clone(), l.timestamp))
                .collect(),
            collection: LOCAL_ID,
            allow_unbound: true,
            place: RefPlace::of_collection(dst, LOCAL_ID),
            summary: Mutex::new(None),
        }
    }

    /// Puts the bytes of the commit `from` of the archive repository at `dir`
    /// under the name of its commit `to`.
    fn replace_commit_file(dir: &Path, to: &Checksum, from: &Checksum) {
        let path = |commit: &Checksum| {
            dir.join("objects").join(ostrya_core::loose_path(
                commit,
                ObjectType::Commit,
                crate::RepoMode::Archive,
            ))
        };
        std::fs::remove_file(path(to)).unwrap();
        std::fs::copy(path(from), path(to)).unwrap();
    }

    /// Asserts that the repository `dst` at `dir` holds no object, no
    /// `.commitpartial` marker, no staging directory, and no collection ref.
    async fn assert_nothing_written(dst: &Repo, dir: &Path) {
        let objects = dst.list_objects().await.unwrap();
        assert!(objects.is_empty(), "{objects:?}");
        let leftovers: Vec<String> = ["state", "tmp"]
            .into_iter()
            .flat_map(|sub| std::fs::read_dir(dir.join(sub)).unwrap())
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".commitpartial") || name.starts_with("staging-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let refs = dst
            .list_collection_refs_in(LOCAL_ID, &RefSelector::parse(std::iter::empty()).unwrap())
            .await
            .unwrap();
        assert!(refs.is_empty(), "{refs:?}");
    }

    /// Without a summary policy, the probe of a local candidate reads the
    /// timestamp of each tip commit. Under a summary policy, the refs and
    /// their timestamps come from the summary.
    #[test]
    fn the_local_probe_reads_the_timestamp_of_each_tip_commit() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new();
            let src = scratch.create("src").await;
            let one = local_commit(&src, &["os/a", "os/b"], None, 1_700_000_001, b"one").await;
            let two = local_commit(&src, &["os/c"], None, 1_700_000_002, b"two").await;
            let unverified = Verification::from_trust(PullTrust::unverified());

            let listed = probe_local(&src, &unverified, LOCAL_ID, &[])
                .await
                .unwrap()
                .listed;
            assert_eq!(listed.len(), 3);
            let timestamps: HashMap<Checksum, u64> =
                listed.iter().map(|l| (l.commit, l.timestamp)).collect();
            assert_eq!(timestamps.len(), 2);
            assert_eq!(timestamps[&one], 1_700_000_001);
            assert_eq!(timestamps[&two], 1_700_000_002);

            // Under a summary policy, the refs come from the summary.
            src.regenerate_summary(&crate::SummaryOptions::default())
                .await
                .unwrap();
            src.sign_summary(&ed25519_signer()).await.unwrap();
            let policy =
                Verification::from_trust(PullTrust::unverified().with_summary(ed25519_keys()));
            let mut from_summary = probe_local(&src, &policy, LOCAL_ID, &[])
                .await
                .unwrap()
                .listed;
            let mut expected = listed;
            from_summary.sort_unstable_by(|a, b| a.name.cmp(&b.name));
            expected.sort_unstable_by(|a, b| a.name.cmp(&b.name));
            assert_eq!(from_summary, expected);
        });
    }

    /// Under a summary policy, the pull of a local candidate reads the
    /// `summary` and the `summary.sig` of the source again, and checks them.
    /// So a pull that requires static deltas applies the delta that the
    /// summary advertises. A source that holds no `summary.sig` at the pull
    /// fails the pull with [`Error::Signature`], with and without static
    /// deltas, and the pull writes nothing.
    #[test]
    fn a_local_candidate_reads_and_checks_the_summary_again() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new();
            let src = scratch.create("src").await;
            let tip = local_commit(&src, &["os/a"], None, 1_700_000_001, b"one").await;
            src.generate_static_delta(None, &tip, &crate::DeltaOptions::default())
                .await
                .unwrap();
            src.regenerate_summary(&crate::SummaryOptions::default())
                .await
                .unwrap();
            src.sign_summary(&ed25519_signer()).await.unwrap();
            let trust = PullTrust::unverified().with_summary(ed25519_keys());
            let verification = Verification::from_trust(trust.clone());
            let listed = probe_local(&src, &verification, LOCAL_ID, &["os/a"])
                .await
                .unwrap()
                .listed;
            let run = PullOptions {
                refs: vec!["os/a".to_owned()],
                require_static_deltas: true,
                ..PullOptions::default()
            };

            let dst = scratch.create("dst").await;
            let pinned = pinned_of(&dst, &listed);
            let related = RelatedRule::of(dst.config()).unwrap();
            let stats = dst
                .pull_local_candidate(&src, trust.clone(), related, run.clone(), &pinned)
                .await
                .unwrap();
            assert!(stats.delta_parts > 0, "{stats:?}");
            let cref = crate::Ref::collection(LOCAL_ID, "os/a");
            assert_eq!(dst.resolve_ref_tip(&cref).await.unwrap(), Some(tip));

            std::fs::remove_file(scratch.root.join("src").join("summary.sig")).unwrap();
            // A pull that reads no static delta also reads and checks the
            // summary.
            let plain = PullOptions {
                refs: vec!["os/a".to_owned()],
                ..PullOptions::default()
            };
            for (name, run) in [("unsigned", run), ("unsigned-plain", plain)] {
                let dst = scratch.create(name).await;
                let pinned = pinned_of(&dst, &listed);
                let related = RelatedRule::of(dst.config()).unwrap();
                let pulled = dst
                    .pull_local_candidate(&src, trust.clone(), related, run, &pinned)
                    .await;
                assert!(
                    matches!(pulled, Err(Error::Signature(_))),
                    "{name}: {pulled:?}"
                );
                assert_nothing_written(&dst, &scratch.root.join(name)).await;
            }
        });
    }

    /// With depth 1, a selected tip that is the parent of another selected
    /// tip is pulled, and each ref gets its commit, in each order of the
    /// refs.
    #[test]
    fn a_selected_tip_that_is_a_parent_of_another_is_pulled_in_each_order() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new();
            for (at, (child_ref, parent_ref)) in
                [("os/a", "os/b"), ("os/b", "os/a")].into_iter().enumerate()
            {
                let src = scratch.create(&format!("src{at}")).await;
                let parent = local_commit(&src, &[parent_ref], None, 1_700_000_001, b"one").await;
                let child =
                    local_commit(&src, &[child_ref], Some(parent), 1_700_000_002, b"two").await;
                let dst = scratch.create(&format!("dst{at}")).await;
                let src = Repo::open(&scratch.root.join(format!("src{at}")))
                    .await
                    .unwrap();
                probe_and_pull(
                    &dst,
                    &src,
                    PullTrust::unverified(),
                    &["os/a", "os/b"],
                    PullFlags::NONE,
                    1,
                )
                .await
                .unwrap();
                for (name, commit) in [(child_ref, child), (parent_ref, parent)] {
                    let cref = crate::Ref::collection(LOCAL_ID, name);
                    assert_eq!(dst.resolve_ref_tip(&cref).await.unwrap(), Some(commit));
                }
            }
        });
    }

    /// Under `UNTRUSTED`, a tip commit file that does not hash to its name
    /// fails the pull with [`Error::ChecksumMismatch`] at the import. The
    /// file has the listed timestamp, so the listed check passes. The pull
    /// publishes no object and writes no ref, and it leaves no
    /// `.commitpartial` marker and no staging directory.
    #[test]
    fn a_commit_that_does_not_hash_to_its_name_fails_an_untrusted_pull() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new();
            let src = scratch.create("src").await;
            let one = local_commit(&src, &["os/a"], None, 1_700_000_001, b"one").await;
            let two = local_commit(&src, &[], None, 1_700_000_001, b"two").await;
            replace_commit_file(&scratch.root.join("src"), &one, &two);
            let dst = scratch.create("dst").await;
            let pulled = probe_and_pull(
                &dst,
                &src,
                PullTrust::unverified(),
                &["os/a"],
                PullFlags::UNTRUSTED,
                0,
            )
            .await;
            match pulled {
                Err(Error::ChecksumMismatch { expected, actual }) => {
                    assert_eq!((expected, actual), (one, two));
                }
                other => panic!("{other:?}"),
            }
            assert_nothing_written(&dst, &scratch.root.join("dst")).await;
        });
    }

    /// A tip commit whose timestamp changes between the probe and the pull
    /// of a local candidate fails the check of the listed timestamp with
    /// [`Error::Pull`], with and without `UNTRUSTED`. The pull writes
    /// nothing.
    #[test]
    fn a_tip_commit_that_changes_after_the_probe_fails_the_listed_check() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new();
            let src = scratch.create("src").await;
            let one = local_commit(&src, &["os/a"], None, 1_700_000_001, b"one").await;
            let two = local_commit(&src, &[], None, 1_700_000_002, b"two").await;
            let unverified = Verification::from_trust(PullTrust::unverified());
            let listed = probe_local(&src, &unverified, LOCAL_ID, &["os/a"])
                .await
                .unwrap()
                .listed;
            assert_eq!(
                listed,
                [Listed {
                    name: "os/a".to_owned(),
                    commit: one,
                    timestamp: 1_700_000_001,
                }]
            );
            replace_commit_file(&scratch.root.join("src"), &one, &two);

            for (at, flags) in [PullFlags::NONE, PullFlags::UNTRUSTED]
                .into_iter()
                .enumerate()
            {
                let name = format!("dst{at}");
                let dst = scratch.create(&name).await;
                let run = PullOptions {
                    refs: vec!["os/a".to_owned()],
                    flags,
                    ..PullOptions::default()
                };
                let pinned = pinned_of(&dst, &listed);
                let related = RelatedRule::of(dst.config()).unwrap();
                let pulled = dst
                    .pull_local_candidate(&src, PullTrust::unverified(), related, run, &pinned)
                    .await;
                match pulled {
                    Err(Error::Pull(message)) => {
                        assert!(message.contains("timestamp"), "case {at}: {message}");
                    }
                    other => panic!("case {at}: {other:?}"),
                }
                assert_nothing_written(&dst, &scratch.root.join(&name)).await;
            }
        });
    }

    /// Two refs that name one tip commit each get the check of their own
    /// listed timestamp. A wrong listed timestamp of either ref fails the
    /// pull with [`Error::Pull`] that names the ref, and the pull writes
    /// nothing. With the listed timestamps of the probe, the pull writes both
    /// refs.
    #[test]
    fn each_ref_that_names_one_tip_gets_the_listed_check() {
        ostrya_rt::block_on(async {
            let scratch = Scratch::new();
            let src = scratch.create("src").await;
            let names = ["os/a", "os/b"];
            let tip = local_commit(&src, &names, None, 1_700_000_001, b"one").await;
            let unverified = Verification::from_trust(PullTrust::unverified());
            let listed = probe_local(&src, &unverified, LOCAL_ID, &names)
                .await
                .unwrap()
                .listed;
            let run = PullOptions {
                refs: names.map(str::to_owned).to_vec(),
                ..PullOptions::default()
            };

            for (at, wrong) in names.into_iter().enumerate() {
                let dir = format!("wrong{at}");
                let dst = scratch.create(&dir).await;
                let mut pinned = pinned_of(&dst, &listed);
                pinned.listed.insert(wrong.to_owned(), 1_700_000_002);
                let related = RelatedRule::of(dst.config()).unwrap();
                let pulled = dst
                    .pull_local_candidate(
                        &src,
                        PullTrust::unverified(),
                        related,
                        run.clone(),
                        &pinned,
                    )
                    .await;
                match pulled {
                    Err(Error::Pull(message)) => {
                        assert!(message.contains(&format!("'{wrong}'")), "{message}");
                    }
                    other => panic!("{wrong}: {other:?}"),
                }
                assert_nothing_written(&dst, &scratch.root.join(&dir)).await;
            }

            let dst = scratch.create("dst").await;
            let pinned = pinned_of(&dst, &listed);
            let related = RelatedRule::of(dst.config()).unwrap();
            dst.pull_local_candidate(&src, PullTrust::unverified(), related, run, &pinned)
                .await
                .unwrap();
            for name in names {
                let cref = crate::Ref::collection(LOCAL_ID, name);
                assert_eq!(dst.resolve_ref_tip(&cref).await.unwrap(), Some(tip));
            }
        });
    }
}
