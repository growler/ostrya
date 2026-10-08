//! The pull from a remote, over HTTP or over ssh.
//!
//! [`Repo::pull`], [`Repo::pull_over_stream`], and
//! [`Repo::remote_fetch_summary`] are the entry points. [`Repo::pull`] holds
//! the rules of the pull.
//!
//! The loop that drives the steps owns the plan, so the plan needs no lock.
//! The pull spawns no task: the step futures borrow the repository, the
//! transaction, and the fetcher. The walk of a subpath pull obeys the rules in
//! `subpath`.
//!
//! The plan walks a dirtree when it applies the step of the dirtree, under
//! each position that reached the dirtree by then. If a later position widens
//! that scope, the plan walks the dirtree again from the transaction.

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use async_compression::futures::bufread::DeflateDecoder;
use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::{AsyncReadExt, AsyncWriteExt};
use ostrya_core::{
    Checksum, Commit, DirTree, FileHeader, ObjectName, ObjectType, RepoMode, loose_path,
};

use crate::config::RepoConfig;
use crate::delta::IO_CHUNK;
use crate::error::{Error, Result};
use crate::fetch::gate::Gate;
use crate::fetch::{
    ClientIdentity, FetchRequest, Fetched, Fetcher, FetcherOptions, LowSpeed, Priority, Proxy,
    TlsOptions, TrustRoots,
};
use crate::inflate::BufSource;
use crate::object::{MAX_FILE_HEADER_SIZE, MAX_METADATA_SIZE};
use crate::push::{PullSession, PullSessionOptions};
use crate::read::CommitState;
use crate::repo::Repo;
use crate::summary::{SUMMARY_FILE, SUMMARY_SIG_FILE, Summary, put_root_file_blocking};
use crate::transaction::Transaction;
use crate::traverse::reaches_at_least;
use crate::write::FileMeta;

use super::address::{PullAddress, fill_pull_connect, refuse_http_fields, resolve_pull_address};
use super::delta::{self, DeltaJob, DeltaSource, PART_CAP};
use super::drive::Slots;
use super::source::{RemoteSource, SshSource, session_error};
use super::subpath::{Scope, Subpaths};
use super::verify::{Defaults, Verification};
use super::{
    DetachedMetadataFilter, ModeChecks, PullCounters, PullFlags, PullOptions, PullStats,
    READ_CHUNK, TimestampCheck, apply_durability, check_depth, check_ref_binding, refspec,
    refuse_remote_collection,
};

/// The number of fetches in flight if the caller names no limit.
const DEFAULT_OUTSTANDING: usize = 8;
/// The number of repeats of a round of mirrors if the caller names no count.
const DEFAULT_RETRIES: u32 = 5;
/// The rate in bytes per second below which the fetcher stops a transfer, if
/// the caller names no rate.
const DEFAULT_LOW_SPEED_LIMIT: u32 = 1000;
/// The time that the rate can stay below the limit, if the caller names no
/// time.
const DEFAULT_LOW_SPEED_TIME: Duration = Duration::from_secs(30);
/// The number of fetched content objects that stream into the object store at
/// once.
const WRITE_THROTTLE: usize = 3;

/// The cap on the repository-root files that a pull fetches (`summary`,
/// `summary.sig`, `config`). The local summary reader applies the same cap.
pub(super) const MAX_ROOT_FILE: u64 = 64 * 1024 * 1024;
/// The cap on a fetched `refs/heads/<ref>` file, which holds 64 hex characters
/// and a newline.
const MAX_REF_FILE: u64 = 1024;

/// The name of the config file at the repository root.
pub(super) const CONFIG_FILE: &str = "config";

/// Methods that pull from a remote over HTTP or ssh.
impl Repo {
    /// Pulls refs and their objects from a remote over HTTP or over ssh.
    ///
    /// `remote` names a `[remote "<name>"]` section of the config of this
    /// repository. The section gives the address, the TLS material, and the
    /// proxy. The pull fetches the objects into one transaction, publishes
    /// them, and then writes the refs. It returns the statistics of the pull.
    ///
    /// The module [`pull`](mod@crate::pull) states the rules of the
    /// `.commitpartial` markers. It also states the concurrency, the write
    /// permits, the memory, the connections, and the retries of this pull.
    ///
    /// [`pull_local`](Repo::pull_local) states the write order of the detached
    /// metadata and the mode checks of a content object. These rules apply to
    /// this pull too.
    ///
    /// [`PullOptions`] states which fields each pull reads, and
    /// [`PullVerify`](crate::PullVerify) holds the signature policy.
    ///
    /// # Address
    ///
    /// The address is the first of these values that is set:
    ///
    /// 1. [`url`](PullOptions::url), which lets a caller pull from a remote
    ///    that the config does not describe
    /// 2. the remote key `pull-url`
    /// 3. the remote key `url`
    ///
    /// If the value starts with `ssh://` or holds no `://`, it is an ssh
    /// address of [`PushRemote::parse`]. Any other value is the base URL of an
    /// HTTP remote. The fetcher gets that value as written, and it refuses a
    /// scheme other than `http` and `https`.
    ///
    /// The remote key `url` cannot hold an ssh address, because the `ostree`
    /// command also reads that key and does not pull over ssh.
    ///
    /// # Refs
    ///
    /// The pull resolves each requested ref against the summary of the remote.
    /// If the summary does not list the ref, or the remote serves no summary,
    /// the pull reads `refs/heads/<ref>` of the remote.
    /// [`refs`](PullOptions::refs) states what an empty list takes.
    ///
    /// [`remote`](PullOptions::remote) and [`MIRROR`](PullFlags::MIRROR)
    /// select the prefix of the written refs.
    /// [`no_ref_writes`](PullOptions::no_ref_writes) turns the ref writes off.
    ///
    /// # Proxy
    ///
    /// An HTTP pull connects through the `http://` proxy URL of the remote key
    /// `proxy`, for every origin, and ignores `no_proxy`. If the key is absent
    /// or empty, the pull reads the proxy environment variables.
    ///
    /// # Pull over ssh
    ///
    /// For an ssh address, the pull runs the ssh client after it resolves the
    /// signature policy. [`connect`](PullOptions::connect) states where the
    /// commands of the client come from. The session obeys the rules of
    /// [`pull_over_stream`](Repo::pull_over_stream).
    ///
    /// A pull over ssh reads no remote key that applies to HTTP alone:
    /// `contenturl`, `metalink`, `proxy`, and the `tls-*` keys. An HTTP pull
    /// reads neither `ssh-command` nor `send-command`.
    ///
    /// The pull reads the remote through a source: the HTTP source over the
    /// fetcher, or the ssh source over a pull session.
    /// [`pull_over_stream`](Repo::pull_over_stream) opens the ssh source over
    /// a pair of streams. The two sources serve the same paths under the same
    /// caps. Each rule of this method applies to both sources, with these
    /// differences:
    ///
    /// - The ssh source requests a ref by its name as written, with no
    ///   percent-encoding.
    /// - The ssh source never sends a request again. A failure ends its
    ///   session and the pull.
    /// - The ssh source keeps the requests of `summary.sig`, `summary`, and
    ///   `config` in flight together, in the order of the HTTP source. It does
    ///   the same for a `.commitmeta` and its commit, so a parent commit costs
    ///   one round trip. The HTTP source sends these requests one at a time.
    /// - The ssh source ends its session before the transaction commits. It
    ///   closes the input of the server and waits for the ssh client.
    ///
    /// # Requests
    ///
    /// The pull first requests `summary.sig`, `summary`, and `config`, in this
    /// order, and then the objects. A remote with no summary answers 404. The
    /// HTTP source percent-encodes each byte of a ref name outside the
    /// unreserved set of RFC 3986, except `/`.
    ///
    /// The remote must be an `archive` repository. The pull requests each
    /// content object as `objects/<..>.filez`, whatever the remote stores on
    /// its disk. That is the one form of a content object that an HTTP client
    /// can read: the framed, deflated payload behind its header.
    ///
    /// The pull reads `config` before the first object request. If `config`
    /// states a different mode, the pull fails. If the remote serves no
    /// `config`, the pull reads the remote as `archive`.
    ///
    /// # Commits
    ///
    /// The pull fetches a commit object before the objects that it references,
    /// because its tree is unknown until it arrives. The pull stages the commit
    /// when it arrives, so the verification of its name fails a wrong commit
    /// before the request of its tree. Nothing of the commit stays in memory
    /// after the step.
    ///
    /// The step that fetches a commit writes its `.commitpartial` marker. The
    /// module [`pull`](mod@crate::pull) states the rules of the markers.
    ///
    /// The pull fetches each object once, also if several commits reach it.
    /// The step that fetches a commit makes the ref-binding check and the
    /// timestamp check of each requested ref that names the commit. So two
    /// refs at one commit get both checks.
    ///
    /// The pull queues no object of the tree of a commit that this repository
    /// holds complete. It follows the parent of that commit all the same, so a
    /// pull extends the history that a shallower pull left.
    ///
    /// # Detached metadata
    ///
    /// The pull requests the `.commitmeta` of a commit before the commit
    /// object. It stages the `.commitmeta` in the transaction when the commit
    /// object arrives, so no `.commitmeta` stays for a parent that the remote
    /// answers 404 for. [`pull_local`](Repo::pull_local) states when the
    /// transaction writes it and what a failure leaves.
    ///
    /// # Verification
    ///
    /// The pull stores each fetched object under the name that it requested.
    /// The write path hashes what it stores and compares the result with that
    /// name. So a corrupt or substituted object fails the pull, and the pull
    /// publishes nothing. No flag turns this verification off, so the pull
    /// ignores [`UNTRUSTED`](PullFlags::UNTRUSTED).
    ///
    /// The pull makes the mode checks of
    /// [`BAREUSERONLY_FILES`](PullFlags::BAREUSERONLY_FILES) and of a
    /// `bare-user-only` destination over the header of a content object.
    ///
    /// The header also declares the size of the decompressed payload. This
    /// size bounds the stream on both sides:
    ///
    /// - A payload larger than the declared size fails the pull. So a corrupt
    ///   or expanding stream writes at most the declared size before the
    ///   checksum comparison at the end of the payload.
    /// - A payload that takes more bytes off the connection than a compressed
    ///   form of that size fails the pull too. The limit is the declared size,
    ///   plus one byte for each 1024, plus 64 KiB. This limit bounds the time
    ///   and the bandwidth of a stream of empty DEFLATE blocks.
    ///
    /// # Static deltas
    ///
    /// A remote that publishes static deltas delivers a commit as one delta,
    /// with no request for each object. Before the pull requests the first
    /// object, it looks for a delta:
    ///
    /// 1. If the remote serves a summary that states `indexed-deltas` or
    ///    omits the key, the pull fetches the delta index of the target
    ///    commit, `delta-indexes/<to_b64[0:2]>/<to_b64[2:]>.index`.
    /// 2. If the remote serves no index, the pull reads the
    ///    `ostree.static-deltas` map of the summary.
    ///
    /// Both map a delta name to the SHA-256 of the `superblock` of that delta.
    /// The pull fetches no delta that the map does not name. So a client that
    /// holds a commit with no published delta from it fetches loose.
    ///
    /// If the remote serves no summary, nothing advertises a delta. The pull
    /// then requests the `superblock` of one delta by name, with no digest to
    /// verify it against. That delta is `<from>-<to>` if this repository holds
    /// the commit of the ref complete, and the from-scratch `<to>` otherwise.
    ///
    /// The pull takes at most one delta for each target commit. It takes the
    /// first of these that the map names:
    ///
    /// - `<from>-<to>`, where `from` is the commit that the pulled ref names in
    ///   this repository
    /// - `<c>-<to>`, for each other commit `c` that this repository holds
    ///   complete
    /// - the from-scratch `<to>`, if the ref names no commit
    ///
    /// A from-to delta patches against the objects of the source commit, so
    /// this repository must hold the source commit complete. A ref whose
    /// commit is absent or partial counts as a ref that names no commit.
    ///
    /// If the ref names a commit that this repository holds complete, the pull
    /// takes no from-scratch delta, which delivers each object of the target
    /// again. It fetches the missing objects loose. With a map, a ref that
    /// names the target commit, held here partial, also leaves the
    /// from-scratch delta alone. The `ostree` command does the same.
    ///
    /// The pull looks for no delta to a target commit that this repository
    /// holds complete. It looks for a delta to a target commit held partial
    /// as for a commit that it does not hold. A
    /// [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull takes no delta.
    /// [`subpaths`](PullOptions::subpaths) states the delta rules of a
    /// subpath pull.
    ///
    /// If the remote advertised a digest for a superblock, the pull hashes the
    /// superblock and compares the result with the digest before the parse.
    /// So a delta swapped under a signed summary fails the pull. The parsed
    /// superblock must name the pulled commit and the source commit that the
    /// delta name states.
    ///
    /// Before any part request, the pull verifies the signatures of the delta
    /// over the raw superblock bytes, under the policy of
    /// [`PullVerify`](crate::PullVerify). Also before any part request, it
    /// verifies each inline part against the size and the checksum of its
    /// meta-entry. A superblock that the remote does not hold (a stale
    /// advertisement) is a 404, and the pull fetches the objects loose.
    ///
    /// The superblock holds the target commit, so the pull requests no
    /// `.commit`. A part that the superblock carries inline needs no request.
    /// The pull queues the objects that the delta hands over loose at once.
    /// Two part fetches run at a time, whatever the step count.
    ///
    /// The pull takes each part off the connection under the size that its
    /// meta-entry declares. It verifies the part against the checksum of that
    /// entry before decompression. So the remote puts at most the size that
    /// the superblock states onto the staging file system for one part. The
    /// pull writes each object of a part with its expected checksum asserted.
    ///
    /// The pull applies the parts in the order that they arrive. The format
    /// allows this order: a part patches against the objects of the source
    /// commit, which are present before the delta applies. A part never
    /// patches against the output of another part.
    ///
    /// After the last part, the pull walks the tree of the commit and fetches
    /// loose each object that no part delivered. The `ostree` command takes
    /// the delta and its loose objects as the whole commit. If the delta was
    /// complete, the walk reads what the delta staged and requests nothing.
    ///
    /// Each part in flight costs one xz decoder and two blobs: the verified
    /// part body and the payload that it decompresses to. Each blob is on the
    /// heap while it is small. After a blob passes its heap threshold, it is a
    /// mapped temp file.
    ///
    /// [`disable_static_deltas`](PullOptions::disable_static_deltas) and
    /// [`require_static_deltas`](PullOptions::require_static_deltas) control
    /// the search.
    ///
    /// # Failure
    ///
    /// The steps borrow the repository, the transaction, and the fetcher. A
    /// failure drops each step in flight, which closes its connection and
    /// releases its fetcher permit. The transaction removes its staging
    /// directory, and the pull writes no ref.
    ///
    /// # Errors
    ///
    /// These errors stop the pull before its first request:
    ///
    /// - [`Error::InvalidInput`] if [`depth`](PullOptions::depth) is below
    ///   `-1`, or if an ssh address is malformed.
    /// - [`Error::InvalidInput`] if a pull over ssh gets a field of HTTP alone:
    ///   [`http_headers`](PullOptions::http_headers),
    ///   [`n_network_retries`](PullOptions::n_network_retries) above 0,
    ///   [`low_speed_limit_bytes`](PullOptions::low_speed_limit_bytes), or
    ///   [`low_speed_time`](PullOptions::low_speed_time).
    /// - [`Error::InvalidInput`] if an HTTP pull gets the ssh command or the
    ///   send command of [`connect`](PullOptions::connect).
    /// - [`Error::Unsupported`] if
    ///   [`collection_id`](PullOptions::collection_id) is set. The pull reads
    ///   no collection ref.
    /// - [`Error::Unsupported`] if the scheme of the URL is neither `http` nor
    ///   `https`.
    /// - [`Error::Unsupported`] if the value of the remote key `proxy` has
    ///   white space at its start or end. Also if the fetcher refuses the
    ///   proxy URL or a proxy environment variable.
    /// - [`Error::Fetch`] if the URL is not a valid absolute URL, if a header
    ///   is invalid, or if the TLS material does not parse.
    /// - [`Error::Pull`] if a subpath does not start with `/`.
    /// - [`Error::Pull`] if the config has no section for `remote` and the
    ///   caller gives no `url`.
    /// - [`Error::Pull`] if the section has neither `pull-url` nor `url`, or if
    ///   `url` holds an ssh address.
    /// - [`Error::Pull`] if the remote names `tls-client-cert-path` without
    ///   `tls-client-key-path`, or the reverse.
    /// - [`Error::Core`] if a key of the remote section holds a malformed
    ///   escape sequence.
    /// - [`Error::Io`] if a PEM file that a `tls-*` key names cannot be read.
    ///
    /// These errors stop the pull before it fetches an object:
    ///
    /// - [`Error::Signature`] if the policy of
    ///   [`PullVerify`](crate::PullVerify) refuses the summary.
    /// - [`Error::Unsupported`] if the `config` of the remote states a mode
    ///   other than `archive`.
    /// - [`Error::InvalidFormat`] if the `config` of the remote is not valid
    ///   UTF-8 or has no valid `[core]` group.
    /// - [`Error::InvalidFormat`] if a `refs/heads/<ref>` file is not valid
    ///   UTF-8.
    /// - [`Error::Core`] if the `config` of the remote does not parse as a key
    ///   file, or if a `refs/heads/<ref>` file holds no checksum.
    /// - [`Error::InvalidRefspec`] if a requested ref, or a ref of the summary
    ///   under `MIRROR`, is not a valid ref name.
    /// - [`Error::RefNotFound`] if neither the summary nor `refs/heads/<ref>`
    ///   names a requested ref.
    /// - [`Error::Pull`] if [`refs`](PullOptions::refs) is empty and the remote
    ///   serves no summary under `MIRROR`, or the remote has no `branches`.
    /// - [`Error::Pull`] if
    ///   [`require_static_deltas`](PullOptions::require_static_deltas) is set
    ///   and the pull finds no delta.
    /// - [`Error::Pull`] if a superblock names other commits than its delta
    ///   name.
    ///
    /// These errors stop the pull while it fetches:
    ///
    /// - [`Error::Signature`] if the policy refuses a commit or a static delta.
    /// - [`Error::Pull`] if the `ostree.ref-binding` of a commit does not list
    ///   the ref.
    /// - [`Error::Pull`] if a tip is older than the
    ///   [`timestamp_check`](PullOptions::timestamp_check) allows, or if a
    ///   content object fails a mode check.
    /// - [`Error::ObjectNotFound`] if the remote does not hold a requested
    ///   commit or an object of a tree.
    /// - [`Error::ChecksumMismatch`] if a fetched object does not hash to its
    ///   name, or a superblock does not hash to its advertised digest.
    /// - [`Error::Core`] if a fetched commit or the header of a content object
    ///   does not parse.
    /// - [`Error::InvalidFormat`] if a content object breaks its framing, or
    ///   passes its declared size or its compressed limit.
    /// - [`Error::InvalidFormat`] if a content object inflates to fewer bytes
    ///   than declared, or has bytes after its end. A malformed static delta
    ///   has the same error.
    /// - [`Error::InsufficientFreeSpace`] if a stored object needs more space
    ///   than the free-space budget of the transaction holds.
    ///
    /// These errors can stop the pull at any request or write:
    ///
    /// - [`Error::Fetch`], [`Error::HttpStatus`], [`Error::FetchTooLarge`],
    ///   [`Error::ContentEncoded`], or [`Error::RedirectLimit`] if an HTTP
    ///   request fails after its retries.
    /// - [`Error::Push`] if the session of a pull over ssh fails.
    /// - [`Error::LockTimeout`] if the wait for the repository lock or the
    ///   update lock passes `[core] lock-timeout-secs`.
    /// - [`Error::Io`] for an I/O error of the file system.
    ///
    /// # Examples
    ///
    /// Pull one ref from the remote `origin` of the config:
    ///
    /// ```no_run
    /// # async fn run() -> ostrya::Result<()> {
    /// let repo = ostrya::Repo::open("/srv/repo".as_ref()).await?;
    /// let opts = ostrya::PullOptions {
    ///     refs: vec!["exampleos/stable".to_owned()],
    ///     ..Default::default()
    /// };
    /// let stats = repo.pull("origin", opts).await?;
    /// println!("{} content objects fetched", stats.content_fetched);
    /// # Ok(()) }
    /// ```
    ///
    /// [`PushRemote::parse`]: crate::push::PushRemote::parse
    pub async fn pull(&self, remote: &str, opts: PullOptions) -> Result<PullStats> {
        let started = Instant::now();
        // A subpath the walk cannot read is refused before anything else, so it
        // costs no request and opens no transaction.
        let subpaths = Subpaths::parse(&opts.subpaths)?;
        check_depth(opts.depth)?;
        refuse_remote_collection(&opts)?;
        let section = self.config().remote(remote);
        // The address is resolved first, so a remote the config does not
        // describe reports that before a policy is resolved for it.
        let address = resolve_pull_address(section.as_ref(), remote, opts.url.as_deref())?;
        let counters = PullCounters::new(opts.progress.as_ref());
        let (source, verification) = match address {
            PullAddress::Http(url) => {
                refuse_ssh_fields(&opts)?;
                // `remote_fetcher` reads the TLS material and the proxy and
                // sends no request, so a refused policy still stops the pull
                // before its first fetch.
                let fetcher = self
                    .remote_fetcher(
                        remote,
                        section.as_ref(),
                        url,
                        &opts,
                        counters.transferred_sinks(),
                    )
                    .await?;
                let verification =
                    Verification::build(self, Some(remote), &opts.verify, Defaults::Config).await?;
                (RemoteSource::Http(fetcher), verification)
            }
            PullAddress::Ssh(address) => {
                refuse_http_fields(&opts, &address)?;
                let connect = fill_pull_connect(section.as_ref(), opts.connect.clone())?;
                let verification =
                    Verification::build(self, Some(remote), &opts.verify, Defaults::Config).await?;
                // The ssh client starts where the HTTP pull sends its first
                // request.
                let session =
                    PullSession::connect(&address.remote, connect, session_options(&opts)).await?;
                let source = RemoteSource::Ssh(Box::new(SshSource::new(
                    session,
                    counters.transferred_sinks(),
                )));
                (source, verification)
            }
        };
        // The state of `pull_from` is on the heap, which keeps the future of
        // `pull` small.
        Box::pin(self.pull_from(
            remote,
            source,
            &opts,
            &verification,
            subpaths,
            &counters,
            started,
        ))
        .await
    }

    /// Pulls refs and their objects from `ostrya send` over a pair of streams.
    ///
    /// `input` carries the bytes from the server, and `output` carries the
    /// bytes to it. The caller connects them to `ostrya send` on the side of
    /// the remote repository.
    ///
    /// `remote` names the remote whose config the pull reads, as for
    /// [`pull`](Repo::pull): the signature policy, the `branches` key, and the
    /// prefix of the written refs. The remote needs no config section, as for a
    /// pull with [`url`](PullOptions::url).
    ///
    /// The pull obeys every rule of [`pull`](Repo::pull): the transaction, the
    /// commit walk, [`depth`](PullOptions::depth), the subpaths, the
    /// verification of signatures, the static deltas, and the statistics.
    ///
    /// The session opens after the pull resolves the signature policy, so a
    /// refused policy writes nothing to `output`. The session keeps at most
    /// [`max_outstanding_fetches`](PullOptions::max_outstanding_fetches)
    /// requests in flight. It never sends a request again, and it puts no time
    /// limit on a read. Before the transaction commits, the pull closes
    /// `output`, which ends the session.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `opts` sets [`url`](PullOptions::url), or
    ///   the ssh command or the send command of
    ///   [`connect`](PullOptions::connect). The caller already connected the
    ///   streams.
    /// - [`Error::Unsupported`] if
    ///   [`collection_id`](PullOptions::collection_id) is set, before the
    ///   session opens.
    /// - [`Error::Push`] if the session fails. A failure ends the session and
    ///   the pull.
    /// - The other errors of [`pull`](Repo::pull) that apply to a pull over
    ///   ssh.
    pub async fn pull_over_stream<R, W>(
        &self,
        remote: &str,
        input: R,
        output: W,
        opts: PullOptions,
    ) -> Result<PullStats>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let started = Instant::now();
        let subpaths = Subpaths::parse(&opts.subpaths)?;
        check_depth(opts.depth)?;
        refuse_remote_collection(&opts)?;
        if opts.url.is_some() {
            return Err(Error::InvalidInput(
                "a pull over a pair of streams takes no url".into(),
            ));
        }
        if opts.connect.ssh_command.is_some() || opts.connect.send_command.is_some() {
            return Err(Error::InvalidInput(
                "a pull over a pair of streams runs no ssh client, so it takes no ssh \
                 command and no send command"
                    .into(),
            ));
        }
        let counters = PullCounters::new(opts.progress.as_ref());
        let verification =
            Verification::build(self, Some(remote), &opts.verify, Defaults::Config).await?;
        let session = PullSession::over_stream(input, output, session_options(&opts)).await?;
        let source = RemoteSource::Ssh(Box::new(SshSource::new(
            session,
            counters.transferred_sinks(),
        )));
        self.pull_from(
            remote,
            source,
            &opts,
            &verification,
            subpaths,
            &counters,
            started,
        )
        .await
    }

    /// Runs a pull from `source` to its end: fetches what the refs reach into
    /// a transaction, ends the source, commits the transaction, and writes the
    /// refs.
    #[allow(clippy::too_many_arguments)]
    async fn pull_from(
        &self,
        remote: &str,
        source: RemoteSource,
        opts: &PullOptions,
        verification: &Verification,
        subpaths: Option<Subpaths>,
        counters: &PullCounters,
        started: Instant,
    ) -> Result<PullStats> {
        let mirror = opts.flags.contains(PullFlags::MIRROR);
        let prefix = if mirror {
            None
        } else {
            Some(opts.remote.as_deref().unwrap_or(remote))
        };

        // The markers that the pull writes. They stay outside the span that
        // writes them, so a failure in that span clears the markers it left.
        let mut marked = Vec::new();
        let fetched = self
            .fetch_from(
                &source,
                remote,
                opts,
                prefix,
                verification,
                subpaths,
                counters,
                &mut marked,
            )
            .await;
        // The source ends before the transaction commits. The ssh source
        // closes the input of the server and waits for the ssh client. As a
        // result, a failure of the session fails the pull before anything
        // publishes.
        let fetched = source.finish(fetched).await;
        let published = match fetched {
            Ok(fetched) => {
                let FetchedPull {
                    txn,
                    targets,
                    summary,
                    signature,
                } = fetched;
                if !opts.no_ref_writes {
                    for (name, tip) in &targets {
                        txn.set_ref(&refspec(prefix, name), Some(tip));
                    }
                }
                txn.commit().await.map(|stats| (stats, summary, signature))
            }
            Err(e) => Err(e),
        };
        let (stats, summary_bytes, signature) = match published {
            Ok(published) => published,
            Err(e) => {
                self.clear_markers_for_absent_commits(&marked).await;
                return Err(e);
            }
        };

        // The content that a marker guarded is published. A commit-only pull
        // keeps its markers, because it fetched no tree. A pull with subpaths
        // keeps them too, because it fetched part of each tree.
        if !opts.flags.contains(PullFlags::COMMIT_ONLY) && opts.subpaths.is_empty() {
            for commit in &marked {
                self.remove_partial_marker(commit).await?;
            }
        }

        // A mirror pull of every ref holds all that the remote publishes, so
        // the summary of the remote also describes this repository. The pull
        // copies it byte for byte. A mirror pull of named refs holds part of
        // it and writes no summary. A pull that writes no ref writes no
        // summary, because the summary lists refs that the pull did not write.
        if mirror
            && opts.refs.is_empty()
            && !opts.no_ref_writes
            && let Some(bytes) = summary_bytes
        {
            let fsync = self.config().fsync()? && !opts.disable_fsync;
            // The pull writes both files under one hold of the update lock. It
            // takes the lock after the transaction commit released its own
            // hold, so no other writer of the summary lands between the files.
            // The hold can time out after the transaction commit wrote the
            // refs and the `.commitmeta` files. The pull then fails with those
            // files in place and the summary as it was.
            self.write_locked(move |repo| {
                put_root_file_blocking(repo.repo_fd(), SUMMARY_FILE, &bytes, fsync)?;
                // The signature covers those bytes, so the pull copies it with
                // them. A client that pulls from this repository with
                // `gpg-verify-summary=true` reads the pair. If the remote holds
                // no `summary.sig`, the file of this repository stays as it
                // is. The `ostree` command does the same.
                if let Some(sig) = signature {
                    put_root_file_blocking(repo.repo_fd(), SUMMARY_SIG_FILE, &sig, fsync)?;
                }
                // One sync of the root directory makes both renames durable.
                if fsync {
                    rustix::fs::fsync(repo.repo_fd())?;
                }
                Ok(())
            })
            .await?;
        }

        Ok(PullStats {
            metadata_imported: stats.metadata_written,
            content_imported: stats.content_written,
            content_bytes_written: stats.content_bytes_written,
            content_bytes_unpacked: stats.content_bytes_unpacked,
            metadata_fetched: counters.metadata(),
            content_fetched: counters.content(),
            delta_parts: counters.parts(),
            bytes_transferred: counters.bytes(),
            elapsed: started.elapsed(),
        })
    }

    /// Fetches what a pull from `source` reaches into a new transaction: the
    /// summary and its checks, the refs, the deltas, and then the plan, to
    /// its end. The commits whose `.commitpartial` marker the pull wrote go
    /// into `marked`.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_from(
        &self,
        source: &RemoteSource,
        remote: &str,
        opts: &PullOptions,
        prefix: Option<&str>,
        verification: &Verification,
        subpaths: Option<Subpaths>,
        counters: &PullCounters,
        marked: &mut Vec<Checksum>,
    ) -> Result<FetchedPull> {
        let mut root = source.root_files().await?;
        // The pull checks the summary before it reads it. The pull acts on the
        // refs that the summary resolves and the deltas that it advertises.
        // As a result, a summary that the policy refuses stops the pull before
        // its first object request.
        verification
            .check_summary(root.summary.as_deref(), root.signature.as_deref())
            .await?;
        let summary = match root.summary.as_deref() {
            Some(bytes) => Some(Summary::parse(bytes)?),
            None => None,
        };
        check_remote_mode(root.config(source).await?)?;
        let targets = self
            .remote_targets(remote, opts, summary.as_ref(), source)
            .await?;
        // The transferred count starts after the summary, the config, and the
        // ref files that a pull reads from a remote with no summary. The
        // `ostree` command reports the same count.
        counters.restart_transferred();

        // The deltas that can deliver these commits, found before the first
        // object request. A commit that a delta carries has no `.commit`
        // request of its own.
        let deltas = delta::discover(
            self,
            &DeltaSource::Remote(source),
            summary.as_ref(),
            &targets,
            opts,
            prefix,
            verification,
            counters,
        )
        .await?;
        for job in deltas.values() {
            let (parts, bytes) = job.fetched_parts();
            counters.parts_planned(parts, bytes);
        }

        let mut txn = self.transaction().await?;
        apply_durability(&mut txn, opts);
        self.drive(
            &txn,
            source,
            opts,
            prefix,
            &targets,
            &deltas,
            verification,
            subpaths,
            counters,
            marked,
        )
        .await?;
        Ok(FetchedPull {
            txn,
            targets,
            summary: root.summary,
            signature: root.signature,
        })
    }

    /// Fetches the `summary` and `summary.sig` files of a remote.
    ///
    /// Returns the bytes of `summary` and of `summary.sig`, in this order. A
    /// file that the remote does not serve is `None`. Each file has a cap of
    /// 64 MiB.
    ///
    /// The call reaches the remote as [`pull`](Repo::pull) does, with no
    /// override. It reads the address from `pull-url` or `url`, and over HTTP
    /// it uses the TLS material and the proxy of the remote. Over ssh, the
    /// remote keys `ssh-command` and `send-command` give the commands. The
    /// `OSTRYA_SSH_COMMAND` environment variable has precedence over
    /// `ssh-command`.
    ///
    /// Over HTTP, the call requests `summary.sig` and then `summary`. Over
    /// ssh, the two requests are in flight together, and the session ends
    /// before the call returns.
    ///
    /// # Errors
    ///
    /// - [`Error::Pull`] if the config has no section for `remote`, or if the
    ///   section has neither `pull-url` nor `url`.
    /// - [`Error::Pull`] if `url` holds an ssh address.
    /// - [`Error::Pull`] if the remote names only one of
    ///   `tls-client-cert-path` and `tls-client-key-path`.
    /// - [`Error::InvalidInput`] if the ssh address is malformed.
    /// - [`Error::Unsupported`] if the scheme of the URL is neither `http` nor
    ///   `https`.
    /// - [`Error::Unsupported`] if the value of the remote key `proxy` has
    ///   white space at its start or end. Also if the fetcher refuses the
    ///   proxy URL or a proxy environment variable.
    /// - [`Error::Core`] if a key of the remote section holds a malformed
    ///   escape sequence.
    /// - [`Error::Io`] if a PEM file that a `tls-*` key names cannot be read.
    /// - [`Error::FetchTooLarge`] if an HTTP response declares a file larger
    ///   than 64 MiB.
    /// - [`Error::Fetch`], [`Error::HttpStatus`] other than 404,
    ///   [`Error::ContentEncoded`], or [`Error::RedirectLimit`] if an HTTP
    ///   request fails after its retries.
    /// - [`Error::Push`] if the ssh session fails.
    pub async fn remote_fetch_summary(
        &self,
        remote: &str,
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        let section = self.config().remote(remote);
        let source = match resolve_pull_address(section.as_ref(), remote, None)? {
            PullAddress::Http(url) => RemoteSource::Http(
                self.remote_fetcher(
                    remote,
                    section.as_ref(),
                    url,
                    &PullOptions::default(),
                    Vec::new(),
                )
                .await?,
            ),
            PullAddress::Ssh(address) => {
                let connect = fill_pull_connect(section.as_ref(), Default::default())?;
                let session = PullSession::connect(
                    &address.remote,
                    connect,
                    session_options(&PullOptions::default()),
                )
                .await?;
                RemoteSource::Ssh(Box::new(SshSource::new(session, Vec::new())))
            }
        };
        let read = source.summary_files().await;
        source.finish(read).await
    }

    /// Builds the fetcher of `url` for one remote from its config section and
    /// `opts`. The fetcher adds the bytes of each body that it reads to each
    /// counter of `received`.
    ///
    /// The section gives the TLS material and the proxy. A `proxy` value with
    /// white space at its start or end is [`Error::Unsupported`]. With no
    /// section, the fetcher trusts the host trust store and reads the proxy
    /// environment variables.
    async fn remote_fetcher(
        &self,
        remote: &str,
        section: Option<&crate::config::Remote<'_>>,
        url: String,
        opts: &PullOptions,
        received: Vec<Arc<AtomicU64>>,
    ) -> Result<Fetcher> {
        let (tls, proxy) = match section {
            Some(section) => (
                remote_tls(remote, section).await?,
                remote_proxy(remote, section)?,
            ),
            None => (TlsOptions::default(), Proxy::Environment),
        };
        Fetcher::with_counters(
            FetcherOptions {
                headers: opts.http_headers.clone(),
                tls,
                proxy,
                max_retries: opts.n_network_retries.unwrap_or(DEFAULT_RETRIES),
                max_outstanding: opts.max_outstanding_fetches.unwrap_or(DEFAULT_OUTSTANDING),
                low_speed: low_speed(opts),
                ..FetcherOptions::new(url)
            },
            received,
        )
        .await
        .map_err(Error::from)
    }

    /// Resolves what to pull: the requested refs, the summary refs of the
    /// remote under [`MIRROR`](PullFlags::MIRROR), or the `branches` key of
    /// the remote.
    async fn remote_targets(
        &self,
        remote: &str,
        opts: &PullOptions,
        summary: Option<&Summary>,
        source: &RemoteSource,
    ) -> Result<Vec<(String, Checksum)>> {
        let names = if !opts.refs.is_empty() {
            opts.refs.clone()
        } else if opts.flags.contains(PullFlags::MIRROR) {
            let Some(summary) = summary else {
                return Err(Error::Pull(
                    "fetching all refs was requested in mirror mode, but the remote \
                     repository does not have a summary"
                        .into(),
                ));
            };
            // A summary name becomes a ref that this pull writes. The pull
            // checks it against the rule of the ref store here, before the
            // first object request. Without this check, the first check comes
            // when the transaction resolves the ref at publication.
            for entry in &summary.refs {
                crate::refs::check_ref_path(&entry.name)?;
            }
            return Ok(summary
                .refs
                .iter()
                .map(|entry| (entry.name.clone(), entry.commit))
                .collect());
        } else {
            let branches = match self.config().remote(remote) {
                Some(section) => section.branches()?.unwrap_or_default(),
                None => Vec::new(),
            };
            if branches.is_empty() {
                return Err(Error::Pull(format!(
                    "no configured branches for remote {remote}"
                )));
            }
            branches
        };

        let mut out = Vec::with_capacity(names.len());
        for name in names {
            // The name goes on the wire as a request path, so the pull checks
            // it against the rule of the ref store. A traversal component can
            // ask the server for a resource that the ref does not name.
            crate::refs::check_ref_path(&name)?;
            let checksum = match summary.and_then(|summary| summary.lookup(&name)) {
                Some(checksum) => checksum,
                None => fetch_remote_ref(source, &name)
                    .await?
                    .ok_or_else(|| Error::RefNotFound(name.clone()))?,
            };
            out.push((name, checksum));
        }
        Ok(out)
    }

    /// Runs the plan to its end. The commits whose `.commitpartial` marker
    /// this pull wrote, and must clear, go into `marked`.
    ///
    /// `marked` is an argument, so the caller holds the written markers when a
    /// step fails.
    #[allow(clippy::too_many_arguments)]
    async fn drive(
        &self,
        txn: &Transaction,
        source: &RemoteSource,
        opts: &PullOptions,
        ref_prefix: Option<&str>,
        targets: &[(String, Checksum)],
        deltas: &HashMap<Checksum, DeltaJob>,
        verification: &Verification,
        subpaths: Option<Subpaths>,
        progress: &PullCounters,
        marked: &mut Vec<Checksum>,
    ) -> Result<()> {
        // The refs of each requested tip. The binding check and the timestamp
        // check apply to each ref. The plan fetches a commit once, whatever the
        // number of refs that name it. So the step that fetches a commit runs
        // the checks of every ref in its entry here.
        let mut tips: HashMap<Checksum, Vec<String>> = HashMap::new();
        for (name, tip) in targets {
            tips.entry(*tip).or_default().push(name.clone());
        }
        let ctx = StepCtx {
            txn,
            source,
            writes: Arc::new(Gate::new(WRITE_THROTTLE)),
            sources: &opts.localcache_repos,
            flags: opts.flags,
            checks: ModeChecks::new(opts.flags, self.mode()),
            ref_prefix,
            timestamp_check: &opts.timestamp_check,
            tips: &tips,
            deltas,
            verification,
            detached_filter: &opts.detached_metadata_filter,
            progress,
        };
        let mut plan = Plan::new(subpaths);
        for (_, tip) in targets {
            plan.push_commit(CommitItem {
                checksum: *tip,
                depth: opts.depth,
                optional: false,
            });
        }

        let mut slots = Slots::new(opts.max_outstanding_fetches.unwrap_or(DEFAULT_OUTSTANDING));
        // The read buffers for content objects, from each source. A localcache
        // import verifies its payload through one, and a fetched payload
        // streams into the object store through one. A step takes a buffer at
        // its start and gives it back with its outcome. So a pull holds one
        // buffer for each slot, whatever the number of objects it stores. A
        // step that fails takes its buffer with it, and the failure ends the
        // pull.
        let mut buffers: Vec<Vec<u8>> = Vec::new();
        // The units of work given to a slot, for the progress total.
        let mut started: usize = 0;
        loop {
            while slots.has_room()
                && let Some(item) = plan.next()
            {
                let buffer = buffers.pop().unwrap_or_default();
                slots.push(self.step(&ctx, item, buffer));
                started += 1;
            }
            plan.report(progress, started);
            let Some(outcome) = slots.next_ready().await else {
                break;
            };
            let (step, buffer) = outcome?;
            buffers.push(buffer);
            progress.object_done();
            plan.apply(step, marked);
        }
        Ok(())
    }

    /// Runs one unit of work: fetches an object and stores it.
    ///
    /// `read_buf` is the read buffer of the slot. The step returns it with the
    /// outcome, for the next step in that slot. A content object reads through
    /// it: the payload of an object from the remote, and the verification of
    /// an object from a localcache repository.
    async fn step(
        &self,
        ctx: &StepCtx<'_>,
        item: Item,
        mut read_buf: Vec<u8>,
    ) -> Result<(Step, Vec<u8>)> {
        let step = match item {
            Item::Commit(commit) => self.fetch_commit(ctx, commit, &mut read_buf).await?,
            Item::Object(name) if name.ty == ObjectType::File => {
                self.fetch_content(ctx, name, &mut read_buf).await?
            }
            Item::Object(name) => self.fetch_metadata(ctx, name, &mut read_buf).await?,
            Item::Part(part) => {
                let job = ctx
                    .deltas
                    .get(&part.commit)
                    .expect("a queued part belongs to a delta this pull found");
                delta::apply_job_part(
                    ctx.txn,
                    &DeltaSource::Remote(ctx.source),
                    job,
                    part.index,
                    ctx.checks,
                    ctx.progress,
                )
                .await?;
                Step::Part(part.commit)
            }
        };
        Ok((step, read_buf))
    }

    /// Fetches one commit: its detached metadata, then the object, then the
    /// checks of each requested ref that names it. The step stages the
    /// detached metadata when the commit object is here.
    async fn fetch_commit(
        &self,
        ctx: &StepCtx<'_>,
        item: CommitItem,
        read_buf: &mut Vec<u8>,
    ) -> Result<Step> {
        let checksum = item.checksum;
        let name = ObjectName::new(checksum, ObjectType::Commit);

        let present = self.has_object(ObjectType::Commit, &checksum).await?;
        let complete = present && self.commit_state(&checksum).await? == CommitState::Normal;
        // How the commit object reaches the object store, after the checks
        // pass. A commit that this repository holds is there already.
        let mut staging = CommitStaging::Held;
        // Detached metadata goes with its commit, and the pull fetches it
        // before the commit. The `ostree` command was observed to request the
        // pair in this order. The pull holds the bytes until the commit object
        // is here, so a commit that the remote does not hold leaves none.
        let (detached, bytes) = if present {
            let detached = self.fetch_detached_metadata(ctx, &checksum).await?;
            let bytes = self
                .load_object_bytes(ObjectType::Commit, &checksum)
                .await?;
            (detached, bytes)
        } else if let Some(src) = cached_source(ctx.sources, name).await? {
            // A localcache source holds the object. The pull reads the bytes
            // from there, and the import runs after the checks, in the order of
            // the fetched branches.
            staging = CommitStaging::Import(src);
            let detached = self.fetch_detached_metadata(ctx, &checksum).await?;
            (
                detached,
                src.load_object_bytes(ObjectType::Commit, &checksum).await?,
            )
        } else if let Some(job) = ctx.deltas.get(&checksum) {
            // A delta carries the target commit in its superblock, and these
            // bytes come from there. The parse of the superblock verified that
            // they hash to this checksum. The write at staging verifies it
            // again.
            staging = CommitStaging::Write;
            let detached = self.fetch_detached_metadata(ctx, &checksum).await?;
            (detached, job.commit_bytes.clone())
        } else {
            match self.fetch_remote_commit(ctx, &checksum).await? {
                (detached, Some(bytes)) => {
                    ctx.progress.metadata_fetched();
                    staging = CommitStaging::Write;
                    (detached, bytes)
                }
                // A parent that the remote does not hold ends that chain, as a
                // source with truncated history does for a local pull. The pull
                // drops its detached metadata: this repository holds no commit
                // for it.
                (_, None) if item.optional => return Ok(Step::Done),
                (_, None) => {
                    return Err(Error::ObjectNotFound {
                        checksum,
                        ty: ObjectType::Commit,
                    });
                }
            }
        };

        let commit = Commit::parse(&bytes)?;
        // The signature verification runs before the pull stages the commit
        // and requests its tree, so a commit that the policy refuses costs no
        // object fetch. The verification reads the detached metadata that this
        // pull puts in place. That is the copy of the remote if it served one,
        // else the copy of this repository. A later verification of the stored
        // commit reads the same metadata.
        if ctx.verification.checks_commits() {
            let dict = match &detached {
                Some(bytes) => crate::summary::parse_signature_dict(bytes)?,
                None => self.read_commit_detached_metadata(&checksum).await?,
            };
            ctx.verification
                .check_commit(&checksum, &bytes, dict.as_ref())
                .await?;
        }
        // The pull checks each requested ref that names this commit here. The
        // plan fetches a commit once, so a second ref at the same commit has no
        // step of its own for its checks.
        for ref_name in ctx.tips.get(&checksum).into_iter().flatten() {
            if !ctx.flags.contains(PullFlags::DISABLE_VERIFY_BINDINGS) {
                check_ref_binding(&checksum, &commit, ref_name)?;
            }
            self.check_timestamp(ctx, ref_name, &checksum, &commit)
                .await?;
        }

        // The pull writes no partial marker for a commit that this repository
        // holds complete: a pull that fails elsewhere must not demote it.
        if !complete {
            self.write_partial_marker(&checksum).await?;
        }
        // The pull stages the commit here, after its marker and before its
        // tree. Each path hashes the bytes and compares the result with the
        // requested name. The write path does this for bytes in memory, and the
        // untrusted import for an object of a localcache source. So a commit
        // stored under a wrong name fails here, before the pull fetches its
        // tree, and nothing stays after the step. The marker guards a reader
        // against a commit whose tree is not yet complete. The pull clears the
        // marker after the transaction publishes.
        match staging {
            CommitStaging::Held => {}
            CommitStaging::Import(src) => {
                self.import_from(
                    ctx.txn,
                    src,
                    name,
                    ctx.flags | PullFlags::UNTRUSTED,
                    read_buf,
                )
                .await?;
            }
            CommitStaging::Write => {
                ctx.txn
                    .write_metadata(ObjectType::Commit, Some(&checksum), &bytes)
                    .await?;
            }
        }
        // The commit object is here, so the pull stages its detached metadata
        // now. The transaction commit writes it before the ref that names the
        // commit. A verifier that reads the signatures with the commit needs
        // this order. For a commit that this repository already holds, the
        // copy of the remote replaces the copy here. That is the purpose of a
        // new read of a mutable file on each pull.
        //
        // The filter runs here, after the checks read the metadata as the
        // remote holds it. So a filter drops a property from what the pull
        // stores, and the verified metadata stays whole. A filter that allows
        // no property stages nothing, and the copy of this repository stays as
        // it is.
        if let Some(meta) = detached
            && let Some(meta) = ctx.detached_filter.apply(&checksum, meta)?
        {
            ctx.txn.stage_commit_detached_bytes(&checksum, meta).await?;
        }
        // Where the objects of the commit come from. A commit that is complete
        // here needs none of them: what it references is present. Its parent
        // is a different case. The depth of an earlier pull can be smaller
        // than the depth of this pull. So the chain walks on, and the step of
        // the parent decides what it needs.
        let tree = vec![
            ObjectName::new(commit.root_dirmeta, ObjectType::DirMeta),
            ObjectName::new(commit.root_dirtree, ObjectType::DirTree),
        ];
        let next = if complete || ctx.flags.contains(PullFlags::COMMIT_ONLY) {
            CommitNext::Nothing
        } else if let Some(job) = ctx.deltas.get(&checksum) {
            // A delta delivers the tree: its parts, and the objects that it
            // names and hands over loose. The tree walk comes after the last
            // part. It finds each object that no part delivered and fetches it
            // loose.
            CommitNext::Delta {
                parts: job.parts(),
                fallbacks: job.fallbacks(),
                tree,
            }
        } else {
            CommitNext::Scan(tree)
        };
        Ok(Step::Commit(CommitOutcome {
            checksum,
            next,
            parent: commit.parent,
            marked: !complete,
        }))
    }

    /// Reads the `.commitmeta` of a commit from the first localcache source
    /// that holds it, else from the remote. The caller writes the bytes when
    /// the commit object is here. A 404 means that the commit has none, and
    /// the copy of this repository stays as it is.
    async fn fetch_detached_metadata(
        &self,
        ctx: &StepCtx<'_>,
        commit: &Checksum,
    ) -> Result<Option<Vec<u8>>> {
        if let Some(bytes) = cached_detached_metadata(ctx.sources, commit).await? {
            return Ok(Some(bytes));
        }
        self.fetch_remote_detached(ctx, commit).await
    }

    /// Fetches the `.commitmeta` of a commit from the remote, or `None` if the
    /// remote serves none.
    async fn fetch_remote_detached(
        &self,
        ctx: &StepCtx<'_>,
        commit: &Checksum,
    ) -> Result<Option<Vec<u8>>> {
        let path = object_path(commit, ObjectType::CommitMeta);
        let fetched = ctx
            .source
            .read_optional(&path, Priority::High, MAX_METADATA_SIZE)
            .await?;
        if fetched.is_some() {
            ctx.progress.metadata_fetched();
        }
        Ok(fetched)
    }

    /// Fetches a commit that only the remote can give, with its detached
    /// metadata. The `.commitmeta` comes from the first localcache source that
    /// holds it, else from the remote. The commit object comes after it.
    /// `None` in either place is a file that the remote does not serve.
    ///
    /// Over ssh, the two remote requests are in flight together, in the order
    /// of an HTTP pull, so the pair costs one round trip. Over HTTP, the pull
    /// requests the commit after the `.commitmeta` arrives.
    async fn fetch_remote_commit(
        &self,
        ctx: &StepCtx<'_>,
        commit: &Checksum,
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        let path = object_path(commit, ObjectType::Commit);
        let fetch = || {
            ctx.source
                .read_optional(&path, Priority::High, MAX_METADATA_SIZE)
        };
        match cached_detached_metadata(ctx.sources, commit).await? {
            Some(detached) => Ok((Some(detached), fetch().await?)),
            None if matches!(ctx.source, RemoteSource::Ssh(_)) => {
                let (detached, fetched) =
                    futures_lite::future::zip(self.fetch_remote_detached(ctx, commit), fetch())
                        .await;
                Ok((detached?, fetched?))
            }
            None => {
                let detached = self.fetch_remote_detached(ctx, commit).await?;
                Ok((detached, fetch().await?))
            }
        }
    }

    /// Fetches one dirtree or dirmeta object and stores it. A dirtree also
    /// reports what it references, for the scan to walk on from.
    async fn fetch_metadata(
        &self,
        ctx: &StepCtx<'_>,
        name: ObjectName,
        read_buf: &mut Vec<u8>,
    ) -> Result<Step> {
        // The pull does not fetch an object that is here. It still reads a
        // dirtree: an object that it references can be missing, and the walk
        // finds that.
        if ctx.txn.is_staged(&name.checksum, name.ty)
            || self.has_object(name.ty, &name.checksum).await?
        {
            // An object that this transaction staged stays in the staging
            // directory until the transaction publishes. So the read looks in
            // the staged set before `objects/`.
            return self
                .walked(name, || ctx.txn.load_dirtree_staged_first(&name.checksum))
                .await;
        }
        if let Some(src) = cached_source(ctx.sources, name).await? {
            self.import_from(
                ctx.txn,
                src,
                name,
                ctx.flags | PullFlags::UNTRUSTED,
                read_buf,
            )
            .await?;
            return self.walked(name, || src.load_dirtree(&name.checksum)).await;
        }
        let path = object_path(&name.checksum, name.ty);
        let bytes = ctx
            .source
            .read_optional(&path, Priority::High, MAX_METADATA_SIZE)
            .await?
            .ok_or(Error::ObjectNotFound {
                checksum: name.checksum,
                ty: name.ty,
            })?;
        // The write path hashes the bytes and compares the result with the
        // requested name, so a substituted object fails here.
        ctx.txn
            .write_metadata(name.ty, Some(&name.checksum), &bytes)
            .await?;
        ctx.progress.metadata_fetched();
        match name.ty {
            ObjectType::DirTree => Ok(Step::DirTree(name.checksum, DirTree::parse(&bytes)?)),
            _ => Ok(Step::Done),
        }
    }

    /// Returns the step of a stored metadata object. A dirtree reports itself,
    /// for the plan to walk on from. Any other object is a leaf, so the method
    /// calls `load` only for a dirtree.
    async fn walked<F>(&self, name: ObjectName, load: impl FnOnce() -> F) -> Result<Step>
    where
        F: Future<Output = Result<DirTree>>,
    {
        if name.ty != ObjectType::DirTree {
            return Ok(Step::Done);
        }
        Ok(Step::DirTree(name.checksum, load().await?))
    }

    /// Fetches one content object and stores it.
    async fn fetch_content(
        &self,
        ctx: &StepCtx<'_>,
        name: ObjectName,
        read_buf: &mut Vec<u8>,
    ) -> Result<Step> {
        if ctx.txn.is_staged(&name.checksum, ObjectType::File)
            || self.has_object(ObjectType::File, &name.checksum).await?
        {
            return Ok(Step::Done);
        }
        if let Some(src) = cached_source(ctx.sources, name).await? {
            self.import_from(
                ctx.txn,
                src,
                name,
                ctx.flags | PullFlags::UNTRUSTED,
                read_buf,
            )
            .await?;
            return Ok(Step::Done);
        }
        // The pull requests a content object as `.filez`, whatever the remote
        // stores on its disk. The framed, deflated form is the one form that an
        // HTTP client can read.
        let path = object_path(&name.checksum, ObjectType::File);
        let fetcher = match ctx.source {
            RemoteSource::Http(fetcher) => fetcher,
            RemoteSource::Ssh(ssh) => {
                // A `.filez` has no whole read. The header read caps its header,
                // and the size that the header declares caps its payload.
                let body = ssh
                    .get(&path, u64::MAX)
                    .await?
                    .ok_or(Error::ObjectNotFound {
                        checksum: name.checksum,
                        ty: name.ty,
                    })?;
                // The ssh source takes no write permit. The session streams one
                // body at a time, and the depth of the pipeline bounds the
                // stores that finish after the end of their body. If the step
                // took a permit here, the permit holds the one reader of the
                // session while other stores finish.
                self.store_content(ctx, &name.checksum, body, read_buf)
                    .await
                    .map_err(session_error)?;
                ctx.progress.content_fetched();
                return Ok(Step::Done);
            }
        };
        // If a body fails in transit, the pull fetches it again from the
        // start, and the retry count of the fetcher pays for it. The write that
        // failed with it stages nothing, because an object is staged only
        // after the checksum comparison. The write removes its temp file when
        // it fails.
        let mut refetch = fetcher.refetching(FetchRequest {
            priority: Priority::Low,
            ..FetchRequest::path(&path)
        });
        loop {
            let body = match refetch.fetch().await {
                Ok(Fetched::Body(body)) => body,
                Ok(Fetched::NotModified) => {
                    return Err(Error::Fetch(format!(
                        "{path}: the remote answered 304 to an unconditional request"
                    )));
                }
                Err(e) => return Err(object_not_found(e.into(), name)),
            };
            // The step takes the write permit before it reads the body. A step
            // that waits for a permit did not ask the connection for bytes yet,
            // so the progress window of the fetcher does not run against it.
            // The permit covers the whole body: the header read, the payload,
            // and the end-of-stream read. The step releases it before a refetch
            // waits for its delay.
            let permit = ctx.writes.acquire(Priority::Normal).await;
            let stored = self
                .store_content(ctx, &name.checksum, body, read_buf)
                .await;
            drop(permit);
            match stored {
                Ok(()) => {
                    ctx.progress.content_fetched();
                    return Ok(Step::Done);
                }
                Err(e) => refetch.retry(e).await?,
            }
        }
    }

    /// Stores one fetched content object under the requested name.
    ///
    /// The payload streams through `read_buf`, the buffer of the slot, so the
    /// objects that a slot stores share one allocation.
    async fn store_content<R: AsyncRead + Unpin>(
        &self,
        ctx: &StepCtx<'_>,
        expected: &Checksum,
        body: R,
        read_buf: &mut Vec<u8>,
    ) -> Result<()> {
        let (header, declared, framed_header, body) = read_archive_header(body).await?;
        let FileHeader {
            uid,
            gid,
            mode,
            symlink_target: _,
            xattrs,
        } = header.clone();
        let meta = FileMeta {
            uid,
            gid,
            mode,
            xattrs,
        };
        // The mode checks of a local pull, over the metadata in the header that
        // arrives with the object.
        ctx.checks.check(expected, &meta)?;
        store_filez_payload(
            ctx.txn,
            expected,
            &header,
            &meta,
            declared,
            &framed_header,
            body,
            read_buf,
        )
        .await
    }

    /// Refuses a fetched tip that is older than the commit of the check.
    async fn check_timestamp(
        &self,
        ctx: &StepCtx<'_>,
        ref_name: &str,
        tip: &Checksum,
        fetched: &Commit,
    ) -> Result<()> {
        let against = match ctx.timestamp_check {
            TimestampCheck::Off => return Ok(()),
            TimestampCheck::CurrentRef => {
                let current = self
                    .resolve_ref_tip(&refspec(ctx.ref_prefix, ref_name))
                    .await?;
                // A ref that this repository does not hold has nothing to be
                // older than.
                let Some(current) = current else {
                    return Ok(());
                };
                current
            }
            TimestampCheck::Rev(rev) => *rev,
        };
        let bytes = self.load_object_bytes(ObjectType::Commit, &against).await?;
        let current = Commit::parse(&bytes)?;
        if fetched.timestamp >= current.timestamp {
            return Ok(());
        }
        Err(Error::Pull(format!(
            "commit {tip} (timestamp {}) is chronologically older than \
             {against} (timestamp {})",
            fetched.timestamp, current.timestamp
        )))
    }
}

/// What a pull fetched into its transaction, for the transaction commit.
struct FetchedPull {
    txn: Transaction,
    /// The refs to write, and the commit each names.
    targets: Vec<(String, Checksum)>,
    /// The `summary` and `summary.sig` of the remote, which a mirror pull of
    /// every ref copies.
    summary: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
}

/// Refuses a field of [`connect`](PullOptions::connect) that applies to a pull
/// over ssh alone. The pull does not read the remote ssh command, as an HTTP
/// push does not read it.
fn refuse_ssh_fields(opts: &PullOptions) -> Result<()> {
    // Each name is the remote key of the field.
    let set = [
        ("ssh-command", opts.connect.ssh_command.is_some()),
        ("send-command", opts.connect.send_command.is_some()),
    ];
    match set.iter().find(|(_, set)| *set) {
        Some((name, _)) => Err(Error::InvalidInput(format!(
            "{name} applies to a pull over ssh, and this pull runs over HTTP"
        ))),
        None => Ok(()),
    }
}

/// Returns the options of the pull session of `opts`.
fn session_options(opts: &PullOptions) -> PullSessionOptions {
    PullSessionOptions {
        agent: None,
        max_outstanding: Some(opts.max_outstanding_fetches.unwrap_or(DEFAULT_OUTSTANDING)),
    }
}

/// The state that every step of one pull shares.
struct StepCtx<'a> {
    txn: &'a Transaction,
    source: &'a RemoteSource,
    /// The write throttle: the number of fetched content objects that stream
    /// into the object store at once.
    writes: Arc<Gate>,
    /// The repositories that the pull reads for an object before the network,
    /// in order.
    sources: &'a [Repo],
    flags: PullFlags,
    /// The mode checks for each content object that this pull writes, on each
    /// path: a loose fetch, a localcache import, or the parts of a static
    /// delta.
    checks: ModeChecks,
    /// The prefix of the pulled refs. The timestamp check resolves the current
    /// tip of a ref through it. `None` is a local ref.
    ref_prefix: Option<&'a str>,
    timestamp_check: &'a TimestampCheck,
    /// The requested refs of each tip commit, for the binding check and the
    /// timestamp check. A commit with no entry is a parent under `depth`,
    /// which no ref names.
    tips: &'a HashMap<Checksum, Vec<String>>,
    /// The static delta that delivers each target commit, if the remote
    /// publishes one. The pull fetches a commit with no entry object by
    /// object.
    deltas: &'a HashMap<Checksum, DeltaJob>,
    /// The signature policy of this pull. The pull verifies each commit of a
    /// step before it stages its bytes.
    verification: &'a Verification,
    /// The filter of the properties of detached metadata that this pull
    /// stores. It applies after the checks of the commit pass.
    detached_filter: &'a DetachedMetadataFilter,
    /// The live counters of the pull.
    progress: &'a PullCounters,
}

/// One commit to fetch.
struct CommitItem {
    checksum: Checksum,
    /// The number of parents to follow from here, `-1` for all of them.
    depth: i32,
    /// `true` if a remote that does not hold this commit ends the chain, and
    /// the pull goes on. A parent under `depth` has this value.
    optional: bool,
}

/// One part of the delta of one commit.
struct PartItem {
    /// The commit that the delta produces, which is the key of the job.
    commit: Checksum,
    /// The index of the part. It is the position of the part in the entry
    /// list of the superblock, and its file name on the remote.
    index: usize,
}

/// One unit of work that a slot runs.
enum Item {
    Commit(CommitItem),
    Object(ObjectName),
    Part(PartItem),
}

/// The outcome of one step.
enum Step {
    /// A commit object arrived, or was already here.
    Commit(CommitOutcome),
    /// A dirtree is stored: its checksum and its entries, which the plan walks
    /// on from.
    DirTree(Checksum, DirTree),
    /// A delta part is applied. The value is the commit of the part.
    Part(Checksum),
    /// Nothing follows: a dirmeta or content object is stored, or a parent
    /// that the remote does not hold ended its chain.
    Done,
}

/// What a commit adds to the plan.
struct CommitOutcome {
    checksum: Checksum,
    /// How the pull fetches the objects of the commit.
    next: CommitNext,
    /// The parent to follow under `depth`.
    parent: Option<Checksum>,
    /// `true` if this pull wrote the `.commitpartial` marker of the commit.
    marked: bool,
}

/// How a commit object reaches the object store, after the commit passes the
/// checks of its step.
enum CommitStaging<'a> {
    /// This repository holds it.
    Held,
    /// A localcache repository holds it, and the pull imports it from there.
    Import(&'a Repo),
    /// Its bytes are in memory, and the pull writes them into the transaction.
    Write,
}

/// How the objects of a commit reach this repository.
enum CommitNext {
    /// Object by object: the root dirmeta and dirtree of the commit, and the
    /// walk from there.
    Scan(Vec<ObjectName>),
    /// By static delta: the parts of the delta, the objects that it hands over
    /// loose, and the tree walk after the last part.
    Delta {
        parts: usize,
        fallbacks: Vec<ObjectName>,
        tree: Vec<ObjectName>,
    },
    /// Nothing: the commit is complete here, or the pull is commit-only.
    Nothing,
}

/// The work that the pull must still do, and the work that it did.
///
/// The loop owns the plan, so nothing here is shared or locked.
#[derive(Default)]
struct Plan {
    /// The commits, drained first and fetched at high priority.
    commits: VecDeque<CommitItem>,
    /// The delta parts, drained second and fetched at high priority. At most
    /// [`PART_CAP`] are in flight, whatever the slot count of the pull.
    parts: VecDeque<PartItem>,
    /// The number of part fetches in flight.
    parts_in_flight: usize,
    /// The number of parts of the delta of each commit that are not applied
    /// yet. When that count is zero, the plan queues the tree walk that
    /// `delta_trees` holds.
    delta_parts: HashMap<Checksum, usize>,
    delta_trees: HashMap<Checksum, Vec<ObjectName>>,
    /// The dirtree and dirmeta objects that the walk waits for, drained third
    /// and fetched at high priority.
    scan: VecDeque<ObjectName>,
    /// The content objects, drained last and fetched at low priority.
    content: VecDeque<ObjectName>,
    /// The objects that this pull queued, so that the pull fetches an object
    /// once, also if several commits reach it.
    queued: HashSet<ObjectName>,
    /// The subpaths of the walk. `None` walks every tree whole.
    subpaths: Option<Subpaths>,
    /// The scope of the walk of the root dirtree of each commit.
    root: Scope,
    /// The dirtrees queued under a scope smaller than the whole tree. Each
    /// entry holds the scope of the walk, and a flag that tells if the plan
    /// applied that walk.
    ///
    /// If the plan reaches a dirtree again under a scope that its scope does
    /// not cover, the plan widens its scope. A dirtree that is still queued or
    /// in flight gets the walk under the wider scope when the plan applies its
    /// step. The plan queues a walked dirtree again, and that second step reads
    /// the dirtree that this pull stored.
    partial_trees: HashMap<Checksum, PartialTree>,
    /// The remaining depth at which the plan reached each commit. It decides
    /// if a chain that reaches the commit again walks on from it.
    seen: HashMap<Checksum, i32>,
    /// The parent that each fetched commit named. A chain that reaches the
    /// commit again, with more depth, resumes at the parent and does not fetch
    /// the commit again.
    parents: HashMap<Checksum, Option<Checksum>>,
}

/// A dirtree walked under a scope smaller than the whole tree.
struct PartialTree {
    scope: Scope,
    walked: bool,
}

impl Plan {
    /// Creates a plan whose walk keeps to `subpaths`.
    fn new(subpaths: Option<Subpaths>) -> Plan {
        Plan {
            root: subpaths.as_ref().map(Subpaths::root).unwrap_or_default(),
            subpaths,
            ..Plan::default()
        }
    }

    /// Queues a commit, unless the plan reached it at this depth or deeper.
    ///
    /// The plan does not fetch again a commit that it reaches again with more
    /// depth: the walk resumes at the parent that the commit named. A commit
    /// still in flight named no parent yet. Its own outcome follows the parent
    /// to the depth recorded here.
    fn push_commit(&mut self, mut item: CommitItem) {
        loop {
            if let Some(&prev) = self.seen.get(&item.checksum)
                && reaches_at_least(prev, item.depth)
            {
                return;
            }
            let depth = item.depth;
            if self.seen.insert(item.checksum, depth).is_none() {
                self.commits.push_back(item);
                return;
            }
            if depth == 0 {
                return;
            }
            let Some(Some(parent)) = self.parents.get(&item.checksum).copied() else {
                return;
            };
            item = CommitItem {
                checksum: parent,
                depth: one_less(depth),
                optional: true,
            };
        }
    }

    /// Queues an object that this pull did not queue yet, and a dirtree that it
    /// queued under a scope that does not cover `scope`.
    fn push_object(&mut self, name: ObjectName, scope: Scope) {
        if self.queued.insert(name) {
            if name.ty == ObjectType::DirTree && scope != Scope::All {
                self.partial_trees.insert(
                    name.checksum,
                    PartialTree {
                        scope,
                        walked: false,
                    },
                );
            }
            match name.ty {
                ObjectType::File => self.content.push_back(name),
                _ => self.scan.push_back(name),
            }
            return;
        }
        if name.ty != ObjectType::DirTree {
            return;
        }
        // A dirtree with no entry here was queued whole.
        let Some(tree) = self.partial_trees.get_mut(&name.checksum) else {
            return;
        };
        if tree.scope.covers(&scope) {
            return;
        }
        tree.scope.widen(&scope);
        if tree.walked {
            tree.walked = false;
            self.scan.push_back(name);
        }
    }

    /// Queues one object of the tree of a commit: the root dirtree under the
    /// root scope, or the root dirmeta.
    fn push_root(&mut self, name: ObjectName) {
        let scope = if name.ty == ObjectType::DirTree {
            self.root.clone()
        } else {
            Scope::All
        };
        self.push_object(name, scope);
    }

    /// Queues the objects that a stored dirtree references, under the scope of
    /// its walk.
    fn apply_dirtree(&mut self, checksum: Checksum, dirtree: &DirTree) {
        let Some(subpaths) = &self.subpaths else {
            for name in children_of(dirtree) {
                self.push_object(name, Scope::All);
            }
            return;
        };
        let scope = match self.partial_trees.get_mut(&checksum) {
            Some(tree) => {
                tree.walked = true;
                tree.scope.clone()
            }
            None => Scope::All,
        };
        for (name, scope) in subpaths.children(dirtree, &scope) {
            self.push_object(name, scope);
        }
    }

    /// Returns the next unit of work: the commits, then the delta parts, then
    /// the scan, then the content.
    ///
    /// The plan holds back a queued part while [`PART_CAP`] parts are in
    /// flight. A pull with more slots spends the other slots on the scan and
    /// the content. The loop can run out of work while parts are queued. This
    /// is safe: the plan holds back a part only while a part is in flight, in a
    /// slot that the loop waits on.
    fn next(&mut self) -> Option<Item> {
        if let Some(commit) = self.commits.pop_front() {
            return Some(Item::Commit(commit));
        }
        if self.parts_in_flight < PART_CAP
            && let Some(part) = self.parts.pop_front()
        {
            self.parts_in_flight += 1;
            return Some(Item::Part(part));
        }
        if let Some(name) = self.scan.pop_front() {
            return Some(Item::Object(name));
        }
        self.content.pop_front().map(Item::Object)
    }

    /// Stores the progress total and the scan state: the `started` units of
    /// work given to a slot, and the queued work.
    fn report(&self, progress: &PullCounters, started: usize) {
        let queued = self.commits.len() + self.parts.len() + self.scan.len() + self.content.len();
        let total = u32::try_from(started + queued).unwrap_or(u32::MAX);
        progress.report(total, !self.commits.is_empty() || !self.scan.is_empty());
    }

    /// Adds the outcome of one step to the plan.
    fn apply(&mut self, step: Step, marked: &mut Vec<Checksum>) {
        match step {
            Step::Commit(outcome) => self.apply_commit(outcome, marked),
            Step::DirTree(checksum, dirtree) => self.apply_dirtree(checksum, &dirtree),
            Step::Part(commit) => self.apply_part(commit),
            Step::Done => {}
        }
    }

    /// Records an applied delta part. After the last part of the delta, queues
    /// the tree walk of its commit.
    fn apply_part(&mut self, commit: Checksum) {
        self.parts_in_flight -= 1;
        let left = self
            .delta_parts
            .get_mut(&commit)
            .expect("an applied part belongs to a commit whose delta is counted");
        *left -= 1;
        if *left > 0 {
            return;
        }
        self.delta_parts.remove(&commit);
        // Each object of the delta is staged now. The walk reads what is here,
        // and requests from the network only what the delta left out.
        for name in self.delta_trees.remove(&commit).unwrap_or_default() {
            self.push_root(name);
        }
    }

    /// Records a commit and queues what it needs.
    fn apply_commit(&mut self, outcome: CommitOutcome, marked: &mut Vec<Checksum>) {
        if outcome.marked {
            marked.push(outcome.checksum);
        }
        self.parents.insert(outcome.checksum, outcome.parent);
        match outcome.next {
            CommitNext::Nothing => {}
            CommitNext::Scan(tree) => {
                for name in tree {
                    self.push_root(name);
                }
            }
            CommitNext::Delta {
                parts,
                fallbacks,
                tree,
            } => {
                // The plan queues the objects that the delta hands over loose at
                // once, so they travel together with the parts.
                for name in fallbacks {
                    self.push_object(name, Scope::All);
                }
                if parts == 0 {
                    // A delta of fallbacks alone has no part to wait for.
                    for name in tree {
                        self.push_root(name);
                    }
                } else {
                    self.delta_parts.insert(outcome.checksum, parts);
                    self.delta_trees.insert(outcome.checksum, tree);
                    for index in 0..parts {
                        self.parts.push_back(PartItem {
                            commit: outcome.checksum,
                            index,
                        });
                    }
                }
            }
        }
        // The depth comes from the plan. A later chain can reach this commit
        // with more depth while the commit is in flight.
        let depth = self.seen.get(&outcome.checksum).copied().unwrap_or(0);
        if depth != 0
            && let Some(parent) = outcome.parent
        {
            self.push_commit(CommitItem {
                checksum: parent,
                depth: one_less(depth),
                optional: true,
            });
        }
    }
}

/// Returns the depth after one parent: a finite depth counts down, and `-1`
/// stays `-1`.
fn one_less(depth: i32) -> i32 {
    if depth > 0 { depth - 1 } else { depth }
}

/// Returns the objects that a dirtree references: its files, and the dirmeta
/// and dirtree of each subdirectory.
fn children_of(dirtree: &DirTree) -> Vec<ObjectName> {
    let mut out = Vec::with_capacity(dirtree.files.len() + 2 * dirtree.dirs.len());
    for (_, file) in &dirtree.files {
        out.push(ObjectName::new(*file, ObjectType::File));
    }
    for (_, subtree, submeta) in &dirtree.dirs {
        out.push(ObjectName::new(*submeta, ObjectType::DirMeta));
        out.push(ObjectName::new(*subtree, ObjectType::DirTree));
    }
    out
}

/// Returns the request path of a loose object. The remote is an archive
/// repository, so a content object has the name `.filez` there, whatever this
/// repository stores.
fn object_path(checksum: &Checksum, ty: ObjectType) -> String {
    format!("objects/{}", loose_path(checksum, ty, RepoMode::Archive))
}

/// Returns the `.commitmeta` of a commit from the first localcache repository
/// that holds it.
async fn cached_detached_metadata(sources: &[Repo], commit: &Checksum) -> Result<Option<Vec<u8>>> {
    for src in sources {
        match src.load_object_bytes(ObjectType::CommitMeta, commit).await {
            Ok(bytes) => return Ok(Some(bytes)),
            Err(Error::ObjectNotFound { .. }) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Returns the first localcache repository that holds `name`.
async fn cached_source(sources: &[Repo], name: ObjectName) -> Result<Option<&Repo>> {
    for src in sources {
        if src.has_object(name.ty, &name.checksum).await? {
            return Ok(Some(src));
        }
    }
    Ok(None)
}

/// Maps a 404 for an object to [`Error::ObjectNotFound`]. Any other error
/// stays as it is.
fn object_not_found(error: Error, name: ObjectName) -> Error {
    match error {
        Error::HttpStatus { status: 404, .. } => Error::ObjectNotFound {
            checksum: name.checksum,
            ty: name.ty,
        },
        other => other,
    }
}

/// Fetches the summary of the remote and its signature. An absent file is
/// `None`.
///
/// The signature comes first, which is the order of the `ostree` command. The
/// signature covers the summary that follows. In the other order, a summary
/// can pair with the signature of a summary that the remote replaced before.
pub(super) async fn fetch_summary(fetcher: &Fetcher) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let signature =
        fetch_optional(fetcher, SUMMARY_SIG_FILE, Priority::High, MAX_ROOT_FILE).await?;
    let summary = fetch_optional(fetcher, SUMMARY_FILE, Priority::High, MAX_ROOT_FILE).await?;
    Ok((summary, signature))
}

/// Refuses a remote whose `[core] mode` is not archive, from the bytes of its
/// `config`.
fn check_remote_mode(config: Option<Vec<u8>>) -> Result<()> {
    let Some(bytes) = config else {
        // The pull reads a remote that serves no config as an archive,
        // because the remote serves `.filez` objects.
        return Ok(());
    };
    let text = String::from_utf8(bytes)
        .map_err(|_| Error::InvalidFormat("the remote config is not valid utf-8".into()))?;
    let config = RepoConfig::parse(&text)?;
    if config.mode().is_archive() {
        return Ok(());
    }
    Err(Error::Unsupported(format!(
        "can't pull from a remote in mode {}: an http pull reads an archive \
         repository, whose content objects are served in the framed, deflated \
         form a client can store",
        config.mode().as_mode_str()
    )))
}

/// Returns the commit that `refs/heads/<name>` of the remote names, or `None`
/// if the remote serves no such ref.
async fn fetch_remote_ref(source: &RemoteSource, name: &str) -> Result<Option<Checksum>> {
    let path = source.ref_path(name);
    let Some(bytes) = source
        .read_optional(&path, Priority::High, MAX_REF_FILE)
        .await?
    else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::InvalidFormat(format!("the remote ref {name} is not valid utf-8")))?;
    Ok(Some(Checksum::from_hex(text.trim())?))
}

/// Returns the request path of a remote ref: `refs/heads/` and the
/// percent-encoded name.
///
/// A request path goes on the wire as written, so this function encodes the
/// name. It encodes each byte outside the unreserved set of RFC 3986: the
/// ASCII letters and digits, `-`, `.`, `_`, and `~`. It keeps `/`, which
/// separates the components of the name and of the path.
///
/// A `?`, `#`, or `%` in a name is so part of the ref name. The server cannot
/// read it as a query, a fragment, or an escape that decodes into a different
/// name.
pub(super) fn ref_request_path(name: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::from("refs/heads/");
    for byte in name.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(char::from(byte));
            }
            other => {
                out.push('%');
                out.push(char::from(HEX[usize::from(other >> 4)]));
                out.push(char::from(HEX[usize::from(other & 0x0f)]));
            }
        }
    }
    out
}

/// Returns the low-speed rule of the fetcher of a pull. A field left `None`
/// takes its default, and a zero in either field turns the rule off.
fn low_speed(opts: &PullOptions) -> Option<LowSpeed> {
    let limit = opts
        .low_speed_limit_bytes
        .unwrap_or(DEFAULT_LOW_SPEED_LIMIT);
    let time = opts.low_speed_time.unwrap_or(DEFAULT_LOW_SPEED_TIME);
    (limit != 0 && !time.is_zero()).then_some(LowSpeed { limit, time })
}

/// Fetches a path whole, or returns `None` if the remote answers 404.
pub(crate) async fn fetch_optional(
    fetcher: &Fetcher,
    path: &str,
    priority: Priority,
    max_size: u64,
) -> Result<Option<Vec<u8>>> {
    match fetch_whole(fetcher, path, priority, max_size).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::HttpStatus { status: 404, .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Fetches a path whole, under a size cap.
///
/// The fetcher refuses a declared `Content-Length` above the cap before it
/// reads the body. It stops a body that passes the cap when the bytes arrive.
/// Each fetch in flight has one buffer, so the cap of the caller bounds the
/// memory of one step:
///
/// - [`MAX_METADATA_SIZE`] for a metadata object
/// - [`MAX_ROOT_FILE`] for a repository-root file
/// - [`MAX_REF_FILE`] for a `refs/heads/<ref>` file
///
/// The size of the buffer comes from the declared length, which the fetcher
/// held to the cap. The body so goes into one allocation of its own size, and
/// the resident peak is the cap. Each read goes into a chunk of at most
/// 128 KiB, and the function appends the chunk to the buffer.
///
/// No read touches the rest of the buffer, also if the body arrives slowly and
/// a read waits many times. The final read, which finds the end of the stream,
/// goes into the chunk, so a buffer filled to its declared length does not
/// grow. If the remote declares no length, the buffer grows as the function
/// reads, under the same cap.
///
/// If a body fails in transit, the function fetches it again from the start,
/// into a new buffer. It does so while the retry count of the fetcher has a
/// repeat left.
async fn fetch_whole(
    fetcher: &Fetcher,
    path: &str,
    priority: Priority,
    max_size: u64,
) -> Result<Vec<u8>> {
    let mut refetch = fetcher.refetching(FetchRequest {
        priority,
        max_size: Some(max_size),
        ..FetchRequest::path(path)
    });
    loop {
        let Fetched::Body(body) = refetch.fetch().await? else {
            return Err(Error::Fetch(format!(
                "{path}: the remote answered 304 to an unconditional request"
            )));
        };
        let declared = body.content_length();
        match read_whole(body, declared, max_size).await {
            Ok(out) => return Ok(out),
            Err(e) => refetch.retry(Error::from(e)).await?,
        }
    }
}

/// Reads `body` to its end into one buffer. The size of the buffer comes from
/// `declared`, the declared length, which the source held to `max_size`. Each
/// read goes into a bounded chunk, also the read that finds the end of the
/// body. So a buffer filled to its declared length does not grow.
pub(super) async fn read_whole<R: AsyncRead + Unpin>(
    mut body: R,
    declared: Option<u64>,
    max_size: u64,
) -> std::io::Result<Vec<u8>> {
    let declared = usize::try_from(declared.unwrap_or(0).min(max_size)).unwrap_or(0);
    let mut out = Vec::with_capacity(declared);
    let mut chunk = vec![0u8; declared.saturating_add(1).clamp(4096, IO_CHUNK)];
    loop {
        let n = body.read(&mut chunk).await?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

/// Reads the archive framing off the front of the stream of a content object.
///
/// The framing is a four-byte big-endian header length, four zero bytes, and
/// then the header. The rest of the stream is the raw-DEFLATE payload.
///
/// The function also returns the size that the header declares for the
/// payload. This size bounds the decompressed payload. The function also
/// returns the raw framed bytes: the length prefix and the header variant, as
/// the remote sent them. A caller can store these bytes as they are, with no
/// new serialization of the parsed header.
///
/// The remote states the header length and supplies the bytes after it. So the
/// function refuses a length above [`MAX_FILE_HEADER_SIZE`] before it
/// allocates the buffer. That bound holds for each fetch in flight, because
/// each content object has one header.
async fn read_archive_header<R: AsyncRead + Unpin>(
    mut stream: R,
) -> Result<(FileHeader, u64, Vec<u8>, R)> {
    let mut prefix = [0u8; 8];
    stream.read_exact(&mut prefix).await?;
    if prefix[4..] != [0u8; 4] {
        return Err(Error::InvalidFormat(
            "content framing padding is not zero".into(),
        ));
    }
    let header_len =
        u32::from_be_bytes(prefix[..4].try_into().expect("four bytes of a length")) as u64;
    if header_len > MAX_FILE_HEADER_SIZE {
        return Err(Error::InvalidFormat(
            "content header exceeds the size cap".into(),
        ));
    }
    let mut bytes = vec![0u8; header_len as usize];
    stream.read_exact(&mut bytes).await?;
    let (header, uncompressed) = FileHeader::parse_archive(&bytes)?;
    let mut framed = prefix.to_vec();
    framed.extend_from_slice(&bytes);
    Ok((header, uncompressed, framed, stream))
}

/// Stores one content object in the archive wire form, from the stream after
/// its framed header.
///
/// `header` and `declared` come from [`read_archive_header`], and
/// `framed_header` is the framing that it read. `meta` is the logical metadata
/// of `header`, which the caller checked against the destination mode.
///
/// A symlink carries no payload, so its stream must end after the header. An
/// archive destination stores the compressed bytes as they arrive. Each other
/// mode inflates them into a content writer. Both sides of the payload are
/// held to `declared`.
///
/// On each of the three paths, the function reads the stream to its end
/// before it stores the object. Each destination refuses a payload that
/// inflates to fewer bytes than `declared`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn store_filez_payload<R: AsyncRead + Unpin>(
    txn: &Transaction,
    expected: &Checksum,
    header: &FileHeader,
    meta: &FileMeta,
    declared: u64,
    framed_header: &[u8],
    mut body: R,
    read_buf: &mut Vec<u8>,
) -> Result<()> {
    if header.is_symlink() {
        check_stream_end(expected, "symlink header", &mut body).await?;
        txn.write_symlink(&header.symlink_target, meta, Some(expected))
            .await?;
        return Ok(());
    }
    // The declared size bounds both sides of the payload: the decompressed
    // size, and the bytes that come off the connection to produce it.
    let source = BoundedInput::new(body, *expected, compressed_bound(declared));
    if txn.repo().mode().is_archive() {
        // The remote stores this object deflated, in the wire form that this
        // destination writes. So the fetched bytes go to disk as they are,
        // with no inflate and no new compression.
        txn.write_archive_payload(expected, header, framed_header, declared, source, read_buf)
            .await
            .map_err(payload_refusal)?;
        return Ok(());
    }
    let mut writer = txn.content_writer(Some(expected), meta).await?;
    let mut payload = DeflateDecoder::new(BufSource::new(source));
    let short = copy_bounded(&mut payload, &mut writer, read_buf, expected, declared)
        .await
        .map_err(payload_refusal)?;
    if short != 0 {
        return Err(Error::InvalidFormat(format!(
            "content object {expected}: the payload inflates to {} byte(s), not the \
             {declared} its header declares",
            declared - short
        )));
    }
    // The decoder stops at the DEFLATE end-of-stream marker and asks its
    // input for no more bytes. So the function must read the stream to its
    // end here. That read returns the connection to the pool for the next
    // object, and moves a pull session to its next reply. It comes before
    // the finish of the writer, so the next reply arrives while this object
    // is stored.
    check_stream_end(expected, "deflated payload", payload.into_inner())
        .await
        .map_err(payload_refusal)?;
    writer.finish().await?;
    Ok(())
}

/// Streams the payload of a content object into `writer`, and stops if the
/// payload grows past the size that its header declared. Returns the number of
/// declared bytes that the payload did not hold.
///
/// A correct object decompresses to exactly `declared`. A stream that passes
/// it is corrupt or built to expand, so the rest of it has no value. The
/// checksum of the object covers the declared size only at the comparison at
/// the end of the payload. This bound limits the bytes written before that
/// comparison.
///
/// Each read is clamped to the bytes left plus the one byte that decides the
/// result. So at most one byte past the declaration is stored before the
/// refusal.
///
/// `buf` is the read buffer of the slot. It grows to [`READ_CHUNK`] on its
/// first use, and each later object of that slot uses it again.
///
/// [`BoundedInput`], under the decoder, bounds the compressed side of the same
/// declaration.
async fn copy_bounded<R, W>(
    mut reader: R,
    writer: &mut W,
    buf: &mut Vec<u8>,
    expected: &Checksum,
    declared: u64,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: futures_io::AsyncWrite + Unpin,
{
    if buf.len() < READ_CHUNK {
        buf.resize(READ_CHUNK, 0);
    }
    let mut left = declared;
    loop {
        let window = buf.len().min(
            usize::try_from(left)
                .unwrap_or(usize::MAX)
                .saturating_add(1),
        );
        let n = reader.read(&mut buf[..window]).await?;
        if n == 0 {
            return Ok(left);
        }
        if n as u64 > left {
            return Err(Error::InvalidFormat(format!(
                "content object {expected}: the payload outgrew the {declared} \
                 byte(s) its header declares"
            )));
        }
        left -= n as u64;
        writer.write_all(&buf[..n]).await?;
    }
}

/// Returns the number of bytes that a payload of `declared` uncompressed bytes
/// can take off the connection.
///
/// A DEFLATE compressor uses a stored block for data that it cannot shrink:
/// five bytes of framing for each 65535 bytes of input. That is one part in
/// thirteen thousand, and one part in 1024 covers it with a margin. The fixed
/// 64 KiB covers a small object, whose framing is larger than its content. A
/// stream past this bound is not a compressed form of the declared size,
/// whatever it decompresses to.
pub(crate) fn compressed_bound(declared: u64) -> u64 {
    declared
        .saturating_add(declared / 1024)
        .saturating_add(64 * 1024)
}

/// The compressed stream of a content object, bounded by the size that its
/// header declares.
///
/// [`copy_bounded`] bounds the decompressed payload. That bound does not limit
/// the compressed bytes that produce it. An empty non-final DEFLATE block is
/// five bytes that decompress to nothing. A stream of these blocks
/// decompresses to nothing for as long as the remote sends it.
///
/// Memory and disk then stay bounded, and time and bandwidth do not. The
/// decoder does not return to its caller while its input gives bytes. So the
/// bound on that input must be in the read of the decoder, which is this read.
///
/// The refusal is an [`Error::InvalidFormat`] in the `io::Error` that the
/// decoder passes up. [`payload_refusal`] takes it back out. The bound comes
/// from the declaration of the object, so the refusal names the object, as the
/// refusal of the decompressed size does.
pub(crate) struct BoundedInput<R> {
    inner: R,
    /// The object of the bound.
    checksum: Checksum,
    bound: u64,
    /// The bytes taken from `inner`. This count passes the bound by at most the
    /// one read that trips it.
    taken: u64,
}

impl<R> BoundedInput<R> {
    pub(crate) fn new(inner: R, checksum: Checksum, bound: u64) -> BoundedInput<R> {
        BoundedInput {
            inner,
            checksum,
            bound,
            taken: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BoundedInput<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        let n = ready!(Pin::new(&mut me.inner).poll_read(cx, buf))?;
        me.taken += n as u64;
        if me.taken > me.bound {
            return Poll::Ready(Err(std::io::Error::other(Error::InvalidFormat(format!(
                "content object {}: the compressed payload passed the {} byte(s) \
                 its declared size allows",
                me.checksum, me.bound
            )))));
        }
        Poll::Ready(Ok(n))
    }
}

/// Takes back the refusal that a bounded read reported.
///
/// The decoder returns the failure of its input as its own failure. So a
/// refusal of [`BoundedInput`] arrives here in an `io::Error`. The unwrap gives
/// that refusal the same form as a refusal of [`copy_bounded`]. Any other error
/// stays as it is.
pub(crate) fn payload_refusal(error: Error) -> Error {
    match error {
        Error::Io(io) => io.downcast::<Error>().unwrap_or_else(Error::Io),
        other => other,
    }
}

/// Checks that the stream of a content object ends after `after`, and reads to
/// that end.
///
/// One byte decides it. The remote sends the framing that selects the check of
/// the caller. If bytes follow, the remote chose their length, and a read of
/// all of them holds all of them. If the object ends at the correct point,
/// this read reaches the end of its response. The read then returns the
/// connection to the pool for the next object.
///
/// The stream of the payload is the input buffer of the decoder. It gives back
/// the read-ahead that the decoder left before it asks the body for more
/// bytes. A correct object leaves none: nothing follows its final DEFLATE
/// block.
pub(crate) async fn check_stream_end<R: AsyncRead + Unpin>(
    expected: &Checksum,
    after: &str,
    mut stream: R,
) -> Result<()> {
    let mut byte = [0u8; 1];
    if stream.read(&mut byte).await? != 0 {
        return Err(Error::InvalidFormat(format!(
            "content object {expected}: bytes follow the {after}"
        )));
    }
    Ok(())
}

/// Reads the proxy that the `proxy` key of a remote names. An empty or absent
/// key leaves the proxy to the environment variables.
///
/// The function refuses a value with white space at its start or end, as the
/// `ostree` command refuses it. The fetcher trims a proxy URL, so without this
/// check it connects through such a value. The message leaves out the value,
/// because the userinfo of the value can hold a password.
fn remote_proxy(remote: &str, section: &crate::config::Remote<'_>) -> Result<Proxy> {
    Ok(match section.proxy()? {
        Some(url) if url.trim() != url => {
            return Err(Error::Unsupported(format!(
                "remote '{remote}': the proxy key has white space at the start or \
                 the end of its value"
            )));
        }
        Some(url) if !url.is_empty() => Proxy::Url(url),
        _ => Proxy::Environment,
    })
}

/// Reads the trust anchors and the client identity that the TLS keys of a
/// remote name.
async fn remote_tls(remote: &str, section: &crate::config::Remote<'_>) -> Result<TlsOptions> {
    // `tls-permissive` keeps the host name check and ignores `tls-ca-path`.
    // Both facts are observed on the `ostree` command: a CA that signed
    // nothing in the chain works, and a path that names an absent file works
    // too. So the function does not read the path, and an absent file is no
    // failure. `DangerousAcceptAnyChain` keeps the name check and takes the
    // chain as presented, so it is the setting that this mapping needs.
    //
    // `DangerousAcceptAnyChain` also drops the expiry check. That part is a
    // reading of ostrya, with no observation behind it. A peer verification
    // that ignores the CA path is libcurl peer verification turned off, and
    // that setting also drops the validity dates.
    let roots = if section.tls_permissive()? {
        TrustRoots::DangerousAcceptAnyChain
    } else {
        match section.tls_ca_path()? {
            Some(path) => TrustRoots::Pem(read_pem(&path).await?),
            None => TrustRoots::System,
        }
    };
    let client_identity = match (
        section.tls_client_cert_path()?,
        section.tls_client_key_path()?,
    ) {
        (Some(cert), Some(key)) => Some(ClientIdentity {
            cert_chain_pem: read_pem(&cert).await?,
            key_pem: read_pem(&key).await?,
            // A remote has no config key for a passphrase, so a remote client
            // key must need no passphrase.
            key_passphrase: None,
        }),
        (None, None) => None,
        _ => {
            return Err(Error::Pull(format!(
                "remote '{remote}': a client certificate needs both \
                 tls-client-cert-path and tls-client-key-path"
            )));
        }
    };
    Ok(TlsOptions {
        roots,
        client_identity,
    })
}

/// Reads a PEM file that the config names.
async fn read_pem(path: &str) -> Result<Vec<u8>> {
    let path = path.to_owned();
    ostrya_rt::unblock(move || std::fs::read(&path).map_err(Error::from)).await
}

/// A compile-time check that the future of a pull is `Send`: over HTTP,
/// through the ssh source, and from a local repository.
const _: fn() = || {
    fn assert_send<T: Send>(_: &T) {}
    let _ = |repo: &Repo| assert_send(&repo.pull("origin", PullOptions::default()));
    let _ = |repo: &Repo, src: &Repo| assert_send(&repo.pull_local(src, PullOptions::default()));
    let _ = |repo: &Repo| {
        assert_send(&repo.pull_over_stream(
            "origin",
            futures_lite::io::empty(),
            futures_lite::io::sink(),
            PullOptions::default(),
        ))
    };
};

#[cfg(test)]
mod tests {
    use super::*;
    use async_compression::futures::bufread::DeflateEncoder;
    use futures_lite::io::Cursor;
    use ostrya_core::Xattrs;
    use ostrya_rt::block_on;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// By default, a pull holds each transfer to 1000 bytes per second over 30
    /// seconds. A field left unset keeps its default, and a zero in either
    /// field turns the rule off.
    #[test]
    fn the_low_speed_rule_defaults_and_turns_off_at_zero() {
        let rule = |limit: Option<u32>, secs: Option<u64>| {
            low_speed(&PullOptions {
                low_speed_limit_bytes: limit,
                low_speed_time: secs.map(Duration::from_secs),
                ..PullOptions::default()
            })
        };
        let low = |limit, secs| {
            Some(LowSpeed {
                limit,
                time: Duration::from_secs(secs),
            })
        };
        assert_eq!(rule(None, None), low(1000, 30));
        assert_eq!(rule(Some(0), None), None);
        assert_eq!(rule(None, Some(0)), None);
        assert_eq!(rule(Some(0), Some(5)), None);
        assert_eq!(rule(Some(50), None), low(50, 30));
        assert_eq!(rule(None, Some(2)), low(1000, 2));
        assert_eq!(rule(Some(50), Some(2)), low(50, 2));
    }

    /// Returns the archive stored form of a content object: the framed header,
    /// then the payload that the caller supplies.
    fn framed(header: &FileHeader, uncompressed: u64, payload: &[u8]) -> Vec<u8> {
        let bytes = header.serialize_archive(uncompressed).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&bytes);
        out.extend_from_slice(payload);
        out
    }

    fn regular_header() -> FileHeader {
        FileHeader {
            uid: 0,
            gid: 0,
            mode: 0o100644,
            symlink_target: String::new(),
            xattrs: Xattrs::default(),
        }
    }

    /// The header comes off the front of the stream, and the rest is the
    /// payload, which goes to the decoder.
    #[test]
    fn the_header_is_read_off_the_front_and_the_payload_is_left() {
        block_on(async {
            let stored = framed(&regular_header(), 4, b"payload bytes");
            let (header, declared, raw, mut rest) =
                read_archive_header(Cursor::new(stored.clone()))
                    .await
                    .unwrap();
            assert_eq!(header, regular_header());
            assert_eq!(declared, 4);
            assert_eq!(raw, stored[..stored.len() - b"payload bytes".len()]);
            let mut payload = Vec::new();
            rest.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, b"payload bytes");
        });
    }

    /// The header of a symlink names its target, and its stored form carries no
    /// payload.
    #[test]
    fn a_symlink_header_names_its_target() {
        block_on(async {
            let header = FileHeader {
                uid: 0,
                gid: 0,
                mode: 0o120777,
                symlink_target: "hello.txt".to_owned(),
                xattrs: Xattrs::default(),
            };
            let stored = framed(&header, 0, b"");
            let (parsed, _declared, _raw, mut rest) =
                read_archive_header(Cursor::new(stored)).await.unwrap();
            assert!(parsed.is_symlink());
            assert_eq!(parsed.symlink_target, "hello.txt");
            let mut payload = Vec::new();
            rest.read_to_end(&mut payload).await.unwrap();
            assert!(payload.is_empty());
        });
    }

    /// The four bytes after the length are padding and must be zero. Other
    /// bytes are not the framing that this reader reads.
    #[test]
    fn nonzero_framing_padding_is_rejected() {
        block_on(async {
            let mut stored = framed(&regular_header(), 0, b"");
            stored[5] = 1;
            let err = read_archive_header(Cursor::new(stored)).await.unwrap_err();
            assert!(err.to_string().contains("padding"), "{err}");
        });
    }

    /// A stream that ends inside the framing is a truncated object, and the
    /// read fails.
    #[test]
    fn a_truncated_stream_fails_rather_than_ending() {
        block_on(async {
            let stored = framed(&regular_header(), 0, b"");
            for cut in [4, 8, stored.len() - 1] {
                let err = read_archive_header(Cursor::new(stored[..cut].to_vec()))
                    .await
                    .unwrap_err();
                assert!(matches!(err, Error::Io(_)), "cut at {cut}: {err}");
            }
        });
    }

    /// A stream that never ends. Past a small budget it fails. So a check that
    /// reads to an end fails this test, and the process does not run out of
    /// memory.
    struct Endless {
        handed_out: usize,
    }

    impl AsyncRead for Endless {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.handed_out >= 4096 {
                return Poll::Ready(Err(std::io::Error::other("the check read past the header")));
            }
            buf.fill(0);
            self.handed_out += buf.len();
            Poll::Ready(Ok(buf.len()))
        }
    }

    /// A symlink whose stored form carries a payload is refused. The refusal
    /// reads one byte of the payload, and holds none of the length that the
    /// remote chose to send.
    #[test]
    fn a_symlink_payload_is_refused_without_reading_it() {
        block_on(async {
            let mut stream = Endless { handed_out: 0 };
            let err = check_stream_end(&csum(1), "symlink header", &mut stream)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("bytes follow"), "{err}");
            assert_eq!(stream.handed_out, 1);
        });
    }

    /// The decoder stops at the end of the DEFLATE stream and does not read the
    /// bytes after it. So the end-of-stream check runs over the input buffer of
    /// the decoder. A payload that ends the stream passes the check, and the
    /// check refuses trailing bytes that the decoder did not consume.
    #[test]
    fn the_check_sees_what_the_decoder_left_behind() {
        block_on(async {
            let mut encoder = DeflateEncoder::new(Cursor::new(b"hello ostree\n".to_vec()));
            let mut compressed = Vec::new();
            encoder.read_to_end(&mut compressed).await.unwrap();

            for (trailing, expect_end) in [(&b""[..], true), (b"junk", false)] {
                let mut stored = compressed.clone();
                stored.extend_from_slice(trailing);
                let mut decoder = DeflateDecoder::new(BufSource::new(Cursor::new(stored)));
                let mut out = Vec::new();
                copy_bounded(&mut decoder, &mut out, &mut Vec::new(), &csum(1), 13)
                    .await
                    .unwrap();
                assert_eq!(out, b"hello ostree\n");
                let result =
                    check_stream_end(&csum(1), "deflated payload", decoder.into_inner()).await;
                assert_eq!(
                    result.is_ok(),
                    expect_end,
                    "trailing {trailing:?}: {result:?}"
                );
            }
        });
    }

    /// A payload that decompresses past the size that its header declares is
    /// refused. The refusal reads one byte past the declaration, and no more of
    /// a stream that never ends.
    #[test]
    fn a_payload_outgrowing_its_declared_size_is_refused() {
        block_on(async {
            let mut stream = Endless { handed_out: 0 };
            let mut out = Vec::new();
            let err = copy_bounded(&mut stream, &mut out, &mut Vec::new(), &csum(1), 4)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("outgrew the 4 byte"), "{err}");
            assert_eq!(stream.handed_out, 5);
        });
    }

    /// A stream of empty non-final DEFLATE blocks: five bytes that decompress
    /// to nothing, repeated. Past a budget well above the bound under test it
    /// fails. So an unbounded compressed stream fails this test, and the
    /// process does not run out of memory.
    struct EmptyBlocks {
        handed_out: usize,
    }

    impl AsyncRead for EmptyBlocks {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            const BLOCK: [u8; 5] = [0x00, 0x00, 0x00, 0xff, 0xff];
            if self.handed_out >= 1024 * 1024 {
                return Poll::Ready(Err(std::io::Error::other(
                    "the payload read past its compressed bound",
                )));
            }
            let base = self.handed_out;
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte = BLOCK[(base + i) % BLOCK.len()];
            }
            self.handed_out += buf.len();
            Poll::Ready(Ok(buf.len()))
        }
    }

    /// A payload that decompresses to nothing for as long as it is sent is
    /// refused against the bound that its declared size sets. The decompressed
    /// bound never trips against it. The refusal reaches the caller as the
    /// refusal that it is. The stream delivered the bound plus the one read
    /// that tripped it.
    #[test]
    fn a_compressed_payload_passing_its_bound_is_refused() {
        block_on(async {
            let mut source = EmptyBlocks { handed_out: 0 };
            let mut out = Vec::new();
            let bound = compressed_bound(13);
            let err = {
                let source = BoundedInput::new(&mut source, csum(1), bound);
                let mut payload = DeflateDecoder::new(BufSource::new(source));
                copy_bounded(&mut payload, &mut out, &mut Vec::new(), &csum(1), 13)
                    .await
                    .unwrap_err()
            };
            let err = payload_refusal(err);
            assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
            assert!(
                err.to_string()
                    .contains(&format!("passed the {bound} byte")),
                "{err}"
            );
            assert!(out.is_empty());
            assert!(
                source.handed_out <= bound as usize + 16 * 1024,
                "{} bytes taken for a {bound}-byte bound",
                source.handed_out
            );
        });
    }

    /// The bound refuses no object of the size that it is stated for. Data that
    /// a compressor cannot shrink is the worst case, and its compressed form is
    /// inside the bound that its uncompressed size sets.
    #[test]
    fn the_compressed_bound_holds_incompressible_data() {
        block_on(async {
            // A linear congruential sequence, which DEFLATE cannot shrink.
            let mut state = 1u32;
            let data: Vec<u8> = (0..200_000)
                .map(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (state >> 24) as u8
                })
                .collect();
            let mut encoder = DeflateEncoder::new(Cursor::new(data.clone()));
            let mut compressed = Vec::new();
            encoder.read_to_end(&mut compressed).await.unwrap();
            let declared = data.len() as u64;
            let bound = compressed_bound(declared);
            assert!(
                compressed.len() as u64 <= bound,
                "{} compressed bytes for a {bound}-byte bound",
                compressed.len()
            );

            let source = BoundedInput::new(Cursor::new(compressed), csum(1), bound);
            let mut payload = DeflateDecoder::new(BufSource::new(source));
            let mut out = Vec::new();
            copy_bounded(&mut payload, &mut out, &mut Vec::new(), &csum(1), declared)
                .await
                .unwrap();
            assert_eq!(out, data);
        });
    }

    /// The declaration is a ceiling. A payload that reaches it is stored
    /// whole, and the checksum comparison decides a shorter one.
    #[test]
    fn a_payload_within_its_declared_size_is_stored() {
        block_on(async {
            // One buffer serves both objects, as the buffer of a slot does.
            let mut buf = Vec::new();
            for payload in [&b"four"[..], b"two"] {
                let mut out = Vec::new();
                copy_bounded(
                    Cursor::new(payload.to_vec()),
                    &mut out,
                    &mut buf,
                    &csum(1),
                    4,
                )
                .await
                .unwrap();
                assert_eq!(out, payload);
            }
            // The second object reads through the buffer that the first object
            // grew, and that buffer is the read chunk of the slot.
            assert_eq!(buf.len(), READ_CHUNK);
        });
    }

    /// A declared header length past the header cap is refused before the
    /// buffer is allocated. So a remote controls at most that cap for each
    /// fetch in flight. The test refuses the first byte past the cap and the
    /// largest length that the four-byte field holds.
    #[test]
    fn an_oversized_header_length_is_refused() {
        block_on(async {
            for header_len in [MAX_FILE_HEADER_SIZE as u32 + 1, u32::MAX] {
                let mut stored = Vec::new();
                stored.extend_from_slice(&header_len.to_be_bytes());
                stored.extend_from_slice(&[0u8; 4]);
                let err = read_archive_header(Cursor::new(stored)).await.unwrap_err();
                assert!(err.to_string().contains("size cap"), "{header_len}: {err}");
            }
        });
    }

    /// A ref name goes on the wire encoded. Its `/` separators stay, and each
    /// character that names something else in a URL is encoded.
    #[test]
    fn a_ref_request_path_encodes_the_name() {
        assert_eq!(ref_request_path("test/main"), "refs/heads/test/main");
        // The unreserved set passes through as itself.
        assert_eq!(ref_request_path("a-b.c_d~e"), "refs/heads/a-b.c_d~e");
        // A query, a fragment, and an escape name the ref, not a request target.
        assert_eq!(ref_request_path("a?b"), "refs/heads/a%3Fb");
        assert_eq!(ref_request_path("a#b"), "refs/heads/a%23b");
        assert_eq!(ref_request_path("a%2fb"), "refs/heads/a%252fb");
        // A space and a CRLF are bytes of the name.
        assert_eq!(ref_request_path("a b\r\n"), "refs/heads/a%20b%0D%0A");
        // A non-ASCII name is encoded as its UTF-8 bytes.
        assert_eq!(ref_request_path("é"), "refs/heads/%C3%A9");
    }

    // --- the plan ---------------------------------------------------------

    fn csum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    fn object(byte: u8, ty: ObjectType) -> ObjectName {
        ObjectName::new(csum(byte), ty)
    }

    /// Returns the outcome of a fetched commit that holds `tree`.
    fn fetched(checksum: Checksum, tree: Vec<ObjectName>, parent: Option<Checksum>) -> Step {
        Step::Commit(CommitOutcome {
            checksum,
            next: CommitNext::Scan(tree),
            parent,
            marked: true,
        })
    }

    /// Returns the outcome of a commit that a delta delivers.
    fn by_delta(
        checksum: Checksum,
        parts: usize,
        fallbacks: Vec<ObjectName>,
        tree: Vec<ObjectName>,
    ) -> Step {
        Step::Commit(CommitOutcome {
            checksum,
            next: CommitNext::Delta {
                parts,
                fallbacks,
                tree,
            },
            parent: None,
            marked: true,
        })
    }

    /// Drains the plan: applies a stored outcome for each queued object. The
    /// dirtrees reference no more objects.
    fn drain(plan: &mut Plan, marked: &mut Vec<Checksum>) {
        while let Some(item) = plan.next() {
            let step = match item {
                Item::Object(name) if name.ty == ObjectType::DirTree => {
                    Step::DirTree(name.checksum, DirTree::default())
                }
                Item::Object(_) => Step::Done,
                Item::Part(part) => Step::Part(part.commit),
                Item::Commit(_) => panic!("the test queues no further commits"),
            };
            plan.apply(step, marked);
        }
    }

    /// A commit queues the objects that it references, and reports that this
    /// pull marked it partial.
    #[test]
    fn a_commit_queues_the_objects_it_references() {
        let mut plan = Plan::default();
        let mut marked = Vec::new();
        plan.push_commit(CommitItem {
            checksum: csum(1),
            depth: 0,
            optional: false,
        });
        assert!(matches!(plan.next(), Some(Item::Commit(_))));
        plan.apply(
            fetched(
                csum(1),
                vec![
                    object(2, ObjectType::DirMeta),
                    object(3, ObjectType::DirTree),
                ],
                None,
            ),
            &mut marked,
        );
        assert_eq!(plan.scan.len(), 2);
        drain(&mut plan, &mut marked);
        assert!(plan.next().is_none());
        assert_eq!(marked, [csum(1)]);
    }

    /// An object that several commits reach is queued once. This holds if the
    /// other commits reach it while it is queued, and after it is fetched.
    #[test]
    fn an_object_several_commits_reach_is_queued_once() {
        let mut plan = Plan::default();
        let mut marked = Vec::new();
        let shared = object(9, ObjectType::DirMeta);
        for byte in [1u8, 2] {
            plan.apply(fetched(csum(byte), vec![shared], None), &mut marked);
        }
        assert_eq!(plan.scan.len(), 1);
        drain(&mut plan, &mut marked);
        plan.apply(fetched(csum(3), vec![shared], None), &mut marked);
        assert!(plan.next().is_none());
    }

    /// A commit reached again with more depth is not fetched again: the walk
    /// resumes at the parent that it named.
    #[test]
    fn a_commit_reached_deeper_resumes_at_its_parent() {
        let mut plan = Plan::default();
        let mut marked = Vec::new();
        let tip = CommitItem {
            checksum: csum(1),
            depth: 0,
            optional: false,
        };
        plan.push_commit(tip);
        assert!(matches!(plan.next(), Some(Item::Commit(_))));
        // Its parent is recorded, but depth 0 followed none of it.
        plan.apply(fetched(csum(1), Vec::new(), Some(csum(2))), &mut marked);
        assert!(plan.next().is_none());

        // A second ref reaches the same commit with one parent to follow.
        plan.push_commit(CommitItem {
            checksum: csum(1),
            depth: 1,
            optional: false,
        });
        let Some(Item::Commit(next)) = plan.next() else {
            panic!("the parent was not queued");
        };
        assert_eq!(next.checksum, csum(2));
        assert_eq!(next.depth, 0);
        assert!(next.optional);
        assert!(plan.next().is_none());
    }

    /// The drain order is the fetch order of the pull: the commits, then the
    /// objects that the scan waits for, then the content.
    #[test]
    fn the_plan_drains_commits_then_scan_then_content() {
        let mut plan = Plan::default();
        let mut marked = Vec::new();
        plan.apply(
            fetched(
                csum(1),
                vec![
                    object(4, ObjectType::File),
                    object(2, ObjectType::DirMeta),
                    object(3, ObjectType::DirTree),
                ],
                None,
            ),
            &mut marked,
        );
        plan.push_commit(CommitItem {
            checksum: csum(5),
            depth: 0,
            optional: false,
        });
        let mut drained = Vec::new();
        while let Some(item) = plan.next() {
            drained.push(match item {
                Item::Commit(commit) => commit.checksum,
                Item::Object(name) => name.checksum,
                Item::Part(part) => part.commit,
            });
        }
        assert_eq!(drained, [csum(5), csum(2), csum(3), csum(4)]);
    }

    /// A delta queues its parts and the objects that it hands over loose. The
    /// tree walk of the commit waits for the last part.
    #[test]
    fn a_delta_queues_its_parts_before_the_tree() {
        let mut plan = Plan::default();
        let mut marked = Vec::new();
        let fallback = object(7, ObjectType::File);
        let tree = vec![
            object(2, ObjectType::DirMeta),
            object(3, ObjectType::DirTree),
        ];
        plan.apply(by_delta(csum(1), 2, vec![fallback], tree), &mut marked);

        // The parts come before the fallback, which is content.
        assert!(matches!(plan.next(), Some(Item::Part(_))));
        assert!(matches!(plan.next(), Some(Item::Part(_))));
        let Some(Item::Object(name)) = plan.next() else {
            panic!("the fallback was not queued");
        };
        assert_eq!(name, fallback);
        // The tree is not queued while a part is outstanding.
        assert!(plan.next().is_none());

        plan.apply(Step::Part(csum(1)), &mut marked);
        assert!(plan.next().is_none());
        plan.apply(Step::Part(csum(1)), &mut marked);
        let Some(Item::Object(name)) = plan.next() else {
            panic!("the tree was not queued after the last part");
        };
        assert_eq!(name, object(2, ObjectType::DirMeta));
    }

    /// The plan gives out no more than [`PART_CAP`] parts at once, whatever the
    /// number of parts of the delta and of slots of the pull.
    #[test]
    fn the_part_cap_holds_however_many_parts_a_delta_has() {
        let mut plan = Plan::default();
        let mut marked = Vec::new();
        plan.apply(by_delta(csum(1), 5, Vec::new(), Vec::new()), &mut marked);

        let mut in_flight = 0;
        let mut high_water = 0;
        let mut applied = 0;
        loop {
            while let Some(item) = plan.next() {
                assert!(matches!(item, Item::Part(_)));
                in_flight += 1;
                high_water = high_water.max(in_flight);
            }
            if in_flight == 0 {
                break;
            }
            plan.apply(Step::Part(csum(1)), &mut marked);
            in_flight -= 1;
            applied += 1;
        }
        assert_eq!(high_water, PART_CAP);
        assert_eq!(applied, 5);
    }

    /// A stream that checks, at its end, that the transaction did not stage the
    /// object yet.
    struct EndBeforeStore<'a> {
        inner: Cursor<Vec<u8>>,
        txn: &'a Transaction,
        checksum: Checksum,
        ended: bool,
    }

    impl AsyncRead for EndBeforeStore<'_> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            let me = self.get_mut();
            let n = ready!(Pin::new(&mut me.inner).poll_read(cx, buf))?;
            if n == 0 && !buf.is_empty() {
                assert!(
                    !me.txn.is_staged(&me.checksum, ObjectType::File),
                    "the object was stored before its stream ended"
                );
                me.ended = true;
            }
            Poll::Ready(Ok(n))
        }
    }

    /// Each destination reads the end of the stream of a content object before
    /// it stores the object. So a pull session moves to its next reply while
    /// the store finishes. The test covers the regular-file path of an archive
    /// and of a bare-user destination, and the symlink path.
    #[test]
    fn the_stream_ends_before_the_object_is_stored() {
        let dir =
            std::env::temp_dir().join(format!("ostrya-pull-stream-end-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let payload = b"payload of a regular file".to_vec();
        let symlink = FileHeader {
            symlink_target: "target".to_owned(),
            mode: 0o120777,
            ..regular_header()
        };
        block_on(async {
            for (mode, header) in [
                (RepoMode::Archive, regular_header()),
                (RepoMode::BareUser, regular_header()),
                (RepoMode::BareUser, symlink.clone()),
            ] {
                let root = dir.join(format!("{}-{}", mode.as_mode_str(), header.is_symlink()));
                let repo = Repo::create(&root, crate::CreateOptions::new(mode))
                    .await
                    .unwrap();
                let txn = repo.transaction().await.unwrap();
                let body = if header.is_symlink() {
                    Vec::new()
                } else {
                    payload.clone()
                };
                let mut hasher = ostrya_core::ContentHasher::new(&header).unwrap();
                hasher.update(&body);
                let checksum = hasher.finish();
                let mut deflated = Vec::new();
                if !header.is_symlink() {
                    DeflateEncoder::new(&body[..])
                        .read_to_end(&mut deflated)
                        .await
                        .unwrap();
                }
                let stored = framed(&header, body.len() as u64, &deflated);
                let (parsed, declared, framed_header, rest) =
                    read_archive_header(Cursor::new(stored)).await.unwrap();
                let FileHeader {
                    uid,
                    gid,
                    mode: file_mode,
                    xattrs,
                    ..
                } = parsed.clone();
                let meta = FileMeta {
                    uid,
                    gid,
                    mode: file_mode,
                    xattrs,
                };
                let mut stream = EndBeforeStore {
                    inner: rest,
                    txn: &txn,
                    checksum,
                    ended: false,
                };
                store_filez_payload(
                    &txn,
                    &checksum,
                    &parsed,
                    &meta,
                    declared,
                    &framed_header,
                    &mut stream,
                    &mut Vec::new(),
                )
                .await
                .unwrap();
                assert!(stream.ended, "{mode:?}: the stream was not read to its end");
                assert!(txn.is_staged(&checksum, ObjectType::File), "{mode:?}");
            }
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A remote with `tls-permissive` maps to the bypass that keeps the host
    /// name check. The function never opens the `tls-ca-path` of the remote.
    /// The path here names no file, so a read of it fails the call.
    #[test]
    fn tls_permissive_leaves_the_ca_path_unread() {
        let cfg = RepoConfig::parse(
            "[core]\nrepo_version=1\nmode=archive-z2\n\
             [remote \"origin\"]\nurl=https://example.invalid/repo\n\
             tls-permissive=true\ntls-ca-path=/nonexistent/ca.pem\n",
        )
        .unwrap();
        let section = cfg.remote("origin").unwrap();
        let tls = block_on(remote_tls("origin", &section)).unwrap();
        assert_eq!(tls.roots, TrustRoots::DangerousAcceptAnyChain);
        assert!(tls.client_identity.is_none());
    }

    /// Pops the next item, which must be the dirtree `byte`.
    fn pop_dirtree(plan: &mut Plan, byte: u8) {
        loop {
            match plan.next() {
                Some(Item::Object(name)) if name.ty == ObjectType::DirMeta => continue,
                Some(Item::Object(name)) => {
                    assert_eq!(name, object(byte, ObjectType::DirTree));
                    return;
                }
                _ => panic!("dirtree {byte} was not queued"),
            }
        }
    }

    /// A dirtree reached at two subpath positions gets a walk under both, also
    /// if the second position reaches it after its first walk. The plan queues
    /// it again, and the second walk fetches what the first walk left out.
    #[test]
    fn a_dirtree_reached_again_under_a_wider_scope_is_walked_again() {
        let values = ["/p/x/".to_owned(), "/q/x".to_owned()];
        let mut plan = Plan::new(Subpaths::parse(&values).unwrap());
        let mut marked = Vec::new();
        // The root (1) holds `p` (10) and `q` (11), and both hold `x`, the one
        // dirtree 20, which holds the file 30.
        let root = DirTree {
            files: Vec::new(),
            dirs: vec![
                ("p".into(), csum(10), csum(2)),
                ("q".into(), csum(11), csum(2)),
            ],
        };
        let parent = DirTree {
            files: Vec::new(),
            dirs: vec![("x".into(), csum(20), csum(2))],
        };
        let x = DirTree {
            files: vec![("f".into(), csum(30))],
            dirs: Vec::new(),
        };
        plan.apply(
            fetched(
                csum(1),
                vec![
                    object(2, ObjectType::DirMeta),
                    object(1, ObjectType::DirTree),
                ],
                None,
            ),
            &mut marked,
        );
        pop_dirtree(&mut plan, 1);
        plan.apply(Step::DirTree(csum(1), root), &mut marked);
        pop_dirtree(&mut plan, 10);
        pop_dirtree(&mut plan, 11);
        plan.apply(Step::DirTree(csum(10), parent.clone()), &mut marked);
        // The walk of `x` is under `/p/x/` alone, which fetches nothing in it.
        pop_dirtree(&mut plan, 20);
        plan.apply(Step::DirTree(csum(20), x.clone()), &mut marked);
        assert!(plan.content.is_empty());
        // `/q/x` reaches it again and names it whole.
        plan.apply(Step::DirTree(csum(11), parent), &mut marked);
        pop_dirtree(&mut plan, 20);
        plan.apply(Step::DirTree(csum(20), x.clone()), &mut marked);
        assert_eq!(
            plan.content.iter().copied().collect::<Vec<_>>(),
            [object(30, ObjectType::File)]
        );
        // The scope covers a third reach, so the plan queues nothing again.
        plan.push_object(object(20, ObjectType::DirTree), Scope::All);
        assert!(plan.scan.is_empty());
    }

    /// A delta whose objects all went to fallbacks has no part to wait for. So
    /// the plan queues its tree walk at once.
    #[test]
    fn a_delta_with_no_parts_queues_its_tree_at_once() {
        let mut plan = Plan::default();
        let mut marked = Vec::new();
        plan.apply(
            by_delta(
                csum(1),
                0,
                vec![object(7, ObjectType::File)],
                vec![object(2, ObjectType::DirMeta)],
            ),
            &mut marked,
        );
        assert_eq!(plan.scan.len(), 1);
        assert_eq!(plan.content.len(), 1);
        assert!(plan.parts.is_empty());
    }
}
