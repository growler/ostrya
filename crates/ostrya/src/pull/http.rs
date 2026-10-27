//! The pull from a remote, over HTTP or over ssh.
//!
//! [`Repo::pull`], [`Repo::pull_with_session`],
//! [`Repo::remote_fetch_summary`], and [`Repo::remote_fetch_summary_with`]
//! are the entry points. [`Repo::pull`] holds
//! the rules of the pull. [`Repo::pull`] and [`Repo::pull_with_session`] run
//! one engine.
//!
//! The loop that drives the steps owns the plan, so the plan needs no lock.
//! The pull spawns no task: the step futures borrow the repository, the
//! transaction, and the fetcher. The walk of a subpath pull obeys the rules in
//! `subpath`.
//!
//! The plan walks a dirtree when it applies the step of the dirtree, under
//! each position that reached the dirtree by then. If a later position widens
//! that scope, the plan walks the dirtree again from the transaction.
//!
//! With a list of static deltas, the loop runs the plan one time for each
//! level of intermediate commits, and then one time for the targets, in one
//! transaction. Each run starts from the objects that the earlier runs
//! queued.

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};
use std::time::Instant;

use async_compression::futures::bufread::DeflateDecoder;
use futures_io::AsyncRead;
use futures_lite::{AsyncReadExt, AsyncWriteExt};
use ostrya_core::{
    Checksum, Commit, DirTree, FileHeader, ObjectName, ObjectType, RepoMode, loose_path,
};

use crate::composefs::recorded_digest;
use crate::config::RepoConfig;
use crate::delta::IO_CHUNK;
use crate::endpoint::{EndpointOverrides, resolve_pull};
use crate::error::{Error, Result};
use crate::fetch::gate::Gate;
use crate::fetch::{FetchRequest, Fetched, Fetcher, Priority};
use crate::inflate::BufSource;
use crate::object::{MAX_FILE_HEADER_SIZE, MAX_METADATA_SIZE};
use crate::read::CommitState;
use crate::related::RelatedRule;
use crate::remote::{Endpoint, PullSession, StreamSessionOptions};
use crate::repo::Repo;
use crate::summary::{SUMMARY_FILE, SUMMARY_SIG_FILE, Summary, put_root_file_blocking};
use crate::transaction::Transaction;
use crate::traverse::reaches_at_least;
use crate::verify::PullTrust;
use crate::verify::trust::FieldGroup;
use crate::write::FileMeta;

use super::chain::Edges;
use super::delta::{self, CommitCheck, DeltaJob, DeltaPlan, DeltaSource, PART_CAP};
use super::drive::Slots;
use super::source::{Connection, RemoteSource, RootFiles, Transfer, http_error, session_error};
use super::subpath::{Scope, Subpaths};
use super::verify::Verification;
use super::{
    CheckedMeta, ModeChecks, PullCounters, PullFlags, PullOptions, PullStats, PullVerify,
    READ_CHUNK, RefPlace, TimestampBase, TipChecks, apply_durability,
    check_commit_signatures_filtered, check_depth, check_remote_option, check_static_deltas,
    check_tip_refs, refuse_remote_collection, take_static_deltas,
};

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
    /// repository. The section gives the signature policy and the `branches`
    /// key. By default, the name gives the prefix of the written refs.
    /// [`remote`](PullOptions::remote) and [`MIRROR`](PullFlags::MIRROR)
    /// change this. The section also gives the address, the TLS material, and
    /// the proxy, and [`overrides`](PullOptions::overrides) changes them. The
    /// pull fetches the objects into one transaction, publishes them, and then
    /// writes the refs. It returns the statistics of the pull.
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
    /// [`PullVerify`] holds the signature policy.
    ///
    /// # Address
    ///
    /// The pull calls [`resolve_pull`] with
    /// [`overrides`](PullOptions::overrides), and reads the remote at the
    /// endpoint that it returns. `resolve_pull` reads the address from
    /// [`EndpointOverrides::url`], or else from the remote key `pull-url` or
    /// `url`, and states the rules of the address.
    ///
    /// An [`Endpoint::Http`] gives an HTTP pull through the fetcher, and an
    /// [`Endpoint::Ssh`] gives a pull over ssh. The fetcher gets each mirror
    /// as written, and it refuses a scheme other than `http` and `https`.
    /// With the `s3` feature, an `Endpoint::S3` gives an HTTP pull through a
    /// fetcher that signs each request. The module [`pull`](mod@crate::pull)
    /// states its rules in "Bucket repository".
    ///
    /// The pull reads the trust of the remote with
    /// [`PullTrust::from_remote`] before it opens the session, with the trust
    /// group of [`trust_group`](PullOptions::trust_group) if the field is set.
    /// So a refused policy starts no fetcher and no ssh client. Then the pull runs as
    /// [`pull_with_session`](Repo::pull_with_session) with that session and
    /// that trust, with the `branches` key and the summary copy of this
    /// method.
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
    /// An HTTP pull connects through the proxy of the endpoint.
    /// [`resolve_pull`] reads it from the
    /// remote key `proxy`. With the `http://` proxy URL of that key, the pull
    /// connects through the proxy for every origin, and ignores `no_proxy`. If
    /// the key is absent or empty, the pull reads the proxy environment
    /// variables.
    ///
    /// # Pull over ssh
    ///
    /// For an ssh endpoint, the pull runs the ssh client after it resolves the
    /// signature policy. The [`SshOptions`](crate::remote::SshOptions) of the
    /// endpoint give the commands of the client, by the rules of
    /// [`StreamSession::connect`](crate::remote::StreamSession::connect).
    ///
    /// `resolve_pull` reads no remote key that applies to HTTP alone for an
    /// ssh address: `contenturl`, `metalink`, `proxy`, and the `tls-*` keys.
    /// For an HTTP address, it reads neither `ssh-command` nor
    /// `send-command`.
    ///
    /// The pull reads the remote through a source: the HTTP source over the
    /// fetcher, or the stream source over a stream session.
    /// [`PullSession::over_stream`] opens a stream session over a pair of
    /// streams, for [`pull_with_session`](Repo::pull_with_session). The two
    /// sources serve the same paths under the same caps. Each rule of this
    /// method applies to both sources, with these differences:
    ///
    /// - The stream source requests a ref by its name as written, with no
    ///   percent-encoding.
    /// - The stream source never sends a request again. A failure ends its
    ///   session and the pull.
    /// - The stream source keeps the requests of `summary.sig`, `summary`, and
    ///   `config` in flight together, in the order of the HTTP source. It does
    ///   the same for a `.commitmeta` and its commit, so a parent commit costs
    ///   one round trip. It also does the same for the superblock of a step of
    ///   a [`static_deltas`](PullOptions::static_deltas) chain and the
    ///   `.commitmeta` of the commit of the step, the superblock first, as
    ///   `# Static deltas` states. The HTTP source sends these requests one at
    ///   a time, except `summary.sig` and `summary` of a bucket repository.
    ///   The module [`pull`](mod@crate::pull) states that exception in
    ///   "Bucket repository".
    /// - The stream source ends its session before the transaction commits.
    ///   It closes the input of the server and, over ssh, waits for the ssh
    ///   client.
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
    /// refs at one commit get both checks. For a commit of a chain of a
    /// [`static_deltas`](PullOptions::static_deltas) list, discovery makes
    /// these checks before the transaction opens, as `# Static deltas`
    /// states.
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
    /// If `[ex-ostrya] keep-detached-related` of this repository is `false`
    /// ([`RepoConfig::keep_detached_related`](crate::RepoConfig::keep_detached_related)),
    /// the pull drops `ostrya.related` from each `.commitmeta` that it stores,
    /// also through a static delta.
    ///
    /// # Composefs image
    ///
    /// For each commit that carries `ostree.composefs.digest.v0`, the pull
    /// requests the composefs image `objects/<..>.cfs`, also for a commit
    /// that this repository holds complete. A
    /// [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull and a pull with
    /// [`subpaths`](PullOptions::subpaths) request no image. A malformed value
    /// of the key counts as no key. If this repository holds an image of the
    /// commit, the pull does not request it and does not read the stored
    /// image. A localcache repository that holds the image supplies it.
    ///
    /// The requests of the images come after the requests of all other
    /// objects of the pull: the first image request goes out when no request
    /// of another object is queued or in flight. In a pull through a chain of
    /// static deltas, the images wait for the last step of the chain. A
    /// remote that serves no image of a commit leaves the commit with no
    /// image, and the pull goes on. After the first image that the remote
    /// does not serve, the pull requests no image of a commit that this
    /// repository holds complete. The image of each commit whose objects the
    /// pull takes is requested all the same. The images of the held commits
    /// come after the other images, one request at a time until the remote
    /// serves one, so a remote that serves no image gets at most one request
    /// for them.
    ///
    /// The pull streams the image to the staging directory, computes its
    /// fs-verity digest, and stages it only when the digest is the key. No
    /// count of the pull but
    /// [`bytes_transferred`](PullStats::bytes_transferred) includes the
    /// image.
    ///
    /// A static delta can carry the image of its target commit in a part.
    /// The application of the part stages the image with the same digest
    /// check, so the pull does not request it. A pull with
    /// [`subpaths`](PullOptions::subpaths) also stages an image that a part
    /// carries. The pull does not fetch an image that the delta lists as a
    /// fallback as a fallback object: the rules above apply to it.
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
    /// [`PullVerify`]. Also before any part request, it
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
    /// The pull applies the parts of one delta in the order that they arrive.
    /// The format allows this order: a part patches against the objects of the
    /// source commit, which are present before the delta applies. A part never
    /// patches against the output of another part of the same delta.
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
    /// [`static_deltas`](PullOptions::static_deltas) replaces this search with
    /// a list. The pull then reads no delta index and no `ostree.static-deltas`
    /// map, and it needs no summary for the deltas. For each target commit, it
    /// plans the chain with the fewest steps. A chain starts at a commit that
    /// this repository holds complete, or with a delta from scratch if the
    /// rules above for a map allow a from-scratch delta to the target. Of two
    /// chains with the same number of steps, the chain from a complete commit
    /// wins.
    ///
    /// Before the transaction opens, the pull fetches the superblock of each
    /// step and compares its SHA-256 with the digest in the list. It verifies
    /// the signatures and the inline parts of each superblock, as stated
    /// above, before it checks the commit of the step. For each commit of a
    /// chain, the target included, it also fetches the `.commitmeta` and
    /// checks the signatures of the commit. For each requested ref that names
    /// a commit of a chain, it makes the ref-binding check and the timestamp
    /// check, in the order of the refs. So a target that the policy, its ref
    /// binding, or the timestamp check refuses costs the superblocks that
    /// discovery fetched, and the pull requests no part.
    /// The pull does not request these files again, and does not check these
    /// commits again. A commit that has no record in the last plan gets its
    /// checks when the pull fetches it, and the pull requests its
    /// `.commitmeta` again. This is a target whose chain the pull drops, or a
    /// dropped intermediate commit that a depth walk reaches as a parent.
    ///
    /// Over a stream session, if no localcache repository holds the
    /// `.commitmeta` of the commit of a step, the pull sends the request of
    /// the superblock and the request of the `.commitmeta` as one pair. The
    /// reply of the `.commitmeta` arrives while the pull parses and verifies
    /// the superblock. So discovery then holds one superblock and one
    /// `.commitmeta` on the heap, up to 128 MiB each, and the parse of the
    /// superblock. A superblock that the remote does not hold costs its paired
    /// `.commitmeta` request. If a later plan reaches the same commit through
    /// another delta, the pull requests the `.commitmeta` again and counts it
    /// again. So for the same pull, the metadata count over a stream session
    /// can be higher than over HTTP: one more for each superblock that the
    /// remote does not hold, if the remote holds the `.commitmeta` of its
    /// commit.
    ///
    /// The pull keeps the verified superblocks and `.commitmeta` files of
    /// discovery in one temp file in `tmp/` of this repository until it ends.
    /// The file holds at most 1 GiB, the bytes of the steps that discovery
    /// drops included. A list whose steps pass this limit fails the pull with
    /// [`Error::Pull`], and the pull does not fetch loose.
    ///
    /// The pull applies a chain one level at a time, in its one transaction. A
    /// part of a later step can patch against an object that an earlier step
    /// wrote, also an object that the earlier step hands over loose. So the
    /// parts, the loose objects, and the tree walk of one level end before the
    /// next level starts. Each intermediate commit ends complete, with no
    /// `.commitpartial` marker. The pull writes a ref for an intermediate
    /// commit only if a requested ref names it.
    ///
    /// Discovery checks only the signatures of an intermediate commit that
    /// no requested ref names. It makes no ref-binding check and no timestamp
    /// check on it, so a chain can go through a commit whose ref binding
    /// names another ref. If a requested ref names an intermediate commit,
    /// discovery makes both checks for that ref.
    ///
    /// If the remote does not hold a superblock of a chain, the pull plans
    /// again without that delta. If no chain reaches a target, the pull
    /// fetches its objects loose, or fails under `require_static_deltas`. A
    /// listed delta from scratch to the target that the rules above refuse
    /// counts as found: the pull does not fail, and fetches that target loose.
    /// A [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull ignores the list.
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
    ///   `-1`.
    /// - [`Error::Unsupported`] if
    ///   [`collection_id`](PullOptions::collection_id) is set. The pull reads
    ///   no collection ref. [`pull_collection`](Repo::pull_collection) pulls
    ///   collection refs.
    /// - [`Error::InvalidInput`] if [`remote`](PullOptions::remote) holds a
    ///   name that [`valid_remote_name`](crate::config::valid_remote_name)
    ///   refuses, also under [`MIRROR`](PullFlags::MIRROR).
    /// - [`Error::Pull`] if a subpath does not start with `/`.
    /// - [`Error::InvalidInput`] if
    ///   [`static_deltas`](PullOptions::static_deltas) holds two digests for
    ///   one delta, or is set together with
    ///   [`disable_static_deltas`](PullOptions::disable_static_deltas) or with
    ///   [`subpaths`](PullOptions::subpaths).
    /// - [`Error::Core`] if `[ex-ostrya] keep-detached-related` of this
    ///   repository is not a boolean.
    /// - The errors of [`resolve_pull`]. Among them, [`Error::Io`] names the
    ///   key and the path of a PEM file that cannot be read, and a PEM file
    ///   over 1 MiB is [`Error::InvalidInput`].
    /// - [`Error::Remote`] with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the ssh
    ///   command or the send command of an [`Endpoint::Ssh`] is empty or holds
    ///   only white space.
    /// - [`Error::Unsupported`] if the scheme of a mirror is neither `http`
    ///   nor `https`, or if the fetcher refuses the proxy URL or a proxy
    ///   environment variable.
    /// - [`Error::Fetch`] if a mirror is not a valid absolute URL, if a header
    ///   is invalid, or if the TLS material does not parse.
    /// - The errors of [`PullTrust::from_remote`]. Among them,
    ///   [`Error::InvalidInput`] if
    ///   [`valid_remote_name`](crate::config::valid_remote_name) refuses
    ///   `remote`.
    /// - The errors of [`trust_group`](PullOptions::trust_group), if it is
    ///   set.
    ///
    /// These errors stop the pull before it fetches an object:
    ///
    /// - [`Error::Signature`] if the policy of
    ///   [`PullVerify`] refuses the summary.
    /// - [`Error::Unsupported`] if the `config` of the remote states a mode
    ///   other than `archive`.
    /// - [`Error::InvalidFormat`] if the `config` of the remote is not valid
    ///   UTF-8 or has no valid `[core]` group.
    /// - [`Error::InvalidFormat`] if a `refs/heads/<ref>` file is not valid
    ///   UTF-8.
    /// - [`Error::Core`] if the `config` of the remote does not parse as a key
    ///   file, or if a `refs/heads/<ref>` file holds no checksum.
    /// - [`Error::InvalidRefspec`] if a requested ref, a ref of the summary
    ///   under `MIRROR`, or a name of the `branches` key of the remote is not
    ///   a valid ref name. A `MIRROR` pull of every ref
    ///   fails with this error if the summary lists one name that the ref-name
    ///   rule refuses. The pull does not skip the name.
    /// - [`Error::RefNotFound`] if neither the summary nor `refs/heads/<ref>`
    ///   names a requested ref.
    /// - [`Error::Pull`] if [`refs`](PullOptions::refs) is empty and the remote
    ///   serves no summary under `MIRROR`, or the remote has no `branches`.
    /// - These errors of the commit of
    ///   [`TimestampCheck::Rev`](crate::TimestampCheck::Rev), if
    ///   [`timestamp_check`](PullOptions::timestamp_check) is that check and
    ///   the pull has at least one target. The pull reads the commit after the
    ///   ref files of the remote and before it fetches a delta index or a
    ///   static delta superblock.
    ///   - [`Error::ObjectNotFound`] if this repository does not hold the
    ///     commit.
    ///   - [`Error::Io`] if the commit object is larger than
    ///     [`MAX_METADATA_SIZE`], is not a regular file, or a read of it fails.
    ///   - [`Error::Core`] if the tuple frame, the subject, or the body of the
    ///     commit is not in normal form, or if its parent, root dirtree, or
    ///     root dirmeta checksum has a wrong length.
    /// - [`Error::Pull`] if
    ///   [`require_static_deltas`](PullOptions::require_static_deltas) is set
    ///   and the pull finds no delta, or no chain to a target under a list. A
    ///   listed delta from scratch to the target that the from-scratch rules
    ///   of `# Static deltas` refuse counts as found, and the pull fetches
    ///   that target loose.
    /// - [`Error::Pull`] if a superblock names other commits than its delta
    ///   name.
    /// - [`Error::Pull`] if the superblocks and the `.commitmeta` files of the
    ///   chains of a list pass the limit of 1 GiB.
    /// - [`Error::Signature`] if the policy refuses a commit of a chain of a
    ///   list, or the superblock of a step.
    /// - [`Error::Pull`] if a requested ref that names a commit of a chain of
    ///   a list fails the ref-binding check or the timestamp check.
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
    /// - [`Error::ComposefsDigestMismatch`] if the fs-verity digest of a
    ///   fetched composefs image is not the key of its commit.
    /// - [`Error::InsufficientFreeSpace`] if a stored object needs more space
    ///   than the free-space budget of the transaction holds.
    ///
    /// These errors can stop the pull at any request or write:
    ///
    /// - [`Error::Fetch`], [`Error::HttpStatus`], [`Error::FetchTooLarge`],
    ///   [`Error::ContentEncoded`], or [`Error::RedirectLimit`] if an HTTP
    ///   request fails after its retries.
    /// - [`Error::Remote`] if the session of a pull over ssh fails, or if a
    ///   read of `summary.sig`, `summary`, or `config` from a bucket
    ///   repository fails.
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
    pub async fn pull(&self, remote: &str, mut opts: PullOptions) -> Result<PullStats> {
        let started = Instant::now();
        // A subpath the walk cannot read is refused before anything else, so it
        // costs no request and opens no transaction.
        let subpaths = Subpaths::parse(&opts.subpaths)?;
        check_depth(opts.depth)?;
        refuse_remote_collection(&opts)?;
        check_remote_option(&opts)?;
        check_static_deltas(&opts)?;
        // `drive` reads the rule again. This read refuses a value that is not
        // a boolean before the first request.
        RelatedRule::of(self.config())?;
        let edges = take_static_deltas(&mut opts).await?;
        // The endpoint is resolved first, so a remote the config does not
        // describe reports that before a policy is resolved for it.
        let overrides = std::mem::take(&mut opts.overrides);
        let endpoint = resolve_pull(Some(self.config()), remote, overrides).await?;
        // The trust comes before the session, so a refused policy starts no
        // fetcher and no ssh client.
        let mut group = opts.trust_group.as_deref().map(FieldGroup::new);
        let trust = PullTrust::for_pull(self, remote, &opts.verify, group.as_mut()).await?;
        let (endpoint, stream) = session_options(endpoint, opts.max_outstanding_fetches);
        let connection = connect(endpoint, stream).await?;
        // The trust and the session now hold what these fields gave.
        opts.verify = PullVerify::default();
        opts.trust_group = None;
        opts.max_outstanding_fetches = None;
        opts.remote = opts.remote.or_else(|| Some(remote.to_owned()));
        self.run_session(
            connection,
            trust,
            opts,
            Wanted::Config(remote),
            subpaths,
            edges,
            started,
        )
        .await
    }

    /// Pulls refs and their objects through a session that the caller opened.
    ///
    /// `session` reads the remote, and `trust` holds each key that the pull
    /// checks a signature against. The pull obeys the rules of
    /// [`pull`](Repo::pull) that do not come from the config of a remote: the
    /// transaction, the commit walk, [`depth`](PullOptions::depth), the
    /// subpaths, the verification of signatures, the static deltas, and the
    /// statistics.
    ///
    /// The pull reads no remote section and no trust group of the config of
    /// this repository. It reads the `[core]` keys that each transaction
    /// reads, and `[ex-ostrya] keep-detached-related`.
    ///
    /// # Refs
    ///
    /// The pull takes the refs in [`refs`](PullOptions::refs) alone, and
    /// resolves each one as [`pull`](Repo::pull) does. The prefix of the
    /// written refs comes from [`remote`](PullOptions::remote):
    ///
    /// - `None` writes local refs, `refs/heads/<ref>`, as
    ///   [`pull_local`](Repo::pull_local) does.
    /// - `Some(name)` writes `refs/remotes/<name>/<ref>`.
    /// - [`MIRROR`](PullFlags::MIRROR) writes local refs, whatever `remote`
    ///   holds.
    ///
    /// The pull does not protect the local refs of this repository. Under
    /// [`no_ref_writes`](PullOptions::no_ref_writes), the pull writes no ref,
    /// and the rules above select the ref that the pull reads for delta
    /// discovery and for
    /// [`TimestampCheck::CurrentRef`](crate::TimestampCheck::CurrentRef).
    ///
    /// A `MIRROR` pull copies no `summary` and no `summary.sig`, because the
    /// pull refuses an empty `refs`.
    ///
    /// # Session
    ///
    /// The pull keeps as many steps in flight as the session admits:
    /// [`PullSession::max_outstanding`]. It takes the session by value. A
    /// stream session ends before the transaction commits, as in
    /// [`pull`](Repo::pull).
    ///
    /// # Counters
    ///
    /// [`PullStats::elapsed`] starts at the call of this method.
    /// [`PullStats::bytes_transferred`] and [`progress`](PullOptions::progress)
    /// count as for [`pull`](Repo::pull): the count starts after the
    /// `summary`, the `config`, and the ref files of the remote.
    ///
    /// The caller can attach its own counters to the fetcher of an
    /// [`Http`](PullSession::Http) session with
    /// [`Fetcher::counted`](crate::fetch::Fetcher::counted). Those counters
    /// get the bytes of each body that the fetcher reads, the `summary`, the
    /// `config`, and the ref files included. So their count can be larger
    /// than `bytes_transferred`.
    ///
    /// # Errors
    ///
    /// These errors stop the pull before its first request, before the
    /// transaction opens, and before the pull counts into
    /// [`progress`](PullOptions::progress). The pull writes no object and no
    /// ref. It calls [`PullSession::finish`] before it returns the error, and
    /// ignores the result of that call.
    ///
    /// - [`Error::Core`] if `[ex-ostrya] keep-detached-related` of this
    ///   repository is not a boolean.
    /// - [`Error::Pull`] if a subpath does not start with `/`.
    /// - [`Error::InvalidInput`] if [`depth`](PullOptions::depth) is below
    ///   `-1`.
    /// - [`Error::Unsupported`] if
    ///   [`collection_id`](PullOptions::collection_id) is set. The pull reads
    ///   no collection ref.
    /// - [`Error::InvalidInput`] if [`remote`](PullOptions::remote) holds a
    ///   name that [`valid_remote_name`](crate::config::valid_remote_name)
    ///   refuses, also under `MIRROR`.
    /// - [`Error::InvalidInput`] if
    ///   [`static_deltas`](PullOptions::static_deltas) holds two digests for
    ///   one delta, or is set together with
    ///   [`disable_static_deltas`](PullOptions::disable_static_deltas) or with
    ///   [`subpaths`](PullOptions::subpaths).
    /// - [`Error::InvalidInput`] if [`refs`](PullOptions::refs) is empty, also
    ///   under `MIRROR`.
    /// - [`Error::InvalidInput`] if [`verify`](PullOptions::verify) is not the
    ///   default, or if [`trust_group`](PullOptions::trust_group) is set.
    ///   `trust` holds the keys.
    /// - [`Error::InvalidInput`] if
    ///   [`max_outstanding_fetches`](PullOptions::max_outstanding_fetches) is
    ///   set. The limit of the session applies.
    /// - [`Error::InvalidInput`] if [`overrides`](PullOptions::overrides) is
    ///   not the default. The session selects the server.
    ///
    /// After these checks, the pull has the errors of [`pull`](Repo::pull)
    /// that stop it before it fetches an object, while it fetches, and at any
    /// request or write. A stream session that fails is [`Error::Remote`].
    ///
    /// # Examples
    ///
    /// Pull one ref over HTTP with no check of signatures, into the local ref
    /// `exampleos/stable`:
    ///
    /// ```no_run
    /// use ostrya::fetch::{Fetcher, FetcherOptions};
    /// use ostrya::remote::PullSession;
    /// use ostrya::verify::PullTrust;
    ///
    /// # async fn run() -> ostrya::Result<()> {
    /// let repo = ostrya::Repo::open("/srv/repo".as_ref()).await?;
    /// let fetcher = Fetcher::new(FetcherOptions::new("https://example.com/repo")).await?;
    /// let opts = ostrya::PullOptions {
    ///     refs: vec!["exampleos/stable".to_owned()],
    ///     ..Default::default()
    /// };
    /// let stats = repo
    ///     .pull_with_session(PullSession::Http(fetcher), PullTrust::unverified(), opts)
    ///     .await?;
    /// println!("{} content objects fetched", stats.content_fetched);
    /// # Ok(()) }
    /// ```
    pub async fn pull_with_session(
        &self,
        session: PullSession,
        trust: PullTrust,
        mut opts: PullOptions,
    ) -> Result<PullStats> {
        let started = Instant::now();
        let checked = match RelatedRule::of(self.config()) {
            Ok(_) => check_session_pull(&mut opts).await,
            Err(e) => Err(e),
        };
        let (subpaths, edges) = match checked {
            Ok(checked) => checked,
            Err(e) => {
                // The refusal comes before the first request. The result of
                // the session end does not change it.
                let _ = session.finish().await;
                return Err(e);
            }
        };
        self.run_session(
            session.into(),
            trust,
            opts,
            Wanted::Named,
            subpaths,
            edges,
            started,
        )
        .await
    }

    /// Runs a pull through the session of `connection` to its end, under
    /// `trust`.
    ///
    /// The caller made each check of `opts` that applies to its entry.
    /// [`remote`](PullOptions::remote) gives the prefix of the written refs,
    /// and the session gives the number of steps in flight. `edges` is the
    /// index of the list of static deltas that the caller took out of `opts`.
    /// `started` is the start of [`PullStats::elapsed`].
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run_session(
        &self,
        connection: Connection,
        trust: PullTrust,
        opts: PullOptions,
        wanted: Wanted<'_>,
        subpaths: Option<Subpaths>,
        edges: Option<Edges>,
        started: Instant,
    ) -> Result<PullStats> {
        let counters = PullCounters::new(opts.progress.as_ref());
        let source = RemoteSource::new(connection, counters.transferred_sinks());
        let verification = Verification::from_trust(trust);
        // The state of `pull_from` is on the heap, which keeps the future of
        // each entry small.
        Box::pin(self.pull_from(
            wanted,
            source,
            &opts,
            &verification,
            subpaths,
            edges,
            &counters,
            started,
        ))
        .await
    }

    /// Runs a pull from `source` to its end: fetches what the refs reach into
    /// a transaction, ends the source, commits the transaction, and writes the
    /// refs.
    #[allow(clippy::too_many_arguments)]
    async fn pull_from(
        &self,
        wanted: Wanted<'_>,
        source: RemoteSource,
        opts: &PullOptions,
        verification: &Verification,
        subpaths: Option<Subpaths>,
        edges: Option<Edges>,
        counters: &PullCounters,
        started: Instant,
    ) -> Result<PullStats> {
        let mirror = opts.flags.contains(PullFlags::MIRROR);
        let place = match wanted {
            Wanted::Pinned(pinned) => pinned.place,
            _ if mirror => RefPlace::Heads,
            _ => RefPlace::of_remote(opts.remote.as_deref()),
        };

        // The markers that the pull writes. They stay outside the span that
        // writes them, so a failure in that span clears the markers it left.
        let mut marked = Vec::new();
        let fetched = self
            .fetch_from(
                &source,
                wanted,
                opts,
                place,
                verification,
                subpaths,
                edges,
                counters,
                &mut marked,
            )
            .await;
        // The source ends before the transaction commits. The stream source
        // closes the input of the server and, over ssh, waits for the ssh
        // client. As a result, a failure of the session fails the pull before
        // anything publishes.
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
                        place.queue(&txn, name, tip);
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
    /// its end. With a list of static deltas, the plan runs one time for each
    /// level of intermediate commits, and then one time for the targets. The
    /// commits whose `.commitpartial` marker the pull wrote go into `marked`.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_from(
        &self,
        source: &RemoteSource,
        wanted: Wanted<'_>,
        opts: &PullOptions,
        place: RefPlace<'_>,
        verification: &Verification,
        subpaths: Option<Subpaths>,
        edges: Option<Edges>,
        counters: &PullCounters,
        marked: &mut Vec<Checksum>,
    ) -> Result<FetchedPull> {
        let mut root;
        // The probe of a collection pull read this summary and checked it
        // under the trust of this pull, so the pull does not fetch it again.
        // The pull takes the bytes, so they drop after the parse.
        let probed = match wanted {
            Wanted::Pinned(pinned) => pinned
                .summary
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
            _ => None,
        };
        let summary = if let Some(bytes) = probed {
            // The parse runs on the blocking pool, as below.
            root = RootFiles::default();
            Some(ostrya_rt::unblock(move || Summary::parse(&bytes)).await?)
        } else {
            root = source.root_files().await?;
            // A mirror pull of every ref that writes refs copies the `summary`
            // and the `summary.sig` of the remote. Each other pull drops the
            // bytes after their checks.
            let copies_summary = opts.flags.contains(PullFlags::MIRROR)
                && opts.refs.is_empty()
                && !opts.no_ref_writes;
            // The pull checks the summary before it reads it. The pull acts on
            // the refs that the summary resolves and the deltas that it
            // advertises. As a result, a summary that the policy refuses stops
            // the pull before its first object request.
            root.signature = verification
                .check_summary(root.summary.as_deref(), root.signature.take())
                .await?
                .filter(|_| copies_summary);
            // A summary can be as large as its read cap, so the parse runs on
            // the blocking pool. The bytes come back only for the write of a
            // mirror pull, and else drop there.
            match root.summary.take() {
                Some(bytes) => {
                    let (parsed, bytes) = ostrya_rt::unblock(move || {
                        let parsed = Summary::parse(&bytes);
                        (parsed, copies_summary.then_some(bytes))
                    })
                    .await;
                    root.summary = bytes;
                    Some(parsed?)
                }
                None => None,
            }
        };
        check_remote_mode(root.config(source).await?)?;
        let targets = self
            .remote_targets(wanted, opts, summary.as_ref(), source)
            .await?;
        // The transferred count starts after the summary, the config, and the
        // ref files that a pull reads from a remote with no summary. The
        // `ostree` command reports the same count.
        counters.restart_transferred();

        // The timestamp check reads a commit that it names one time, before
        // discovery. A commit that this repository does not hold stops the
        // pull before its first superblock request. A pull with no target
        // checks no timestamp, so it reads no commit.
        let timestamp = if targets.is_empty() {
            TimestampBase::Off
        } else {
            TimestampBase::resolve(self, &opts.timestamp_check).await?
        };
        // The checks of each requested ref. A collection pull adds the check
        // of the collection binding and of the timestamp that the remote
        // listed.
        let tip_checks = match wanted {
            Wanted::Pinned(pinned) => TipChecks {
                collection: Some(pinned.collection),
                listed: Some(&pinned.listed),
                ..TipChecks::new(opts.flags, timestamp, place)
            },
            _ => TipChecks::new(opts.flags, timestamp, place),
        };

        // The deltas that can deliver these commits, found before the first
        // object request. A commit that a delta carries has no `.commit`
        // request of its own.
        let delta_source = DeltaSource::Remote(source);
        let mut deltas = delta::discover(
            self,
            &delta_source,
            summary.as_ref(),
            &targets,
            opts,
            tip_checks,
            edges,
            verification,
            counters,
        )
        .await?;
        // Discovery is the last reader of the parsed summary.
        drop(summary);
        deltas.plan_parts(counters);

        let mut txn = self.transaction().await?;
        apply_durability(&mut txn, opts);
        // A part of a later step of a chain can patch against an object that
        // an earlier step wrote. So the run of each level of intermediate
        // commits ends before the next run starts. The jobs of a level live
        // for its run alone.
        let none = HashMap::new();
        let mut done = HashSet::new();
        let mut carry = Carry::default();
        for level in deltas.levels() {
            let jobs = deltas.parse_level(self, &delta_source, level).await?;
            let phase = Phase {
                roots: level,
                tips: &none,
                depth: 0,
                subpaths: None,
                deltas: &jobs,
                done: &done,
                last: false,
            };
            self.drive(
                &txn,
                source,
                opts,
                tip_checks,
                phase,
                &deltas,
                verification,
                counters,
                &mut carry,
                marked,
            )
            .await?;
            drop(jobs);
            done.extend(level.iter().copied());
        }
        let jobs = deltas.target_jobs(self, &delta_source).await?;
        // The refs of each requested tip. The binding check and the timestamp
        // check apply to each ref. The plan fetches a commit once, whatever the
        // number of refs that name it. So the step that fetches a commit runs
        // the checks of every ref in its entry here.
        let mut tips: HashMap<Checksum, Vec<String>> = HashMap::new();
        for (name, tip) in &targets {
            tips.entry(*tip).or_default().push(name.clone());
        }
        let roots: Vec<Checksum> = targets.iter().map(|(_, tip)| *tip).collect();
        let phase = Phase {
            roots: &roots,
            tips: &tips,
            depth: opts.depth,
            subpaths,
            deltas: &jobs,
            done: &done,
            last: true,
        };
        self.drive(
            &txn,
            source,
            opts,
            tip_checks,
            phase,
            &deltas,
            verification,
            counters,
            &mut carry,
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

    /// Fetches the `summary` and `summary.sig` files of a remote, as
    /// [`remote_fetch_summary_with`](Repo::remote_fetch_summary_with) does
    /// with the default overrides.
    ///
    /// The default overrides do not set `allow_cleartext_credentials`, so the
    /// call refuses an `http://` S3 endpoint.
    ///
    /// # Errors
    ///
    /// The errors of
    /// [`remote_fetch_summary_with`](Repo::remote_fetch_summary_with).
    pub async fn remote_fetch_summary(
        &self,
        remote: &str,
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        self.remote_fetch_summary_with(remote, EndpointOverrides::default())
            .await
    }

    /// Fetches the `summary` and `summary.sig` files of a remote, with the
    /// overrides `overrides` of the caller.
    ///
    /// Returns the bytes of `summary` and of `summary.sig`, in this order. A
    /// file that the remote does not serve is `None`. Each file has a cap of
    /// 64 MiB.
    ///
    /// The call reaches the remote as [`pull`](Repo::pull) does. It resolves
    /// the endpoint of `remote` with [`resolve_pull`] and `overrides`. The
    /// address is [`EndpointOverrides::url`], else `pull-url`, else `url`.
    /// Over HTTP, the call uses the TLS material and the proxy of the remote.
    /// Over ssh, the remote keys `ssh-command` and `send-command` give the
    /// commands. The `OSTRYA_SSH_COMMAND` environment variable has precedence
    /// over `ssh-command`. For an `s3://` address, the S3 fields of
    /// `overrides` win over the S3 keys of the remote, and
    /// `allow_cleartext_credentials` permits an `http://` S3 endpoint.
    ///
    /// Over HTTP, the call requests `summary.sig` and then `summary`. Over
    /// ssh, the two requests are in flight together, and the session ends
    /// before the call returns. For an `s3://` address, the bucket client
    /// reads the two files with signed requests. It asks for `summary.sig`
    /// first. If the fetcher admits two requests at once, the two requests
    /// are in flight together.
    ///
    /// # Errors
    ///
    /// - The errors of [`resolve_pull`].
    /// - [`Error::Remote`] with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the ssh
    ///   command or the send command of an [`Endpoint::Ssh`] is empty or holds
    ///   only white space.
    /// - [`Error::Unsupported`] if the scheme of a mirror is neither `http`
    ///   nor `https`, or if the fetcher refuses the proxy URL or a proxy
    ///   environment variable.
    /// - [`Error::FetchTooLarge`] if an HTTP response declares a file larger
    ///   than 64 MiB.
    /// - [`Error::Fetch`], [`Error::HttpStatus`] other than 404,
    ///   [`Error::ContentEncoded`], or [`Error::RedirectLimit`] if an HTTP
    ///   request fails after its retries.
    /// - [`Error::Remote`] if the ssh session fails, or if a read from a
    ///   bucket repository fails.
    pub async fn remote_fetch_summary_with(
        &self,
        remote: &str,
        overrides: EndpointOverrides,
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        let endpoint = resolve_pull(Some(self.config()), remote, overrides).await?;
        let connection = connect(endpoint, StreamSessionOptions::default()).await?;
        let source = RemoteSource::new(connection, Vec::new());
        let read = source.summary_files().await;
        source.finish(read).await
    }

    /// Resolves what to pull: the requested refs, the summary refs of the
    /// remote under [`MIRROR`](PullFlags::MIRROR), or the `branches` key of
    /// the remote that `wanted` names.
    async fn remote_targets(
        &self,
        wanted: Wanted<'_>,
        opts: &PullOptions,
        summary: Option<&Summary>,
        source: &RemoteSource,
    ) -> Result<Vec<(String, Checksum)>> {
        if let Wanted::Pinned(pinned) = wanted {
            return Ok(pinned.targets.clone());
        }
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
            let Wanted::Config(remote) = wanted else {
                return Err(no_refs());
            };
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
            // it against the rule of the ref store. A component that the rule
            // refuses, such as a traversal, can ask the server for a resource
            // that the ref does not name.
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

    /// Runs one run of the plan to its end, from the roots of `phase`. The
    /// commits whose `.commitpartial` marker this pull wrote, and must clear,
    /// go into `marked`.
    ///
    /// The run starts from the objects that the earlier runs of this pull
    /// queued, and gives them back in `carry` when it ends. So the pull
    /// fetches an object once over all runs. `carry` also keeps a running
    /// count of the units of work, for the progress total. `delta_plan` holds
    /// the checks that discovery made on the commits of the chains.
    ///
    /// `marked` is an argument, so the caller holds the written markers when a
    /// step fails.
    #[allow(clippy::too_many_arguments)]
    async fn drive(
        &self,
        txn: &Transaction,
        source: &RemoteSource,
        opts: &PullOptions,
        tip_checks: TipChecks<'_>,
        phase: Phase<'_>,
        delta_plan: &DeltaPlan,
        verification: &Verification,
        progress: &PullCounters,
        carry: &mut Carry,
        marked: &mut Vec<Checksum>,
    ) -> Result<()> {
        let ctx = StepCtx {
            txn,
            source,
            writes: Arc::new(Gate::new(WRITE_THROTTLE)),
            sources: &opts.localcache_repos,
            flags: opts.flags,
            checks: ModeChecks::new(opts.flags, self.mode()),
            tip_checks,
            tips: phase.tips,
            deltas: phase.deltas,
            done: phase.done,
            delta_plan,
            verification,
            related: RelatedRule::of(self.config())?,
            images: !opts.flags.contains(PullFlags::COMMIT_ONLY) && opts.subpaths.is_empty(),
            progress,
        };
        let mut plan = Plan::new(phase.subpaths);
        plan.queued = std::mem::take(&mut carry.queued);
        plan.images = std::mem::take(&mut carry.images);
        for root in phase.roots {
            plan.push_commit(CommitItem {
                checksum: *root,
                depth: phase.depth,
                optional: false,
            });
        }

        // The pull keeps as many steps in flight as the session admits.
        let mut slots = Slots::new(source.max_outstanding());
        // The read buffers for content objects, from each source. A localcache
        // import verifies its payload through one, and a fetched payload
        // streams into the object store through one. A step takes a buffer at
        // its start and gives it back with its outcome. So a pull holds one
        // buffer for each slot, whatever the number of objects it stores. A
        // step that fails takes its buffer with it, and the failure ends the
        // pull.
        let mut buffers: Vec<Vec<u8>> = Vec::new();
        // The units of work given to a slot by this pull, for the progress
        // total.
        let mut started = carry.started;
        loop {
            // The composefs images wait for the last run, and in that run for
            // the end of each other step.
            while slots.has_room()
                && let Some(item) = plan
                    .next()
                    .or_else(|| phase.last.then(|| plan.next_image(slots.len())).flatten())
            {
                let buffer = buffers.pop().unwrap_or_default();
                slots.push(self.step(&ctx, item, buffer));
                started += 1;
            }
            plan.report(progress, started, !phase.last);
            let Some(outcome) = slots.next_ready().await else {
                break;
            };
            let (step, buffer) = outcome?;
            buffers.push(buffer);
            progress.object_done();
            plan.apply(step, marked);
        }
        carry.queued = plan.queued;
        carry.images = plan.images;
        carry.started = started;
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
            Item::Object(name) if name.ty == ObjectType::ComposefsImage => {
                Box::pin(self.fetch_image(ctx, name.checksum, &mut read_buf)).await?
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
        if ctx.done.contains(&checksum) {
            return self.done_commit(ctx, checksum).await;
        }
        // Discovery checked the signatures of each commit of a chain, and kept
        // the verified `.commitmeta`: the result of the rule if the check
        // parsed it, else the bytes of the source. The step stages these bytes
        // and does not request them again.
        let (prechecked, filtered, mut known) = match ctx.delta_plan.commit_check(&checksum).await?
        {
            CommitCheck::NotChecked => (false, false, None),
            CommitCheck::Checked { detached, filtered } => (true, filtered, Some(detached)),
        };

        let present = self.has_object(ObjectType::Commit, &checksum).await?;
        let complete = present && self.commit_state(&checksum).await? == CommitState::Normal;
        // How the commit object reaches the object store, after the checks
        // pass. A commit that this repository holds is there already.
        let mut staging = CommitStaging::Held;
        // Detached metadata goes with its commit, and the pull fetches it
        // before the commit. The `ostree` command was observed to request the
        // pair in this order. The pull holds the bytes until the commit object
        // is here, so a commit that the remote does not hold leaves none.
        //
        // The commit bytes are shared, so the bytes of a delta job need no
        // copy.
        let (detached, bytes) = if present {
            let detached = match known.take() {
                Some(detached) => detached,
                None => {
                    fetch_detached_metadata(ctx.source, ctx.sources, ctx.progress, &checksum)
                        .await?
                }
            };
            let bytes = self
                .load_object_bytes(ObjectType::Commit, &checksum)
                .await?;
            (detached, Arc::new(bytes))
        } else if let Some(src) = cached_source(ctx.sources, name).await? {
            // A localcache source holds the object. The pull reads the bytes
            // from there, and the import runs after the checks, in the order of
            // the fetched branches.
            staging = CommitStaging::Import(src);
            let detached = match known.take() {
                Some(detached) => detached,
                None => {
                    fetch_detached_metadata(ctx.source, ctx.sources, ctx.progress, &checksum)
                        .await?
                }
            };
            (
                detached,
                Arc::new(src.load_object_bytes(ObjectType::Commit, &checksum).await?),
            )
        } else if let Some(job) = ctx.deltas.get(&checksum) {
            // A delta carries the target commit in its superblock, and these
            // bytes come from there. The parse of the superblock verified that
            // they hash to this checksum. The write at staging verifies it
            // again.
            staging = CommitStaging::Write(Arc::clone(&job.commit_bytes));
            let detached = match known.take() {
                Some(detached) => detached,
                None => {
                    fetch_detached_metadata(ctx.source, ctx.sources, ctx.progress, &checksum)
                        .await?
                }
            };
            (detached, Arc::clone(&job.commit_bytes))
        } else {
            match self.fetch_remote_commit(ctx, &checksum).await? {
                (detached, Some(bytes)) => {
                    ctx.progress.metadata_fetched();
                    let bytes = Arc::new(bytes);
                    staging = CommitStaging::Write(Arc::clone(&bytes));
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

        // A commit object can be as large as `MAX_METADATA_SIZE`, so the parse
        // runs on the blocking pool.
        let shared = Arc::clone(&bytes);
        let commit = ostrya_rt::unblock(move || Commit::parse(&shared)).await?;
        // The signature verification runs before the pull stages the commit
        // and requests its tree, so a commit that the policy refuses costs no
        // fetch of its own objects. Discovery checked each commit of a chain
        // before the transaction opened: its signatures, and the checks of
        // each requested ref that names it. The step does not check that
        // commit again. The verification reads the detached metadata that
        // this pull puts in place. That is the copy of the remote if it served
        // one, else the copy of this repository. A later verification of the
        // stored commit reads the same metadata.
        // If the verification parses the metadata, the rule of `[ex-ostrya]
        // keep-detached-related` reads that parse right after the
        // verification, and the step keeps only its result. The bytes that
        // the rule of discovery read pass as they are. The step applies the
        // rule to the other bytes that discovery kept, and to a `.commitmeta`
        // that it fetched itself.
        let detached = if prechecked {
            match known {
                None if filtered => Some(CheckedMeta::Filtered(detached)),
                _ => detached.map(CheckedMeta::Source),
            }
        } else {
            let detached = check_commit_signatures_filtered(
                self,
                ctx.verification,
                ctx.related,
                &checksum,
                &bytes,
                detached,
            )
            .await?;
            self.check_tips(ctx, &checksum, &commit).await?;
            detached
        };
        // The checks are the last readers of these bytes. A write keeps its
        // own reference in `staging`, so the other stagings drop the bytes
        // here.
        drop(bytes);

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
            CommitStaging::Write(bytes) => {
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
        // The rule runs after the checks read the metadata as the remote
        // holds it: here, after the verification that parsed it, or in
        // discovery after the verification of a commit of a chain that parsed
        // it. So the rule drops `ostrya.related` from what the pull stores,
        // and the verified metadata stays whole. A dict of which the rule
        // keeps no property stages nothing, and the copy of this repository
        // stays as it is.
        if let Some(meta) = detached
            && let Some(meta) = meta.filtered(ctx.related, &checksum).await?
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
        // The composefs image of the commit follows the other objects of the
        // pull. A commit that is complete here gets its image too, if this
        // repository holds none. A malformed key counts as no key.
        let image = if !ctx.images || !matches!(recorded_digest(&commit), Ok(Some(_))) {
            CommitImage::None
        } else if complete {
            CommitImage::Held
        } else {
            CommitImage::New
        };
        Ok(Step::Commit(CommitOutcome {
            checksum,
            next,
            parent: commit.parent,
            marked: !complete,
            image,
        }))
    }

    /// Makes the ref-binding check and the timestamp check of each requested
    /// ref that names `checksum`.
    ///
    /// The plan fetches a commit once, so a second ref at the same commit has
    /// no step of its own for its checks.
    async fn check_tips(
        &self,
        ctx: &StepCtx<'_>,
        checksum: &Checksum,
        commit: &Commit,
    ) -> Result<()> {
        let refs: Vec<&str> = ctx
            .tips
            .get(checksum)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();
        check_tip_refs(self, ctx.tip_checks, checksum, commit, &refs).await
    }

    /// Runs the step of a commit that an earlier run of this pull made
    /// complete in the transaction.
    ///
    /// The step reads and parses the commit from the transaction in one call
    /// on the blocking pool. It then makes the checks of each requested ref
    /// that names the commit, unless discovery made them. It checks no
    /// signature, requests nothing, and stages nothing. The plan follows the
    /// parent of the commit under `depth`.
    async fn done_commit(&self, ctx: &StepCtx<'_>, checksum: Checksum) -> Result<Step> {
        let commit = ctx.txn.load_commit_staged_first(&checksum).await?;
        if !ctx.delta_plan.checked(&checksum) {
            self.check_tips(ctx, &checksum, &commit).await?;
        }
        Ok(Step::Commit(CommitOutcome {
            checksum,
            next: CommitNext::Nothing,
            parent: commit.parent,
            marked: false,
            image: CommitImage::None,
        }))
    }

    /// Fetches a commit that only the remote can give, with its detached
    /// metadata. The `.commitmeta` comes from the first localcache source that
    /// holds it, else from the remote. The commit object comes after it.
    /// `None` in either place is a file that the remote does not serve.
    ///
    /// From the stream source, the two remote requests are in flight together,
    /// in the order of an HTTP pull, so the pair costs one round trip. From the
    /// HTTP source, the pull requests the commit after the `.commitmeta`
    /// arrives.
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
            None if matches!(ctx.source.transfer(), Transfer::Stream(_)) => {
                let (detached, fetched) = futures_lite::future::zip(
                    fetch_remote_detached(ctx.source, ctx.progress, commit),
                    fetch(),
                )
                .await;
                Ok((detached?, fetched?))
            }
            None => {
                let detached = fetch_remote_detached(ctx.source, ctx.progress, commit).await?;
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
        let fetcher = match ctx.source.transfer() {
            Transfer::Http(fetcher) => fetcher,
            Transfer::Stream(stream) => {
                // A `.filez` has no whole read. The header read caps its header,
                // and the size that the header declares caps its payload.
                let body = stream
                    .get(&path, u64::MAX)
                    .await?
                    .ok_or(Error::ObjectNotFound {
                        checksum: name.checksum,
                        ty: name.ty,
                    })?;
                // The stream source takes no write permit. The session streams
                // one body at a time, and the depth of the pipeline bounds the
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

    /// Fetches the composefs image of `commit` and stages it.
    ///
    /// The step fetches nothing if the transaction staged an image of the
    /// commit or this repository holds one. It does not read a stored image.
    /// An image of a localcache repository is copied from there. Else the
    /// step requests `objects/<xx>/<rest>.cfs` at low priority. A remote that
    /// serves no image, with a 404 or a not-found reply, leaves the commit
    /// without an image, and the pull goes on. The step returns the answer of
    /// the remote in [`Step::Image`].
    ///
    /// The body streams through `read_buf`, the buffer of the slot. The write
    /// computes the fs-verity digest of the image and checks it against the
    /// key of the commit. A digest that is not the key fails the pull with
    /// [`Error::ComposefsDigestMismatch`], and the step fetches the image no
    /// second time.
    async fn fetch_image(
        &self,
        ctx: &StepCtx<'_>,
        commit: Checksum,
        read_buf: &mut Vec<u8>,
    ) -> Result<Step> {
        let name = ObjectName::new(commit, ObjectType::ComposefsImage);
        if ctx.txn.is_staged(&commit, name.ty) || self.has_object(name.ty, &commit).await? {
            return Ok(Step::Image(ImageAnswer::NotAsked));
        }
        if let Some(src) = cached_source(ctx.sources, name).await? {
            ctx.txn.import_composefs_image(src, &commit).await?;
            return Ok(Step::Image(ImageAnswer::NotAsked));
        }
        let path = object_path(&commit, name.ty);
        let fetcher = match ctx.source.transfer() {
            Transfer::Http(fetcher) => fetcher,
            Transfer::Stream(stream) => {
                // The image has no length cap. The stream source takes no
                // write permit, as for a content object.
                let Some(body) = stream.get(&path, u64::MAX).await? else {
                    return Ok(Step::Image(ImageAnswer::Absent));
                };
                ctx.txn
                    .stage_composefs_image_from(&commit, body, read_buf)
                    .await
                    .map_err(session_error)?;
                return Ok(Step::Image(ImageAnswer::Served));
            }
        };
        // A body that fails in transit is fetched again from the start, as
        // for a content object. A failed write removes its temp file.
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
                Err(e) => match Error::from(e) {
                    Error::HttpStatus { status: 404, .. } => {
                        return Ok(Step::Image(ImageAnswer::Absent));
                    }
                    e => return Err(e),
                },
            };
            let permit = ctx.writes.acquire(Priority::Normal).await;
            let stored = ctx
                .txn
                .stage_composefs_image_from(&commit, body, read_buf)
                .await;
            drop(permit);
            match stored {
                Ok(_) => return Ok(Step::Image(ImageAnswer::Served)),
                Err(e @ Error::ComposefsDigestMismatch { .. }) => return Err(e),
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
}

/// What a pull fetched into its transaction, for the transaction commit.
struct FetchedPull {
    txn: Transaction,
    /// The refs to write, and the commit each names.
    targets: Vec<(String, Checksum)>,
    /// The `summary` and `summary.sig` of the remote, which a mirror pull of
    /// every ref copies. Each other pull keeps neither.
    summary: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
}

/// Returns `endpoint` with the request limit `max_outstanding` of the caller,
/// and the options of a stream session to it.
///
/// A limit of the caller replaces the limit of the endpoint. The pull keeps as
/// many steps in flight as the session admits.
pub(super) fn session_options(
    endpoint: Endpoint,
    max_outstanding: Option<usize>,
) -> (Endpoint, StreamSessionOptions) {
    match endpoint {
        Endpoint::Http(mut http) => {
            if let Some(n) = max_outstanding {
                http.max_outstanding = n;
            }
            (Endpoint::Http(http), StreamSessionOptions::default())
        }
        ssh @ Endpoint::Ssh { .. } => (
            ssh,
            StreamSessionOptions {
                agent: None,
                max_outstanding,
            },
        ),
        #[cfg(feature = "s3")]
        Endpoint::S3(mut s3) => {
            if let Some(n) = max_outstanding {
                s3.http.max_outstanding = n;
            }
            (Endpoint::S3(s3), StreamSessionOptions::default())
        }
        // `connect` refuses each other endpoint.
        other => (other, StreamSessionOptions::default()),
    }
}

/// Opens the session of a pull to `endpoint`.
///
/// Over ssh, the session takes the options `stream`. Over HTTP, the options
/// of the endpoint give the request limit, and `stream` must be the default.
///
/// An S3 endpoint gives an HTTP session whose fetcher signs each request,
/// and the bucket client of the repository over the same fetcher, which
/// reads the files at its root. An S3 endpoint has the rules of an HTTP
/// endpoint for `stream`.
pub(super) async fn connect(
    endpoint: Endpoint,
    stream: StreamSessionOptions,
) -> Result<Connection> {
    match endpoint {
        Endpoint::Http(http) => PullSession::connect(Endpoint::Http(http), stream)
            .await
            .map(Connection::from)
            .map_err(http_error),
        ssh @ Endpoint::Ssh { .. } => Ok(PullSession::connect(ssh, stream).await?.into()),
        #[cfg(feature = "s3")]
        Endpoint::S3(s3) => {
            let fetcher = s3_fetcher(&s3, stream).await?;
            // The bucket client shares the fetcher of the session, so the
            // pull builds one fetcher.
            let bucket = crate::remote::s3::Bucket::from_fetcher(&s3, fetcher.clone());
            Ok(Connection {
                session: PullSession::Http(fetcher),
                bucket: Some(bucket),
            })
        }
        _ => Err(crate::endpoint::neither_ssh_nor_http("a pull")),
    }
}

/// Builds the signed fetcher of a pull from the bucket repository of `s3`.
///
/// The fetcher takes the options that `S3Endpoint::pull_options` gives, and
/// `stream` has the rules of an HTTP endpoint. The fetcher is the fetcher
/// that [`PullSession::connect`] builds for an S3 endpoint. The call sends no
/// request.
#[cfg(feature = "s3")]
pub(super) async fn s3_fetcher(
    s3: &crate::remote::s3::S3Endpoint,
    stream: StreamSessionOptions,
) -> Result<Fetcher> {
    let options = s3.pull_options().map_err(http_error)?;
    // The future is boxed, so that the future of an ssh connect does not
    // hold the construction of the fetcher.
    let session = Box::pin(PullSession::connect(Endpoint::Http(options), stream))
        .await
        .map_err(http_error)?;
    let PullSession::Http(fetcher) = session else {
        unreachable!("an HTTP endpoint opens an HTTP session");
    };
    Ok(fetcher)
}

/// Makes the checks of [`Repo::pull_with_session`] over `opts`, and returns
/// the parsed subpaths and the index of the list of static deltas.
///
/// Each check reads `opts` alone, so a refusal sends no request and opens no
/// transaction. The call takes the list out of `opts`, as
/// [`take_static_deltas`] states.
async fn check_session_pull(opts: &mut PullOptions) -> Result<(Option<Subpaths>, Option<Edges>)> {
    let subpaths = Subpaths::parse(&opts.subpaths)?;
    check_depth(opts.depth)?;
    refuse_remote_collection(opts)?;
    check_remote_option(opts)?;
    check_static_deltas(opts)?;
    if opts.refs.is_empty() {
        return Err(no_refs());
    }
    if opts.verify != PullVerify::default() {
        return Err(Error::InvalidInput(
            "a pull with a session takes its signature policy from its trust, and \
             takes no verify option"
                .into(),
        ));
    }
    if opts.trust_group.is_some() {
        return Err(Error::InvalidInput(
            "a pull with a session takes its signature policy from its trust, and \
             takes no trust group"
                .into(),
        ));
    }
    if opts.max_outstanding_fetches.is_some() {
        return Err(Error::InvalidInput(
            "a pull with a session takes its request limit from the session, and \
             takes no max_outstanding_fetches option"
                .into(),
        ));
    }
    if opts.overrides != EndpointOverrides::default() {
        return Err(Error::InvalidInput(
            "a pull with a session takes its server from the session, and takes \
             no endpoint overrides"
                .into(),
        ));
    }
    let edges = take_static_deltas(opts).await?;
    Ok((subpaths, edges))
}

/// Returns the refusal of a pull with a session that names no ref.
fn no_refs() -> Error {
    Error::InvalidInput("a pull with a session needs at least one ref name".into())
}

/// The refs that a pull from a remote takes if
/// [`refs`](PullOptions::refs) is empty, or the refs of a collection pull.
#[derive(Clone, Copy)]
pub(super) enum Wanted<'a> {
    /// No other ref. [`Repo::pull_with_session`] refuses an empty list.
    Named,
    /// Under [`MIRROR`](PullFlags::MIRROR), each ref of the summary of the
    /// remote. Otherwise, the `branches` key of the remote section of this
    /// name.
    Config(&'a str),
    /// The refs of a collection pull, each at the commit that the pull
    /// selected. The pull reads no ref of the remote, and does not read
    /// [`refs`](PullOptions::refs).
    Pinned(&'a Pinned<'a>),
}

/// The refs of a collection pull from one remote, and the checks of their
/// commits.
pub(super) struct Pinned<'a> {
    /// Each ref name, and the commit that the pull selected for it.
    pub(super) targets: Vec<(String, Checksum)>,
    /// The timestamp that the remote listed for each ref of `targets`.
    pub(super) listed: HashMap<String, u64>,
    /// The collection id that the `ostree.collection-binding` of each tip
    /// must state.
    pub(super) collection: &'a str,
    /// The place of the written refs.
    pub(super) place: RefPlace<'a>,
    /// The `summary` of the remote, if the probe of the collection pull read
    /// the refs from it. The probe checked it under the trust of this pull,
    /// so the pull reads these bytes in place of the remote file. The pull
    /// takes them out before the parse.
    pub(super) summary: Mutex<Option<Arc<Vec<u8>>>>,
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
    /// The checks of each requested ref: the ref-binding check, the timestamp
    /// check that the pull resolved before discovery, and the place of the
    /// pulled refs, where the timestamp check reads the current tip of a ref.
    tip_checks: TipChecks<'a>,
    /// The requested refs of each tip commit, for the binding check and the
    /// timestamp check. A commit with no entry is a parent under `depth`,
    /// which no ref names. The map is empty in the run of a level of
    /// intermediate commits.
    tips: &'a HashMap<Checksum, Vec<String>>,
    /// The static delta that delivers each commit of this run, if the remote
    /// publishes one. The pull fetches a commit with no entry object by
    /// object.
    deltas: &'a HashMap<Checksum, DeltaJob>,
    /// The commits that an earlier run of this pull made complete in the
    /// transaction. The step stages nothing for them and checks no signature
    /// again.
    done: &'a HashSet<Checksum>,
    /// The checks that discovery made on the commit of each step of a chain.
    delta_plan: &'a DeltaPlan,
    /// The signature policy of this pull. The pull verifies each commit of a
    /// step before it stages its bytes.
    verification: &'a Verification,
    /// The rule of `[ex-ostrya] keep-detached-related` of this repository. It
    /// applies to the detached metadata that this pull stores, after the
    /// checks of the commit pass.
    related: RelatedRule,
    /// `true` if the pull fetches the composefs image of each commit that
    /// carries the key: a pull that is not commit-only and has no subpath.
    images: bool,
    /// The live counters of the pull.
    progress: &'a PullCounters,
}

/// The commits of one run of the plan, and how the pull fetches them.
struct Phase<'a> {
    /// The commits that the run starts from.
    roots: &'a [Checksum],
    /// The requested refs of each tip commit, as [`StepCtx`] holds them.
    tips: &'a HashMap<Checksum, Vec<String>>,
    /// The number of parents to follow from each root, `-1` for all of them.
    depth: i32,
    /// The subpaths of the walk. `None` walks every tree whole.
    subpaths: Option<Subpaths>,
    /// The static delta of each commit of this run.
    deltas: &'a HashMap<Checksum, DeltaJob>,
    /// The commits that an earlier run made complete in the transaction.
    done: &'a HashSet<Checksum>,
    /// `true` for the last run of the pull.
    last: bool,
}

/// What one run of the plan leaves for the next run.
#[derive(Default)]
struct Carry {
    /// The objects that the runs queued, so that the pull fetches an object
    /// once over all runs.
    queued: HashSet<ObjectName>,
    /// The composefs images that the runs queued. Only the last run fetches
    /// them.
    images: Images,
    /// The units of work that the runs gave to a slot, for the progress total.
    started: usize,
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
    /// The step of a composefs image ended, with the answer of the remote.
    Image(ImageAnswer),
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
    /// The composefs image of the commit that the pull fetches, after the
    /// other objects of the pull.
    image: CommitImage,
}

/// The composefs image that a commit adds to the plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitImage {
    /// No image: the commit carries no valid key, or the pull fetches no
    /// image.
    None,
    /// The image of a commit whose objects this pull takes.
    New,
    /// The image of a commit that this repository holds complete.
    Held,
}

/// What the step of a composefs image got from the remote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImageAnswer {
    /// The step sent no request: the transaction or this repository holds
    /// the image, or a localcache repository supplied it.
    NotAsked,
    /// The remote served the image.
    Served,
    /// The remote serves no image of the commit: a 404, or a not-found
    /// reply.
    Absent,
}

/// How a commit object reaches the object store, after the commit passes the
/// checks of its step.
enum CommitStaging<'a> {
    /// This repository holds it.
    Held,
    /// A localcache repository holds it, and the pull imports it from there.
    Import(&'a Repo),
    /// Its bytes are in memory, and the pull writes them into the transaction.
    Write(Arc<Vec<u8>>),
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
    /// The content objects, drained fourth and fetched at low priority.
    content: VecDeque<ObjectName>,
    /// The composefs images, drained last and fetched at low priority, when
    /// no other step is queued or in flight.
    images: Images,
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

/// The composefs images that a pull fetches, and what the remote answered.
///
/// After the first image that the remote does not serve, the pull requests
/// no image of a held commit. The image of a commit whose objects the pull
/// takes is requested all the same. Until the remote answers a request, at
/// most one image of a held commit is in flight, and only after each image
/// of a new commit. So a remote that serves no image gets at most one
/// request for the held commits.
#[derive(Default)]
struct Images {
    /// The images of the commits whose objects this pull takes.
    new: VecDeque<ObjectName>,
    /// The images of the commits that this repository holds complete.
    held: VecDeque<ObjectName>,
    /// The number of image steps in flight.
    in_flight: usize,
    /// The answers of the remote so far: `None` before the first answer,
    /// `Some(false)` after an image that the remote does not serve, and
    /// `Some(true)` after served images alone.
    served: Option<bool>,
}

impl Images {
    /// Returns the number of queued images.
    fn len(&self) -> usize {
        self.new.len() + self.held.len()
    }

    /// Returns the next image to fetch: the images of new commits, then the
    /// images of held commits by the rule of [`Images`].
    fn next(&mut self) -> Option<ObjectName> {
        let name = match self.new.pop_front() {
            Some(name) => name,
            None => match self.served {
                Some(false) => {
                    self.held.clear();
                    return None;
                }
                None if self.in_flight > 0 => return None,
                _ => self.held.pop_front()?,
            },
        };
        self.in_flight += 1;
        Some(name)
    }

    /// Records the end of the step of one image.
    fn apply(&mut self, answer: ImageAnswer) {
        self.in_flight -= 1;
        match answer {
            ImageAnswer::NotAsked => {}
            ImageAnswer::Served => {
                self.served.get_or_insert(true);
            }
            ImageAnswer::Absent => self.served = Some(false),
        }
    }
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

    /// Queues the composefs image of `commit`, if the commit has one to
    /// fetch.
    fn push_image(&mut self, commit: Checksum, image: CommitImage) {
        let name = ObjectName::new(commit, ObjectType::ComposefsImage);
        if image == CommitImage::None || !self.queued.insert(name) {
            return;
        }
        if image == CommitImage::Held {
            self.images.held.push_back(name);
        } else {
            self.images.new.push_back(name);
        }
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
    /// the scan, then the content. [`next_image`](Plan::next_image) gives the
    /// composefs images.
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

    /// Returns the next composefs image to fetch, when `in_flight` steps are
    /// in flight.
    ///
    /// An image goes out only after each other step of the run: no other
    /// unit of work is queued, and each step in flight is the step of an
    /// image. A dirtree in flight can still queue content, so the images
    /// wait for it. The plan holds back an image while another step is in
    /// flight. This is safe for the same reason as the part cap of
    /// [`next`](Plan::next).
    fn next_image(&mut self, in_flight: usize) -> Option<Item> {
        if !self.commits.is_empty()
            || !self.parts.is_empty()
            || !self.scan.is_empty()
            || !self.content.is_empty()
            || in_flight > self.images.in_flight
        {
            return None;
        }
        self.images.next().map(Item::Object)
    }

    /// Stores the progress total and the scan state: the `started` units of
    /// work given to a slot, and the queued work. `more` is `true` if a later
    /// run of the plan follows this run. The pull then still scans.
    fn report(&self, progress: &PullCounters, started: usize, more: bool) {
        let queued = self.commits.len()
            + self.parts.len()
            + self.scan.len()
            + self.content.len()
            + self.images.len();
        let total = u32::try_from(started + queued).unwrap_or(u32::MAX);
        progress.report(
            total,
            more || !self.commits.is_empty() || !self.scan.is_empty(),
        );
    }

    /// Adds the outcome of one step to the plan.
    fn apply(&mut self, step: Step, marked: &mut Vec<Checksum>) {
        match step {
            Step::Commit(outcome) => self.apply_commit(outcome, marked),
            Step::DirTree(checksum, dirtree) => self.apply_dirtree(checksum, &dirtree),
            Step::Part(commit) => self.apply_part(commit),
            Step::Image(answer) => self.images.apply(answer),
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
        self.push_image(outcome.checksum, outcome.image);
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

/// Reads the `.commitmeta` of a commit from the first localcache source in
/// `sources` that holds it, else from `source`, the remote.
///
/// The caller writes the bytes when the commit object is here. A 404 means
/// that the commit has none, and the copy of this repository stays as it is.
pub(super) async fn fetch_detached_metadata(
    source: &RemoteSource,
    sources: &[Repo],
    progress: &PullCounters,
    commit: &Checksum,
) -> Result<Option<Vec<u8>>> {
    if let Some(bytes) = cached_detached_metadata(sources, commit).await? {
        return Ok(Some(bytes));
    }
    fetch_remote_detached(source, progress, commit).await
}

/// Fetches the `.commitmeta` of a commit from the remote, or `None` if the
/// remote serves none. A file that the remote serves adds one to the metadata
/// count in `progress`.
pub(super) async fn fetch_remote_detached(
    source: &RemoteSource,
    progress: &PullCounters,
    commit: &Checksum,
) -> Result<Option<Vec<u8>>> {
    let path = object_path(commit, ObjectType::CommitMeta);
    let fetched = source
        .read_optional(&path, Priority::High, MAX_METADATA_SIZE)
        .await?;
    if fetched.is_some() {
        progress.metadata_fetched();
    }
    Ok(fetched)
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
pub(super) async fn cached_source(sources: &[Repo], name: ObjectName) -> Result<Option<&Repo>> {
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
pub(crate) async fn read_archive_header<R: AsyncRead + Unpin>(
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
    // object, and moves a stream session to its next reply. It comes before
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

/// A compile-time check that the future of a pull is `Send`: from a remote,
/// through a session of the caller, and from a local repository.
const _: fn() = || {
    fn assert_send<T: Send>(_: &T) {}
    let _ = |repo: &Repo| assert_send(&repo.pull("origin", PullOptions::default()));
    let _ = |repo: &Repo, session: PullSession| {
        assert_send(&repo.pull_with_session(
            session,
            PullTrust::unverified(),
            PullOptions::default(),
        ))
    };
    let _ = |repo: &Repo, src: &Repo| assert_send(&repo.pull_local(src, PullOptions::default()));
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
            image: CommitImage::None,
        })
    }

    /// Returns `step`, the outcome of a commit, with `image` as the
    /// composefs image of the commit to fetch.
    fn with_image(step: Step, image: CommitImage) -> Step {
        match step {
            Step::Commit(outcome) => Step::Commit(CommitOutcome { image, ..outcome }),
            other => other,
        }
    }

    /// Returns the outcome of a commit that this repository holds complete.
    fn held(checksum: Checksum) -> Step {
        Step::Commit(CommitOutcome {
            checksum,
            next: CommitNext::Nothing,
            parent: None,
            marked: false,
            image: CommitImage::Held,
        })
    }

    /// Returns the next unit of work as the drive loop takes it, with
    /// `in_flight` steps in flight.
    fn take(plan: &mut Plan, in_flight: usize) -> Option<Item> {
        plan.next().or_else(|| plan.next_image(in_flight))
    }

    /// Returns the composefs image that `item` names.
    fn image_of(item: Option<Item>) -> ObjectName {
        match item {
            Some(Item::Object(name)) if name.ty == ObjectType::ComposefsImage => name,
            _ => panic!("the plan gave no image"),
        }
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
            image: CommitImage::None,
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

    /// The composefs image of a commit drains after the content of the pull,
    /// also the content of a later commit. A commit that is complete here
    /// queues its image too. A commit with no image to fetch queues none.
    #[test]
    fn the_image_of_a_commit_drains_after_the_content() {
        let mut plan = Plan::default();
        let mut marked = Vec::new();
        plan.apply(
            with_image(
                fetched(
                    csum(1),
                    vec![object(4, ObjectType::File), object(2, ObjectType::DirMeta)],
                    None,
                ),
                CommitImage::New,
            ),
            &mut marked,
        );
        plan.apply(
            fetched(csum(5), vec![object(6, ObjectType::File)], None),
            &mut marked,
        );
        plan.apply(held(csum(7)), &mut marked);
        let mut drained = Vec::new();
        while let Some(item) = take(&mut plan, 0) {
            let Item::Object(name) = item else {
                panic!("the test queues objects alone");
            };
            drained.push(name);
            if name.ty == ObjectType::ComposefsImage {
                plan.apply(Step::Image(ImageAnswer::Served), &mut marked);
            }
        }
        assert_eq!(
            drained,
            [
                object(2, ObjectType::DirMeta),
                object(4, ObjectType::File),
                object(6, ObjectType::File),
                object(1, ObjectType::ComposefsImage),
                object(7, ObjectType::ComposefsImage),
            ]
        );
    }

    /// The composefs image of a commit waits while a dirtree is in flight,
    /// also when the content queue is empty. The dirtree can still queue
    /// content, and that content goes out before the image.
    #[test]
    fn the_image_waits_for_a_dirtree_in_flight() {
        let mut plan = Plan::default();
        let mut marked = Vec::new();
        plan.apply(
            with_image(
                fetched(csum(1), vec![object(3, ObjectType::DirTree)], None),
                CommitImage::New,
            ),
            &mut marked,
        );
        let Some(Item::Object(tree)) = take(&mut plan, 0) else {
            panic!("the plan gave no dirtree");
        };
        assert_eq!(tree, object(3, ObjectType::DirTree));
        assert!(plan.content.is_empty());
        assert!(take(&mut plan, 1).is_none());

        let dirtree = DirTree {
            files: vec![("f".to_owned(), csum(4))],
            dirs: Vec::new(),
        };
        plan.apply(Step::DirTree(tree.checksum, dirtree), &mut marked);
        let Some(Item::Object(file)) = take(&mut plan, 0) else {
            panic!("the plan gave no content");
        };
        assert_eq!(file, object(4, ObjectType::File));
        assert!(take(&mut plan, 1).is_none());

        plan.apply(Step::Done, &mut marked);
        assert_eq!(
            image_of(take(&mut plan, 0)),
            object(1, ObjectType::ComposefsImage)
        );
        assert!(take(&mut plan, 1).is_none());
    }

    /// The composefs image of a commit that a delta delivers waits for the
    /// parts and for the tree.
    #[test]
    fn the_image_of_a_delta_commit_waits_for_the_last_part() {
        let mut plan = Plan::default();
        let mut marked = Vec::new();
        let tree = vec![object(2, ObjectType::DirMeta)];
        plan.apply(
            with_image(by_delta(csum(1), 1, Vec::new(), tree), CommitImage::New),
            &mut marked,
        );
        assert!(matches!(take(&mut plan, 0), Some(Item::Part(_))));
        assert!(take(&mut plan, 1).is_none());

        plan.apply(Step::Part(csum(1)), &mut marked);
        let Some(Item::Object(name)) = take(&mut plan, 0) else {
            panic!("the plan gave no tree object");
        };
        assert_eq!(name, object(2, ObjectType::DirMeta));
        assert!(take(&mut plan, 1).is_none());
        plan.apply(Step::Done, &mut marked);
        assert_eq!(
            image_of(take(&mut plan, 0)),
            object(1, ObjectType::ComposefsImage)
        );
    }

    /// After an image that the remote does not serve, the plan gives no image
    /// of a held commit. The images of new commits go out all the same. Until
    /// the remote answers, one image of a held commit is in flight.
    #[test]
    fn an_absent_image_stops_the_images_of_held_commits() {
        let mut plan = Plan::default();
        let mut marked = Vec::new();
        for byte in [1, 2, 3] {
            plan.apply(held(csum(byte)), &mut marked);
        }
        plan.apply(
            with_image(fetched(csum(9), Vec::new(), None), CommitImage::New),
            &mut marked,
        );
        plan.apply(
            with_image(fetched(csum(8), Vec::new(), None), CommitImage::New),
            &mut marked,
        );
        // The images of the new commits go out together, and the held images
        // wait for their answers.
        let first = image_of(take(&mut plan, 0));
        let second = image_of(take(&mut plan, 1));
        assert_eq!([first.checksum, second.checksum], [csum(9), csum(8)]);
        assert!(take(&mut plan, 2).is_none());
        plan.apply(Step::Image(ImageAnswer::NotAsked), &mut marked);
        assert!(take(&mut plan, 1).is_none());
        plan.apply(Step::Image(ImageAnswer::NotAsked), &mut marked);

        // No answer yet: one held image probes the remote.
        assert_eq!(image_of(take(&mut plan, 0)).checksum, csum(1));
        assert!(take(&mut plan, 1).is_none());
        plan.apply(Step::Image(ImageAnswer::Absent), &mut marked);
        assert!(take(&mut plan, 0).is_none());
        assert_eq!(plan.images.len(), 0);

        // A new commit still gets its image.
        plan.apply(
            with_image(fetched(csum(7), Vec::new(), None), CommitImage::New),
            &mut marked,
        );
        assert_eq!(image_of(take(&mut plan, 0)).checksum, csum(7));
    }

    /// After a served image, the images of held commits go out together.
    #[test]
    fn a_served_image_releases_the_images_of_held_commits() {
        let mut plan = Plan::default();
        let mut marked = Vec::new();
        for byte in [1, 2, 3] {
            plan.apply(held(csum(byte)), &mut marked);
        }
        assert_eq!(image_of(take(&mut plan, 0)).checksum, csum(1));
        assert!(take(&mut plan, 1).is_none());
        plan.apply(Step::Image(ImageAnswer::Served), &mut marked);
        assert_eq!(image_of(take(&mut plan, 0)).checksum, csum(2));
        assert_eq!(image_of(take(&mut plan, 1)).checksum, csum(3));
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
    /// it stores the object. So a stream session moves to its next reply while
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
