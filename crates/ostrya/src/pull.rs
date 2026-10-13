//! Pulls of refs and their objects from another repository.
//!
//! - [`Repo::pull_local`] reads a local repository directly.
//! - [`Repo::pull`] fetches from an HTTP remote, or over ssh from a remote
//!   with an ssh address.
//! - [`Repo::pull_with_session`] reads through a
//!   [`PullSession`](crate::remote::PullSession) that the caller opened,
//!   under a [`PullTrust`](crate::verify::PullTrust) that the caller gives.
//!   It reads no remote section of the config.
//!
//! The three pulls share [`PullOptions`], [`PullFlags`], [`PullStats`], the
//! ref-binding check, and the `.commitpartial` markers. [`PullVerify`] holds
//! the signature policy of each pull other than [`Repo::pull_with_session`].
//!
//! The sections from "Concurrency" to "Retries" apply to a pull from a
//! remote: [`Repo::pull`] and [`Repo::pull_with_session`].
//!
//! # Commit state
//!
//! The pull writes a zero-length `state/<commit>.commitpartial` marker for
//! each commit before it stores the commit object. It removes the marker
//! after the objects of the commit are published. So an interrupted pull
//! leaves the commit marked partial. A local pull writes no marker for a
//! commit that this repository holds complete.
//!
//! Two kinds of pull keep the marker in place, as the `ostree` command
//! does:
//!
//! - a [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull, which did not fetch
//!   the content of the commit.
//! - a pull from a remote with [`subpaths`](PullOptions::subpaths), which
//!   fetched part of the content.
//!
//! The pull does not write over a marker that is present. So the one-byte
//! state that fsck writes stays after a pull over the commit that it
//! marked.
//!
//! If a pull returns an error, it removes the markers that it wrote for
//! commits that this repository does not hold. Its transaction published
//! no object, so such a marker guards nothing. A commit that this
//! repository holds keeps its marker, which the pull found in place over a
//! partial commit. A later [`prune`](Repo::prune) also removes each marker
//! whose commit is absent.
//!
//! # Marker durability
//!
//! The pull does not fsync a marker or `state/`, as the `ostree` command
//! does. The markers stay unsynced under each option.
//!
//! The pull writes each marker before [`Transaction::commit`]. So the
//! `syncfs` at the start of publication makes the marker durable before the
//! first object rename. A staged object enters `objects/` in that rename,
//! so no staged object is reachable before the marker that guards it is
//! durable.
//!
//! A local pull writes all its markers before the first import. A pull
//! from a remote writes the marker of each commit in the step that fetched
//! that commit.
//!
//! The removal of the markers is the last operation of the pull, and no
//! barrier follows it. So a crash right after a successful pull can leave a
//! marker on a complete commit. This costs availability, and the
//! integrity of the repository stays. Checkout refuses the commit until
//! the next pull of it, or a prune of it, clears the marker.
//!
//! # Concurrency
//!
//! A pull from a remote keeps as many steps in flight as its session admits:
//! [`PullSession::max_outstanding`](crate::remote::PullSession::max_outstanding).
//! [`Repo::pull`] gives the session the limit of
//! [`max_outstanding_fetches`](PullOptions::max_outstanding_fetches). If the
//! value is `None`, an HTTP pull keeps up to
//! [`max_outstanding`](crate::fetch::FetcherOptions::max_outstanding) of its
//! endpoint, and a pull over ssh keeps up to 8. Each step fetches one object
//! and stores it. The pull fills a free step from a plan of three classes, in
//! this order and with the matching fetch priority:
//!
//! - the commits: the requested tips, and their parents under
//!   [`depth`](PullOptions::depth)
//! - the scan: the dirtree and dirmeta objects that the walk waits for
//! - the content: the file objects, which nothing waits for
//!
//! The parts of a static delta drain after the commits and before the
//! scan. This drain order sets the order of the requests of a pull. The
//! fetcher admits as many requests at once as the pull has steps.
//!
//! A step has one fetch outstanding at a time, so the admission gate never
//! queues a request of one pull. If more callers share a [`Fetcher`] than
//! it admits, the priority of a class sets the order.
//!
//! With more than one step, the request order is not fixed: when a step
//! finishes, the free step takes the next queued object. The set of
//! requests and the class order are fixed.
//!
//! # Write permits
//!
//! A content step takes one of three write permits when the response head
//! arrives. It holds the permit for the whole body:
//!
//! - the read of the archive header.
//! - the payload stream into the object store.
//! - the read that finds the end of the stream.
//!
//! So a fast remote puts at most three concurrent writers on the
//! destination file system.
//!
//! The step takes the permit before it reads the body. So a wait for a
//! permit does not count against the progress clock of the fetcher. This
//! clock measures the silence since a read asked for bytes. The header
//! usually arrives in the first frame, so the permit spans that frame, the
//! payload, and the byte that ends the stream.
//!
//! A body that waits for a permit holds the bytes that it received,
//! unread. Over HTTP/2 these bytes are flow-control credit. The fetcher
//! gives a connection one stream window for each request that it admits.
//! So a waiting body holds its own credit, and the metadata stream that a
//! scan waits for receives over its own window.
//!
//! The stream source takes no write permit. Its session streams one body at a
//! time, and the depth of the pipeline bounds the stores that finish after
//! the end of their body.
//!
//! # Memory
//!
//! A content object streams into the object store through the 128 KiB
//! read buffer of its step. The step buffers the header alone, which
//! `MAX_FILE_HEADER_SIZE` caps at 1 MiB. All objects that a step stores
//! share its read buffer, from the remote or from a localcache repository.
//! Each object in flight also allocates the 16 KiB through which the
//! decoder reads its compressed input.
//!
//! The pull reads a metadata object (a commit, a dirtree, a dirmeta, or a
//! `.commitmeta`) whole, under the 128 MiB cap of the format,
//! [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE). The size of the buffer
//! comes from the length that the remote declares. A step holds one such
//! buffer, and the step of a commit holds two: the commit and its
//! `.commitmeta`.
//!
//! The metadata that a pull holds is at most two times that cap times the
//! step count.
//!
//! # Connections
//!
//! After the payload, a content step of an HTTP pull reads its response to
//! the end. One byte is enough, because nothing follows the final DEFLATE
//! block of an object. This read returns the connection to the pool.
//! HTTP/1.1 carries one request at a time, so a pull uses up to one
//! connection for each step.
//!
//! Bytes after the payload fail the pull. The stored form of a symlink has
//! the same rule.
//!
//! # Retries
//!
//! If a request of an HTTP pull fails with a retryable failure, the pull
//! sends it again, up to
//! [`max_retries`](crate::fetch::FetcherOptions::max_retries) times of the
//! endpoint. [`resolve_pull`](crate::endpoint::resolve_pull) sets 5. A body can
//! fail in transit: a cut connection, a silent peer, or a transfer slower
//! than the low-speed rule. Then the pull fetches it again from its first
//! byte. Each refetch spends one repeat of the same count.
//!
//! The bytes of the failed read stage nothing, and the pull removes their
//! temp file before the refetch. The pull does not fetch a body again if
//! it refused the body for its content. An object that spends the count
//! fails its step, and the first failed step ends the pull.
//!
//! [`Fetcher`]: crate::fetch::Fetcher

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_lite::AsyncReadExt;
use ostrya_core::{
    Checksum, Commit, ContentHasher, DirTree, ObjectName, ObjectType, RepoMode, Value,
};
use rustix::fs::{AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::file::FileKind;
use crate::modifier::FilterResult;
use crate::perm;
use crate::refs::{CollectionRef, collection_ref_to_relpath, refspec_to_relpath};
use crate::repo::Repo;
use crate::summary::AdvertisedDelta;
use crate::transaction::Transaction;
use crate::traverse::reaches_at_least;
use crate::write::FileMeta;

mod chain;
mod delta;
mod drive;
#[doc(hidden)]
pub mod http;
mod source;
mod subpath;
mod verify;

/// The chunk size of a streamed read of the payload of a content object.
const READ_CHUNK: usize = 128 * 1024;

/// The mode that a `state/<commit>.commitpartial` marker is created with,
/// before the process umask. In a `bare-user-shared` repository an `fchmod`
/// after the create sets [`perm::SHARED_FILE_MODE`].
pub(crate) const PARTIAL_MARKER_MODE: u32 = 0o644;

/// The flags of a pull.
///
/// A bit set of the flag constants. Combine flags with `|`, and test a flag
/// with [`contains`](PullFlags::contains).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PullFlags(u32);

impl PullFlags {
    /// The empty flag set.
    pub const NONE: PullFlags = PullFlags(0);
    /// The verification of the checksum of each imported object against its
    /// name.
    ///
    /// A mismatch fails a local pull with [`Error::ChecksumMismatch`]. The flag
    /// is off by default, as in the `ostree` command: a local source is
    /// trusted, and the pull links its objects without a read.
    /// [`Repo::pull_local`] states the reads that the flag adds.
    pub const UNTRUSTED: PullFlags = PullFlags(1 << 0);
    /// The import of the commit objects alone.
    ///
    /// The pull does not walk the trees, and it keeps the `.commitpartial`
    /// marker of each commit.
    pub const COMMIT_ONLY: PullFlags = PullFlags(1 << 1);
    /// The refusal of a regular file whose logical mode has bits outside
    /// `0775`.
    ///
    /// The flag refuses a world-writable, setuid, setgid, or sticky file with
    /// [`Error::Pull`]. A symlink is exempt. Each pull applies the check: to a
    /// local import, to a fetched loose object, and to the objects that a
    /// static delta part produces. A `bare-user-only` destination applies a
    /// stricter rule with or without this flag, as [`Repo::pull_local`] states.
    pub const BAREUSERONLY_FILES: PullFlags = PullFlags(1 << 2);
    /// The skip of the `ostree.ref-binding` check.
    ///
    /// Without this flag, the pull checks that the `ostree.ref-binding` list of
    /// each pulled commit names the ref that the pull reads. A commit with no
    /// binding key passes. A commit with a list that does not name the ref
    /// fails the pull with [`Error::Pull`].
    pub const DISABLE_VERIFY_BINDINGS: PullFlags = PullFlags(1 << 3);
    /// A copy of each object, with no hardlink.
    ///
    /// An import from a source on another file system copies each object
    /// without this flag too. The pull copies a content object through its
    /// header, so the object gets the inode policy of this repository.
    pub const FORCE_COPY: PullFlags = PullFlags(1 << 4);
    /// A mirror of a remote: local refs, and a copy of the summary.
    ///
    /// [`Repo::pull`] writes the pulled refs as local refs under
    /// `refs/heads/`. If [`refs`](PullOptions::refs) is empty, the pull takes
    /// each ref that the summary of the remote lists. If the pull takes each
    /// such ref, it copies the `summary` and `summary.sig` bytes of the remote
    /// to this repository.
    ///
    /// [`Repo::pull_local`] ignores this flag. It writes the pulled refs under
    /// the prefix that [`remote`](PullOptions::remote) names, or as local refs
    /// if that is `None`. An empty [`refs`](PullOptions::refs) list takes each
    /// ref of the source under `refs/heads`.
    pub const MIRROR: PullFlags = PullFlags(1 << 5);

    /// Returns the empty flag set.
    pub const fn empty() -> PullFlags {
        PullFlags(0)
    }

    /// Returns `true` if each bit of `other` is set in `self`.
    pub const fn contains(self, other: PullFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns the raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl std::ops::BitOr for PullFlags {
    type Output = PullFlags;

    fn bitor(self, rhs: PullFlags) -> PullFlags {
        PullFlags(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for PullFlags {
    fn bitor_assign(&mut self, rhs: PullFlags) {
        self.0 |= rhs.0;
    }
}

/// The commit that the timestamp of a fetched tip is compared against.
///
/// A pull refuses a tip that moves a ref back in time, so a downgrade cannot
/// arrive as an ordinary update. The pull refuses only a strictly older
/// timestamp: an equal timestamp passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TimestampCheck {
    /// No check.
    #[default]
    Off,
    /// The commit that the ref names in this repository now.
    ///
    /// A ref that this repository does not hold passes.
    CurrentRef,
    /// A given commit.
    ///
    /// A pull from a remote that has at least one target reads the commit one
    /// time, so this repository must hold it. The pull reads it after the
    /// `summary`, the `config`, and the ref files of the remote, and before it
    /// fetches a delta index, a static delta superblock, a `.commitmeta`, or
    /// an object. If this repository does not hold the commit, the pull fails
    /// with [`Error::ObjectNotFound`] at that point. A pull with no target
    /// reads no commit. A local pull makes no timestamp check and reads no
    /// commit.
    Rev(Checksum),
}

/// The signature policy of a pull.
///
/// Each field overrides the remote config key of the same name. If a field is
/// `None`, [`Repo::pull`] takes the value from the config of the remote:
///
/// - `gpg-verify`, default `true`.
/// - `gpg-verify-summary`, default `false`.
/// - `sign-verify` and `sign-verify-summary`, both default off.
///
/// If a field is `None`, [`Repo::pull_local`] does not verify those
/// signatures. The `ostree` command has the same defaults for `pull` and
/// `pull-local`. A `Some` field sets the policy whatever the config says.
/// `Some(true)` on a sign-api field selects each engine of this build, as
/// `sign-verify=true` does.
///
/// The keys come from the config section of a remote. If a pull names no
/// remote and asks for a verification, it fails with [`Error::Pull`] before
/// it fetches anything.
///
/// # Keys
///
/// - GPG: the trusted set of the remote. The set holds the
///   `<remote>.trustedkeys.gpg` of the repository,
///   `/etc/ostree/remotes.d/<remote>.trustedkeys.gpg`, the global trusted
///   directory, and the keyrings that `gpgkeypath` names.
/// - The sign api: a value of `sign-verify` is a boolean or a list of engine
///   names. The keys of an engine are its `verification-<engine>-key` and
///   `verification-<engine>-file` entries and the system key store, less the
///   revoked set of the store.
///
/// The GPG axis and the sign-api axis are independent. If a policy asks for
/// both, the pull verifies both. In the sign-api axis, one engine that
/// reports a valid signature is sufficient, so `sign-verify=ed25519;spki`
/// accepts a commit signed by either engine. The `ostree` command does the
/// same.
///
/// # When the pull verifies
///
/// The pull verifies the summary when it has the summary and its signature.
/// The verification comes before the pull reads the refs or the deltas of
/// the summary. If the policy covers the summary and the source has no
/// `summary` or no `summary.sig`, the pull fails with [`Error::Signature`].
///
/// The policy belongs to the pull, so the pull verifies each commit that it
/// carries. This includes the parents that a depth pull follows and a commit
/// that this repository already holds. A commit that fails the policy fails
/// the pull with [`Error::Signature`].
///
/// A pull from a remote verifies a commit outside a chain of static deltas in
/// the step that fetched it. The verification comes before the pull stages
/// the bytes and before it requests the tree.
///
/// With a [`static_deltas`](PullOptions::static_deltas) list, discovery
/// verifies each commit of a chain before the transaction opens. It reads the
/// commit from the superblock of its step, so it fetches no `.commit` object.
///
/// - An intermediate commit that no requested ref names gets the signature
///   checks alone. Discovery makes no ref-binding check and no timestamp
///   check on it. So a chain can go through a commit whose ref binding names
///   another ref.
/// - A target commit gets the signature checks. Then it gets the ref-binding
///   check and the timestamp check of each requested ref that names it, in
///   the order of the refs.
/// - If a requested ref names an intermediate commit, discovery also makes
///   the ref-binding check and the timestamp check of that ref.
///
/// A local pull makes no timestamp check.
///
/// A commit that discovery refuses costs the superblocks and the
/// `.commitmeta` files that discovery fetched, and the pull fetches no part.
/// The pull does not verify a commit of a chain a second time. If the last
/// plan of discovery drops a commit, the commit gets its checks when the pull
/// fetches it.
///
/// The pull verifies the superblock of a static delta before it fetches a
/// part of the delta. For a chain, discovery verifies the superblock of each
/// step before it verifies the commit of the step. Only the sign-api axis
/// applies to a superblock, because a static delta carries sign-api
/// signatures alone. A superblock with no signature of an engine of the
/// policy passes, and the commit that the delta gives still gets its checks.
/// If each such signature of a superblock is from a key that is not trusted,
/// the pull fails with [`Error::Signature`].
///
/// A local pull verifies the commits and the summary before the transaction
/// opens, so a source that the policy refuses imports nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PullVerify {
    /// A GPG signature on each commit, from a trusted keyring of the remote.
    pub gpg: Option<bool>,
    /// A GPG signature on the summary of the remote, from the same keyrings.
    pub gpg_summary: Option<bool>,
    /// A sign-api signature on each commit, from a trusted key.
    ///
    /// A trusted key comes from the config of the remote or from the system
    /// key store.
    pub sign: Option<bool>,
    /// A sign-api signature on the summary of the remote, from a trusted key.
    pub sign_summary: Option<bool>,
}

/// A callback that decides if a pull stores one property of detached metadata.
///
/// The pull calls it before it stores the metadata of a commit. The arguments
/// are the commit, the key of the property, and the value of the property. The
/// value is the `v` member of the `a{sv}` entry, so it is a
/// [`Value::Variant`]. [`Allow`](FilterResult::Allow) stores the property,
/// and [`Skip`](FilterResult::Skip) leaves it out.
pub type DetachedMetadataFilterFn =
    Arc<dyn Fn(&Checksum, &str, &Value) -> FilterResult + Send + Sync>;

/// The detached-metadata filter of a pull, unset by default.
///
/// The pull calls the filter once for each property of the `.commitmeta` of
/// each commit, and stores the properties that it allows. If the filter
/// allows no property, the pull stores nothing, and the destination keeps the
/// detached metadata that it holds.
///
/// The filter runs after each signature verification of the pull, over the
/// metadata as the source holds it. A filter that drops a signature does not
/// change the result of that verification. The stored commit then has no
/// signature for a later verification.
///
/// The pull calls the filter on the blocking pool. The callback is shared (an
/// `Arc`), because a pull from a remote carries several commits at a time and
/// calls the filter from each. So several threads can call the filter at the
/// same time. A filter that keeps state supplies its own interior mutability.
/// If a pull fails while a filter call runs, that call runs to its end, so the
/// callback can run after the pull returns the error.
/// The pull can call the filter for a commit that a later check of the pull
/// refuses, so a call does not mean that the pull stores the commit.
///
/// A pull from a remote with a list of static deltas
/// ([`PullOptions::static_deltas`]) checks the signatures of each commit of a
/// chain in discovery, before the transaction opens. If the pull verifies the
/// signatures of commits, discovery calls the filter for each such commit
/// right after its signature check, over the parse of that check. Discovery
/// keeps the result, and the pull stores it with no second call. So the pull
/// can also call the filter for a commit that a later plan of discovery drops,
/// and for a commit of a pull that fails later in discovery. If the pull does
/// not verify the signatures of commits, it calls the filter for a commit of a
/// chain when it fetches the commit, as for each other commit.
#[derive(Clone, Default)]
pub struct DetachedMetadataFilter(Option<DetachedMetadataFilterFn>);

impl DetachedMetadataFilter {
    /// Creates a filter that calls `f` for each property.
    pub fn new<F>(f: F) -> DetachedMetadataFilter
    where
        F: Fn(&Checksum, &str, &Value) -> FilterResult + Send + Sync + 'static,
    {
        DetachedMetadataFilter(Some(Arc::new(f)))
    }

    /// Creates a filter from a callback that the caller already holds.
    ///
    /// A caller can share one callback between several [`PullOptions`] this
    /// way.
    pub fn from_fn(f: DetachedMetadataFilterFn) -> DetachedMetadataFilter {
        DetachedMetadataFilter(Some(f))
    }

    /// Creates a filter that drops the named metadata keys and keeps the
    /// other properties.
    ///
    /// Each name matches the whole key of a property. An empty list keeps each
    /// property, so the pull stores the source bytes unchanged. A name that no
    /// commit holds drops nothing, and a name can occur more than once in the
    /// list.
    ///
    /// If the list names each property of a commit, the pull writes nothing
    /// for that commit, and the detached metadata that the destination holds
    /// stays. A copy that the destination stored before the list named its
    /// keys stays too.
    ///
    /// The `ostrya` CLI builds the filter with this constructor from the
    /// repository config key `[ex-ostrya] detached-metadata-exclude`
    /// ([`RepoConfig::detached_metadata_exclude`](crate::RepoConfig::detached_metadata_exclude)).
    /// These names share the key space that
    /// [`PruneOptions::gc_root_metadata_keys`](crate::PruneOptions::gc_root_metadata_keys)
    /// reads, and neither list comes from the other. The library reads no
    /// config: a pull filters what its options state.
    pub fn excluding<I, S>(names: I) -> DetachedMetadataFilter
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let names: Vec<String> = names.into_iter().map(Into::into).collect();
        DetachedMetadataFilter::new(move |_, key, _| {
            if names.iter().any(|name| name == key) {
                FilterResult::Skip
            } else {
                FilterResult::Allow
            }
        })
    }

    /// Returns the serialized properties of `bytes` that this filter allows,
    /// or `None` if the caller writes nothing.
    ///
    /// An unset filter, a filter that allows each property, and the zero-length
    /// "no metadata" marker each give the input bytes back unchanged. So a pull
    /// that filters nothing out stores the bytes of the source unchanged. A
    /// filter that allows no property gives `None`, and the destination keeps
    /// the detached metadata that it holds.
    pub(crate) fn apply(&self, commit: &Checksum, bytes: Vec<u8>) -> Result<Option<Vec<u8>>> {
        if self.0.is_none() {
            return Ok(Some(bytes));
        }
        let Some(dict) = crate::summary::parse_signature_dict(&bytes)? else {
            return Ok(Some(bytes));
        };
        self.apply_parsed(commit, bytes, dict)
    }

    /// Runs [`apply`](DetachedMetadataFilter::apply) on the blocking pool.
    ///
    /// An unset filter and the zero-length marker parse nothing, so they give
    /// the input bytes back on the calling task.
    pub(crate) async fn apply_on_pool(
        &self,
        commit: &Checksum,
        bytes: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        if self.0.is_none() || bytes.is_empty() {
            return Ok(Some(bytes));
        }
        let filter = self.clone();
        let commit = *commit;
        ostrya_rt::unblock(move || filter.apply(&commit, bytes)).await
    }

    /// Runs [`apply`](DetachedMetadataFilter::apply) over the `.commitmeta`
    /// bytes `bytes`, whose parse is `dict`.
    ///
    /// The call parses nothing. It serializes only a dict of which the filter
    /// keeps some properties. The result is the result of `apply`.
    pub(crate) fn apply_parsed(
        &self,
        commit: &Checksum,
        bytes: Vec<u8>,
        dict: Value,
    ) -> Result<Option<Vec<u8>>> {
        let Some(filter) = &self.0 else {
            return Ok(Some(bytes));
        };
        match kept_entries(filter, commit, dict)? {
            Kept::All(_) => Ok(Some(bytes)),
            Kept::Nothing => Ok(None),
            Kept::Part(kept) => {
                // The source bytes are not part of the result, so they drop
                // before the serialization.
                drop(bytes);
                crate::summary::serialize_signature_dict(&Value::Array(kept)).map(Some)
            }
        }
    }

    /// Returns the properties of the parsed detached metadata `dict` that this
    /// filter allows, or `None` if the caller writes nothing.
    ///
    /// An unset filter and a filter that allows each property give `dict`
    /// back unchanged. A filter that allows no property gives `None`.
    #[cfg_attr(not(feature = "push"), allow(dead_code))]
    pub(crate) fn apply_value(&self, commit: &Checksum, dict: Value) -> Result<Option<Value>> {
        let Some(filter) = &self.0 else {
            return Ok(Some(dict));
        };
        match kept_entries(filter, commit, dict)? {
            Kept::All(dict) => Ok(Some(dict)),
            Kept::Nothing => Ok(None),
            Kept::Part(kept) => Ok(Some(Value::Array(kept))),
        }
    }
}

/// The properties of a detached metadata dict that a filter keeps.
enum Kept {
    /// Every property: the dict as it came in.
    All(Value),
    /// Some of the properties, in their order.
    Part(Vec<Value>),
    /// No property.
    Nothing,
}

/// Runs `filter` over each property of the detached metadata `dict` of
/// `commit`.
///
/// A value that is not a dict, and an entry that is not `{sv}`, are
/// [`Error::InvalidFormat`].
fn kept_entries(filter: &DetachedMetadataFilterFn, commit: &Checksum, dict: Value) -> Result<Kept> {
    let Value::Array(entries) = dict else {
        return Err(Error::InvalidFormat(format!(
            "detached metadata of {commit} is not a dict"
        )));
    };
    let mut allowed = Vec::with_capacity(entries.len());
    for entry in &entries {
        let (key, value) = entry
            .as_tuple()
            .and_then(|fields| match fields {
                [key, value] => key.as_str().map(|key| (key, value)),
                _ => None,
            })
            .ok_or_else(|| {
                Error::InvalidFormat(format!(
                    "detached metadata of {commit} holds an entry that is not `{{sv}}`"
                ))
            })?;
        allowed.push(filter(commit, key, value) == FilterResult::Allow);
    }
    if allowed.iter().all(|allow| *allow) {
        return Ok(Kept::All(Value::Array(entries)));
    }
    if !allowed.iter().any(|allow| *allow) {
        return Ok(Kept::Nothing);
    }
    let kept = entries
        .into_iter()
        .zip(allowed)
        .filter_map(|(entry, allow)| allow.then_some(entry))
        .collect();
    Ok(Kept::Part(kept))
}

impl std::fmt::Debug for DetachedMetadataFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(_) => f.write_str("DetachedMetadataFilter(set)"),
            None => f.write_str("DetachedMetadataFilter(unset)"),
        }
    }
}

/// The options of a pull.
///
/// The defaults give the behavior of [`Repo::pull_local`]. Each field that
/// only a pull from a remote reads defaults to the behavior of a local pull.
///
/// # Fields for each kind of pull
///
/// - Each pull reads [`refs`](PullOptions::refs),
///   [`remote`](PullOptions::remote),
///   [`no_ref_writes`](PullOptions::no_ref_writes),
///   [`flags`](PullOptions::flags), [`depth`](PullOptions::depth),
///   [`localcache_repos`](PullOptions::localcache_repos),
///   [`disable_fsync`](PullOptions::disable_fsync),
///   [`per_object_fsync`](PullOptions::per_object_fsync),
///   [`disable_static_deltas`](PullOptions::disable_static_deltas),
///   [`require_static_deltas`](PullOptions::require_static_deltas),
///   [`static_deltas`](PullOptions::static_deltas),
///   [`verify`](PullOptions::verify), and
///   [`detached_metadata_filter`](PullOptions::detached_metadata_filter).
/// - Only a local pull reads [`collection_id`](PullOptions::collection_id).
///   A pull from a remote refuses it.
/// - A pull from a remote also reads [`subpaths`](PullOptions::subpaths),
///   [`overrides`](PullOptions::overrides),
///   [`max_outstanding_fetches`](PullOptions::max_outstanding_fetches),
///   [`timestamp_check`](PullOptions::timestamp_check), and
///   [`progress`](PullOptions::progress). A local pull refuses `subpaths`.
/// - [`Repo::pull_with_session`] refuses an empty `refs`, a `verify` other
///   than the default, `overrides` other than the default, and a set
///   `max_outstanding_fetches`.
#[derive(Debug, Clone, Default)]
pub struct PullOptions {
    /// The ref names to pull.
    ///
    /// With an empty list, a local pull takes each ref of the source under
    /// `refs/heads`. [`Repo::pull`] takes each ref that the summary of the
    /// remote lists under [`MIRROR`](PullFlags::MIRROR), and the configured
    /// `branches` of the remote otherwise. [`Repo::pull_with_session`]
    /// refuses an empty list with [`Error::InvalidInput`].
    pub refs: Vec<String>,
    /// The remote name under which the pull writes the refs
    /// (`refs/remotes/<remote>/<ref>`).
    ///
    /// If the value is `None`, a local pull and [`Repo::pull_with_session`]
    /// write local refs under `refs/heads/`. [`Repo::pull`] then writes the
    /// refs under the name of the remote. A pull from a remote writes local
    /// refs under [`MIRROR`](PullFlags::MIRROR), whatever the value. Under
    /// [`no_ref_writes`](PullOptions::no_ref_writes) the pull writes no ref,
    /// and the name still selects the ref that the pull reads.
    ///
    /// [`Repo::pull`] and [`Repo::pull_with_session`] refuse a name that
    /// [`valid_remote_name`](crate::config::valid_remote_name) refuses, with
    /// [`Error::InvalidInput`], before the first request. They refuse it also
    /// under `MIRROR`.
    pub remote: Option<String>,
    /// The option to write no ref.
    ///
    /// The pull stores the objects and the detached metadata, and clears the
    /// `.commitpartial` marker of each commit that it completes, as without
    /// the option. The caller writes the refs.
    ///
    /// [`PullStats`] does not report the commits of a pull. A local pull
    /// without [`collection_id`](PullOptions::collection_id) resolves each
    /// name in [`refs`](PullOptions::refs) on the source with revision syntax.
    /// So a caller pins the commit of a ref when it gives the checksum as the
    /// name. With `collection_id`, each name is a ref name alone.
    ///
    /// A pull from a remote resolves each name as a ref name, through the
    /// summary or the ref file of the remote. There, a checksum names no
    /// commit and fails with [`Error::RefNotFound`], unless the remote holds a
    /// ref of that name.
    ///
    /// A pull from a remote still reads the ref that it writes without the
    /// option. Delta discovery takes the commit of that ref as the source of a
    /// delta, and [`TimestampCheck::CurrentRef`] compares against it. A local
    /// pull reads that ref only for delta discovery, under
    /// [`require_static_deltas`](PullOptions::require_static_deltas) or with a
    /// list of [`static_deltas`](PullOptions::static_deltas). Under this
    /// option, a [`MIRROR`](PullFlags::MIRROR) pull of each ref copies no
    /// `summary` and no `summary.sig`.
    ///
    /// If a pulled commit has detached metadata, the pull takes the update
    /// lock to write it, as [`Transaction::commit`] does. If the caller holds
    /// an [`UpdateGuard`](crate::UpdateGuard) of the destination during the
    /// pull, the pull waits for that guard until the lock timeout.
    pub no_ref_writes: bool,
    /// The collection id of the refs that a local pull reads.
    ///
    /// With an id, [`Repo::pull_local`] resolves each name in
    /// [`refs`](PullOptions::refs) as the collection ref
    /// `refs/mirrors/<id>/<name>` of the source. The name is a ref name alone:
    /// the pull reads a checksum, an abbreviated checksum, and an ancestry
    /// suffix as part of the name. If the source holds no collection ref for a
    /// name, the pull fails with [`Error::RefNotFound`], which carries the path
    /// of the collection ref. A path that names a directory, or that goes
    /// through a file, fails the same way.
    ///
    /// The ref-binding check and delta discovery read the name alone, as
    /// without the option. The pull does not read `ostree.collection-binding`.
    ///
    /// The id needs [`no_ref_writes`](PullOptions::no_ref_writes) and at least
    /// one name in [`refs`](PullOptions::refs). Without them the local pull
    /// fails with [`Error::Unsupported`]. If the ref store refuses the id or a
    /// name, or if a name holds `:`, the pull fails with
    /// [`Error::InvalidRefspec`], which carries `<id>:<name>`.
    ///
    /// Delta discovery reads the name as a refspec, where a `:` changes what
    /// the name refers to. The local pull makes these checks in this order,
    /// before it reads the source. [`Repo::pull`] and
    /// [`Repo::pull_with_session`] refuse an id with [`Error::Unsupported`]
    /// before they send a request.
    pub collection_id: Option<String>,
    /// The flag set.
    pub flags: PullFlags,
    /// The number of parents of each pulled commit that the pull follows.
    ///
    /// `0` takes the named commit alone, and `-1` takes the whole ancestry
    /// that the source holds. The pull follows the chain of each ref to this
    /// depth separately, so the order of the refs does not change the
    /// commits. A value below `-1` is [`Error::InvalidInput`], and the pull
    /// writes no object and no ref.
    pub depth: i32,
    /// More local repositories that supply an object that the source does not
    /// hold, in order.
    ///
    /// A pull from a remote reads each object from these repositories before
    /// the network, through the import path of a local pull. It verifies the
    /// checksum of each such object.
    pub localcache_repos: Vec<Repo>,
    /// The option to turn off each sync of this pull.
    ///
    /// The option turns off these syncs:
    ///
    /// - the per-object syncs.
    /// - the `syncfs` and the directory syncs of publication.
    /// - the syncs of the detached metadata of each pulled commit, of the ref
    ///   writes, and of the summary that a mirror pull copies.
    ///
    /// `false` leaves `[core] fsync` in control. The option never turns a sync
    /// on, and it changes no byte that the pull writes.
    /// [`Transaction::commit`] states the sync sequence.
    pub disable_fsync: bool,
    /// The option to sync the file of each content object that this pull
    /// stages.
    ///
    /// The pull syncs each file when it stages it, whatever
    /// `[core] per-object-fsync` says, and `false` leaves the key in control.
    /// The pull does not sync a metadata object or a hardlinked object
    /// separately.
    /// If fsync is off, from `[core] fsync` or from
    /// [`disable_fsync`](PullOptions::disable_fsync), the pull syncs nothing.
    /// [`Transaction::commit`] states the sync sequence.
    pub per_object_fsync: bool,
    /// The parts of the tree of each commit that a pull from a remote fetches.
    ///
    /// Each value is an absolute path. An empty list fetches the whole tree.
    /// A path through a directory fetches the dirtree and the dirmeta of that
    /// directory and no sibling of it.
    ///
    /// The pull fetches the whole entry that the last component of the path
    /// names. Several paths fetch the union. The pull always fetches the root
    /// dirtree and dirmeta, and `/` fetches nothing more.
    ///
    /// A pull with subpaths leaves each commit that it marks partial, and a
    /// later pull without subpaths completes it. A value that does not start
    /// with `/`, the empty value included, fails the pull with
    /// [`Error::Pull`]. [`Repo::pull_local`] refuses the option with
    /// [`Error::Unsupported`].
    ///
    /// The pull splits each value on `/` after its leading `/`, and keeps each
    /// component, also an empty one. A component `.` or `..`, or an empty
    /// component from a doubled `/`, matches no entry, because no dirtree entry
    /// has such a name. `/sub/` fetches the `sub` dirtree and dirmeta and
    /// nothing in them. A file named by a component that is not the last, and
    /// a name that the dirtree does not hold, end the path there.
    ///
    /// Into an `archive` repository, a subpath pull takes no delta and fetches
    /// the subpaths loose, unless it requires static deltas. Into another
    /// mode, the pull applies a delta that it finds whole, and the walk after
    /// its last part finds the subpaths present.
    pub subpaths: Vec<String>,
    /// The overrides of the endpoint resolution of [`Repo::pull`]: the values
    /// of [`EndpointOverrides`](crate::endpoint::EndpointOverrides).
    ///
    /// [`Repo::pull`] gives them to
    /// [`resolve_pull`](crate::endpoint::resolve_pull) with the config of this
    /// repository and the name of the remote. A value of the caller wins over
    /// its remote key. `resolve_pull` refuses the push fields `push_token_file`
    /// and `push_user` with [`Error::InvalidInput`]. The default value
    /// overrides nothing, and the pull defaults then apply: 5 retries, 8
    /// requests in flight, and a low speed limit of 1000 bytes per second for
    /// 30 seconds.
    ///
    /// [`Repo::pull_with_session`] refuses a value other than the default
    /// with [`Error::InvalidInput`], because its session selects the server.
    pub overrides: crate::endpoint::EndpointOverrides,
    /// The number of fetches that a pull from a remote keeps in flight.
    ///
    /// For an HTTP endpoint, a value replaces
    /// [`max_outstanding`](crate::fetch::FetcherOptions::max_outstanding) of
    /// the endpoint, and `None` keeps the value of the endpoint.
    /// [`resolve_pull`](crate::endpoint::resolve_pull) sets 8. For an ssh
    /// endpoint, the value sets
    /// [`max_outstanding`](crate::remote::StreamSessionOptions::max_outstanding)
    /// of the stream session, and `None` is 8.
    ///
    /// [`Repo::pull_with_session`] refuses a value that is set with
    /// [`Error::InvalidInput`]. The limit of its session applies.
    pub max_outstanding_fetches: Option<usize>,
    /// The commit that the timestamp of a fetched tip is compared against.
    pub timestamp_check: TimestampCheck,
    /// The option to fetch each object loose and ignore static deltas.
    ///
    /// This option wins over
    /// [`require_static_deltas`](PullOptions::require_static_deltas): a pull
    /// that asks for no delta looks for none, so it finds nothing to require. A
    /// local pull reads a delta only if it requires one or applies a list of
    /// [`static_deltas`](PullOptions::static_deltas). So with this option, a
    /// local pull reads no delta. [`Repo::pull`] states the static delta rules
    /// of a pull.
    ///
    /// A pull refuses this option together with
    /// [`static_deltas`](PullOptions::static_deltas).
    pub disable_static_deltas: bool,
    /// The option to require a static delta for each commit that the pull
    /// looks up.
    ///
    /// If the source serves no summary, the pull fails with [`Error::Pull`].
    /// With a summary, the pull refuses with [`Error::Pull`] a commit that this
    /// repository does not hold complete, in two cases:
    ///
    /// - the delta index and the summary name no delta that the pull can take.
    /// - the superblock of the chosen delta is absent.
    ///
    /// The pull leaves a from-scratch delta alone if the ref names a commit
    /// that this repository holds complete, or names the target commit. Such a
    /// delta satisfies the requirement, and that pull fetches its objects
    /// loose. The pull does not look up a commit that this repository holds
    /// complete, so a pull with nothing to fetch is not refused.
    ///
    /// With a list in [`static_deltas`](PullOptions::static_deltas), a pull
    /// needs no summary. It fails with [`Error::Pull`] for a target commit
    /// that no chain of the list reaches. A listed delta from scratch to the
    /// target that the rule above leaves alone counts as found: the pull does
    /// not fail, and fetches that target loose.
    ///
    /// A local pull reads a delta from the source directory only under this
    /// option or with a list. [`Repo::pull_local`] states the static delta
    /// rules of a local pull. The fetch counters of [`PullStats`] count the
    /// files that the local pull reads.
    ///
    /// A local pull reads the summary of the source and its signature under
    /// the size cap of a summary, 64 MiB. It refuses a file of the source that
    /// is not a regular file, so no read waits on a FIFO.
    pub require_static_deltas: bool,
    /// A list of static deltas that replaces the delta search of the pull.
    ///
    /// `None` keeps the search that [`Repo::pull`] and [`Repo::pull_local`]
    /// state. The list can come from [`Summary::static_deltas`] of a ref
    /// listing. Each entry names the source commit, the target commit, and the
    /// SHA-256 digest of the superblock of one delta. The pull ignores an
    /// entry that is equal to an earlier entry.
    ///
    /// The pull refuses these lists with [`Error::InvalidInput`], before its
    /// first request and before its transaction opens:
    ///
    /// - a list with two entries that have the same source and target and
    ///   different digests.
    /// - a list together with
    ///   [`disable_static_deltas`](PullOptions::disable_static_deltas).
    /// - a list together with a [`subpaths`](PullOptions::subpaths) list that
    ///   is not empty. [`Repo::pull_local`] refuses subpaths with
    ///   [`Error::Unsupported`] before this check.
    ///
    /// Each pull applies the chain with the fewest steps to each target
    /// commit, by the rules of [`Repo::pull`] under `# Static deltas`.
    /// [`Repo::pull_local`] states the rules of a local pull under the same
    /// heading. A [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull ignores the
    /// list.
    ///
    /// [`Summary::static_deltas`]: crate::Summary::static_deltas
    pub static_deltas: Option<Vec<AdvertisedDelta>>,
    /// The signature policy of this pull, over the configured policy of the
    /// remote.
    ///
    /// [`Repo::pull_with_session`] refuses a value other than the default
    /// with [`Error::InvalidInput`]. Its
    /// [`PullTrust`](crate::verify::PullTrust) holds the keys.
    pub verify: PullVerify,
    /// The properties of the detached metadata of a commit that this pull
    /// stores.
    ///
    /// The default keeps each property, so the pull stores the bytes of the
    /// source unchanged. The pull calls the filter on the blocking pool, and
    /// several threads can call it at the same time. If a pull fails while a
    /// filter call runs, that call runs to its end, so the callback can run
    /// after the pull returns the error. A call does not mean that the pull
    /// stores the commit: a later check of the pull can refuse it.
    ///
    /// If the pull verifies the signatures of commits, a pull from a remote
    /// calls the filter for each commit of a chain of
    /// [`static_deltas`](PullOptions::static_deltas) in discovery, right after
    /// the signature check of the commit, before the transaction opens. So the
    /// pull can call it for a commit that a later plan of discovery drops, or
    /// for a commit of a pull that fails later in discovery. Else the pull
    /// calls it when it fetches the commit.
    pub detached_metadata_filter: DetachedMetadataFilter,
    /// The handle to which a pull from a remote adds its live counters.
    ///
    /// A caller can show the progress of the pull while it runs. `None` keeps
    /// the counts in the counters of the pull alone. A local pull does not use
    /// the handle.
    pub progress: Option<PullProgress>,
}

/// Applies the durability options of a pull to its transaction.
fn apply_durability(txn: &mut Transaction, opts: &PullOptions) {
    if opts.disable_fsync {
        txn.set_fsync(false);
    }
    if opts.per_object_fsync {
        txn.set_per_object_fsync(true);
    }
}

/// The counts of what a pull imported and fetched.
///
/// The import counters and the written counters cover the objects that the
/// pull staged. An object that the destination already held does not count.
/// The plan of a [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull is the commit
/// objects alone, so the pull reports those and no content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PullStats {
    /// The number of metadata objects that the pull imported.
    pub metadata_imported: u32,
    /// The number of content objects that the pull imported.
    pub content_imported: u32,
    /// The total on-disk size of the imported content objects.
    ///
    /// The total counts an object whether the pull wrote its bytes or shared
    /// them by reflink or by hardlink. It is the storage that those objects
    /// use, so it can be larger than the space that the pull used.
    pub content_bytes_written: u64,
    /// The total payload size of the regular files that the pull wrote.
    ///
    /// The size is before the compression that the destination mode applies.
    /// A symlink, an object shared by hardlink, and an object that a static
    /// delta produced add nothing. The `ostree` command reports this figure as
    /// the content written.
    pub content_bytes_unpacked: u64,
    /// The number of metadata requests of a pull from a remote.
    ///
    /// The count is the metadata fetched, as the `ostree` command counts it.
    /// The count includes each loose metadata object and `.commitmeta` that
    /// the remote served. It also includes each request for a delta index or a
    /// delta superblock, whatever the remote answered.
    ///
    /// A local pull that
    /// [requires static deltas](PullOptions::require_static_deltas), or that
    /// applies a list of [`static_deltas`](PullOptions::static_deltas), counts
    /// the same files when it reads them from the source. Each other local
    /// pull counts zero.
    pub metadata_fetched: u32,
    /// The number of content objects that a pull fetched loose from the
    /// remote.
    ///
    /// An object from a localcache repository does not count. A local pull
    /// counts as [`metadata_fetched`](PullStats::metadata_fetched) states.
    pub content_fetched: u32,
    /// The number of static delta parts that a pull fetched as files.
    ///
    /// A part that the superblock carries inline does not count. A local pull
    /// counts as [`metadata_fetched`](PullStats::metadata_fetched) states.
    pub delta_parts: u32,
    /// The bytes of the successful response bodies that a pull from a remote
    /// read.
    ///
    /// The count starts after the summary, the config, and the ref files of
    /// the remote, and it includes retried bodies. A local pull that requires
    /// static deltas, or that applies a list of static deltas, counts the
    /// stored size of each file that the other fetch counters count, and of
    /// each part file. Each other local pull counts zero.
    ///
    /// A pull over ssh counts the payload bytes of each body that it reads.
    /// So the HTTP count and the ssh count agree for the same files.
    pub bytes_transferred: u64,
    /// The run time of the pull.
    pub elapsed: Duration,
}

/// The live counters of pulls from a remote.
///
/// A caller reads the counters while the pulls run. The caller sets a clone of
/// the handle in [`PullOptions::progress`], and reads
/// [`snapshot`](PullProgress::snapshot) from another task or thread. A pull
/// adds to the counters of the handle and never sets them to zero. A local
/// pull does not use the handle.
///
/// If several pulls share a handle, or one pull after another uses it, the
/// handle shows the sum of their counters. Its `scanning` state is on while
/// any of the pulls scans. A caller that wants the progress of one pull gives
/// that pull a handle of its own.
///
/// The [`PullStats`] of a pull come from its own counters, whatever the handle
/// holds. Each count is one relaxed atomic add to those counters, and one more
/// to the handle if the pull has one. The pull counts the transferred bytes
/// once for each data frame of a response body.
#[derive(Debug, Clone, Default)]
pub struct PullProgress {
    inner: Arc<ProgressCounters>,
}

/// The counters behind a [`PullProgress`], and the counters of one pull.
#[derive(Debug, Default)]
pub(crate) struct ProgressCounters {
    /// The byte count, shared with the fetcher of the pull, which adds the
    /// bytes of each body.
    transferred: Arc<AtomicU64>,
    metadata_fetched: AtomicU32,
    content_fetched: AtomicU32,
    objects_done: AtomicU32,
    objects_total: AtomicU32,
    /// The number of pulls that scan: 0 or 1 in the counters of one pull.
    scanning: AtomicU32,
    delta_parts_fetched: AtomicU32,
    delta_parts_total: AtomicU32,
    delta_bytes_fetched: AtomicU64,
    delta_bytes_total: AtomicU64,
}

/// The counters of one pull: its own counters, which its [`PullStats`] read,
/// and the handle of the caller, which gets the same additions.
///
/// A local pull has no handle of the caller.
pub(crate) struct PullCounters {
    own: ProgressCounters,
    caller: Option<Arc<ProgressCounters>>,
}

impl PullCounters {
    /// Creates the counters of a pull that starts now in the scanning state.
    ///
    /// The counters also count into `caller` if it is present.
    pub(crate) fn new(caller: Option<&PullProgress>) -> PullCounters {
        let counters = PullCounters {
            own: ProgressCounters::default(),
            caller: caller.map(|progress| Arc::clone(&progress.inner)),
        };
        counters.each(|c| {
            c.scanning.fetch_add(1, Ordering::Relaxed);
        });
        counters
    }

    /// Runs `f` on the own counters of the pull, then on those of the caller.
    fn each(&self, f: impl Fn(&ProgressCounters)) {
        f(&self.own);
        if let Some(caller) = &self.caller {
            f(caller);
        }
    }

    /// Returns the byte counters to which the fetcher of the pull adds the
    /// bytes of each body.
    pub(crate) fn transferred_sinks(&self) -> Vec<Arc<AtomicU64>> {
        let mut sinks = vec![Arc::clone(&self.own.transferred)];
        if let Some(caller) = &self.caller {
            sinks.push(Arc::clone(&caller.transferred));
        }
        sinks
    }

    /// Takes back each byte counted so far from both counter sets, so the
    /// count starts again from zero.
    ///
    /// No request is in flight when a pull calls this function.
    pub(crate) fn restart_transferred(&self) {
        let counted = self.own.transferred.swap(0, Ordering::Relaxed);
        if let Some(caller) = &self.caller {
            caller.transferred.fetch_sub(counted, Ordering::Relaxed);
        }
    }

    /// Counts one metadata request that the `ostree` command counts as
    /// metadata fetched.
    pub(crate) fn metadata_fetched(&self) {
        self.each(|c| {
            c.metadata_fetched.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Counts one content object fetched loose.
    pub(crate) fn content_fetched(&self) {
        self.each(|c| {
            c.content_fetched.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Counts one finished unit of work.
    pub(crate) fn object_done(&self) {
        self.each(|c| {
            c.objects_done.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Adds `bytes` read from a local source to the transferred count.
    ///
    /// The fetcher of an HTTP pull adds to this count itself.
    pub(crate) fn add_transferred(&self, bytes: u64) {
        self.each(|c| {
            c.transferred.fetch_add(bytes, Ordering::Relaxed);
        });
    }

    /// Counts one delta part fetched as a file, of declared size `size`.
    pub(crate) fn part_fetched(&self, size: u64) {
        self.each(|c| {
            c.delta_parts_fetched.fetch_add(1, Ordering::Relaxed);
            c.delta_bytes_fetched.fetch_add(size, Ordering::Relaxed);
        });
    }

    /// Adds `parts` delta parts of declared sizes `bytes` to the totals.
    pub(crate) fn parts_planned(&self, parts: u32, bytes: u64) {
        self.each(|c| {
            c.delta_parts_total.fetch_add(parts, Ordering::Relaxed);
            c.delta_bytes_total.fetch_add(bytes, Ordering::Relaxed);
        });
    }

    /// Sets the total units of work of the pull to `total` and its scanning
    /// state to `scanning`.
    ///
    /// The sums of the caller move by the same change.
    pub(crate) fn report(&self, total: u32, scanning: bool) {
        let before = self.own.objects_total.swap(total, Ordering::Relaxed);
        let was = self
            .own
            .scanning
            .swap(u32::from(scanning), Ordering::Relaxed);
        if let Some(caller) = &self.caller {
            caller
                .objects_total
                .fetch_add(total.wrapping_sub(before), Ordering::Relaxed);
            match (was, scanning) {
                (0, true) => caller.scanning.fetch_add(1, Ordering::Relaxed),
                (1, false) => caller.scanning.fetch_sub(1, Ordering::Relaxed),
                _ => 0,
            };
        }
    }

    /// Returns the own count of metadata fetched of the pull.
    pub(crate) fn metadata(&self) -> u32 {
        self.own.metadata_fetched.load(Ordering::Relaxed)
    }

    /// Returns the own count of content objects fetched of the pull.
    pub(crate) fn content(&self) -> u32 {
        self.own.content_fetched.load(Ordering::Relaxed)
    }

    /// Returns the own count of delta parts fetched of the pull.
    pub(crate) fn parts(&self) -> u32 {
        self.own.delta_parts_fetched.load(Ordering::Relaxed)
    }

    /// Returns the own count of bytes transferred of the pull.
    pub(crate) fn bytes(&self) -> u64 {
        self.own.transferred.load(Ordering::Relaxed)
    }
}

impl Drop for PullCounters {
    /// Ends the scanning state in the handle of the caller if the pull ends
    /// on an error while it scans.
    fn drop(&mut self) {
        if let Some(caller) = &self.caller
            && self.own.scanning.load(Ordering::Relaxed) != 0
        {
            caller.scanning.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl PullProgress {
    /// Creates a handle with all counters at zero.
    pub fn new() -> PullProgress {
        PullProgress::default()
    }

    /// Returns the counters as they are now.
    ///
    /// The method reads each counter separately, so two counters of one
    /// snapshot can differ by the work of one step.
    pub fn snapshot(&self) -> PullProgressSnapshot {
        let c = &self.inner;
        PullProgressSnapshot {
            bytes_transferred: c.transferred.load(Ordering::Relaxed),
            metadata_fetched: c.metadata_fetched.load(Ordering::Relaxed),
            content_fetched: c.content_fetched.load(Ordering::Relaxed),
            objects_done: c.objects_done.load(Ordering::Relaxed),
            objects_total: c.objects_total.load(Ordering::Relaxed),
            scanning: c.scanning.load(Ordering::Relaxed) != 0,
            delta_parts_fetched: c.delta_parts_fetched.load(Ordering::Relaxed),
            delta_parts_total: c.delta_parts_total.load(Ordering::Relaxed),
            delta_bytes_fetched: c.delta_bytes_fetched.load(Ordering::Relaxed),
            delta_bytes_total: c.delta_bytes_total.load(Ordering::Relaxed),
        }
    }
}

/// The counters of a [`PullProgress`] at one point in time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PullProgressSnapshot {
    /// The value of [`PullStats::bytes_transferred`] so far.
    pub bytes_transferred: u64,
    /// The value of [`PullStats::metadata_fetched`] so far.
    pub metadata_fetched: u32,
    /// The value of [`PullStats::content_fetched`] so far.
    pub content_fetched: u32,
    /// The units of work that the pull finished.
    ///
    /// One unit is a commit, an object, or a delta part that the pull handled,
    /// fetched or found present.
    pub objects_done: u32,
    /// The units of work that the pull knows of.
    ///
    /// The count includes the finished units, the units in flight, and the
    /// queued units. It grows as the walk reads each dirtree.
    pub objects_total: u32,
    /// The scanning state: `true` while the total still grows.
    ///
    /// The value is `true` while a pull has not reached its objects yet, or
    /// has a commit or a dirtree in its queue.
    pub scanning: bool,
    /// The value of [`PullStats::delta_parts`] so far.
    pub delta_parts_fetched: u32,
    /// The delta parts that the pull fetches as files, over all deltas that it
    /// takes.
    pub delta_parts_total: u32,
    /// The sum of the declared sizes of the delta parts fetched so far.
    pub delta_bytes_fetched: u64,
    /// The sum of the declared sizes of all delta parts that the pull fetches
    /// as files.
    pub delta_bytes_total: u64,
}

/// Methods that pull from a local repository.
impl Repo {
    /// Pulls refs and their objects from another local repository.
    ///
    /// The pull resolves each requested ref in `src`, and follows its commit
    /// chain to [`depth`](PullOptions::depth) parents. It imports each object
    /// that those commits reach into this repository, in one transaction. If
    /// the pull fails, it publishes no object and writes no ref.
    ///
    /// A parent commit that the source does not hold ends its chain without an
    /// error. So a source with a truncated history pulls what it has.
    ///
    /// The pull writes the refs last, after the objects are published. So no
    /// ref of this repository names a commit with objects that are not durable.
    /// Under [`no_ref_writes`](PullOptions::no_ref_writes) the pull writes no
    /// ref.
    ///
    /// With [`collection_id`](PullOptions::collection_id), each name in
    /// [`refs`](PullOptions::refs) is the collection ref
    /// `refs/mirrors/<id>/<name>` of `src`, read as a ref name alone.
    /// [`verify`](PullOptions::verify) selects the signature policy, as
    /// [`PullVerify`] states. The module [`pull`](self) states the rules of
    /// the `.commitpartial` markers.
    ///
    /// # Sources
    ///
    /// The pull reads the source repository first, and then each of
    /// [`localcache_repos`](PullOptions::localcache_repos) in turn. It takes an
    /// object from the first source that holds it.
    ///
    /// The pull trusts the objects that this repository holds, and it does not
    /// import them. It takes an object as held if a `stat` of its path finds an
    /// entry. The `stat` does not follow a symlink.
    ///
    /// The walk reads a dirtree from this repository if this repository holds
    /// it, and from the first source that holds it otherwise. So a localcache
    /// repository supplies a subtree that the source lost.
    ///
    /// For each dirtree that it reads, the walk makes one blocking call. The
    /// call makes a `stat` of each name that the walk did not meet before. It
    /// plans the objects that this repository lacks, and no other objects.
    ///
    /// The walk descends into each dirtree that it reads, also into a dirtree
    /// that this repository holds and no source holds. It imports each object
    /// below that dirtree that this repository lacks from the first source that
    /// holds it. If neither this repository nor a source holds an object, the
    /// pull fails when the import gets to it, so a published commit is
    /// complete.
    ///
    /// The pull walks all its commits as one tree, and descends into each
    /// dirtree once. So a deep pull of a chain of near-identical trees reads
    /// each dirtree once. The plan of each commit holds the objects that the
    /// plans of the commits before it did not hold.
    ///
    /// # Damaged dirtrees
    ///
    /// If this repository holds a dirtree that the pull cannot read or parse,
    /// the pull fails, also if a source holds a good copy. The causes are:
    ///
    /// - a file that this process cannot read.
    /// - an entry that is not a regular file.
    /// - a symlink that points to no file.
    /// - a file larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    /// - bytes that do not parse as a dirtree.
    ///
    /// [`fsck`](Repo::fsck) with [`delete`](crate::FsckOptions::delete) does
    /// not remove such a dirtree. A pull after the removal of the entry from
    /// `objects/` imports that dirtree from the first source that holds it.
    ///
    /// # Complete commits
    ///
    /// A commit is complete in this repository if the commit object is present
    /// and no `.commitpartial` marker names it. The pull does not walk such a
    /// commit: it reads no object of its tree, and imports its detached
    /// metadata alone.
    ///
    /// A gap in a complete commit stays until [`fsck`](Repo::fsck) marks the
    /// commit partial. Then a pull walks its tree and fills the gap. `fsck`
    /// marks a commit partial if a content object or a dirmeta object is
    /// missing. At a missing dirtree, `fsck` ends with
    /// [`FsckFailure::MissingDirTree`](crate::FsckFailure::MissingDirTree) and
    /// marks nothing, so no pull repairs that commit.
    ///
    /// # Import paths
    ///
    /// An imported object gets the file system metadata (unix mode, ownership,
    /// and xattrs) that a commit into this repository gives it. Within that
    /// rule, the object shares the bytes and the inode of the source. The path
    /// of an import depends on how much of the object the two repositories
    /// store in the same form.
    ///
    /// - Hardlink: the pull hardlinks an object with one shared form into the
    ///   staging directory of the transaction. Each metadata object has one
    ///   form in each mode. A content object has one form between repositories
    ///   of the same mode. A symlink object has one form between `bare-user`
    ///   and `bare-user-shared`.
    /// - Reflink or copy of a metadata object: if the pull cannot link a
    ///   metadata object, it makes a `FICLONE` reflink. If the reflink fails,
    ///   it makes a byte copy. The new inode is that of a metadata object written
    ///   into this repository: mode 0644, no xattrs, and the ownership of the
    ///   writing process.
    /// - Clone: the pull clones a regular file if the two modes share its
    ///   payload bytes and not its inode metadata, as two modes of the bare
    ///   family do. The clone is a `FICLONE`
    ///   reflink of the payload, or a copy if the reflink fails. The pull
    ///   applies the inode policy of this repository again from the logical
    ///   header of the object. It reads the header from the metadata of the
    ///   object, and does not read the payload for it.
    /// - Re-ingest: the pull reads the remaining content objects into their
    ///   logical form (uid, gid, mode, xattrs, and payload). It writes them
    ///   through the ordinary ingest path, in the form that the destination
    ///   mode needs. These objects are a content object across the `archive`
    ///   boundary and a symlink between modes that store it in different
    ///   forms. `archive` stores a framed, deflated form that no other mode
    ///   shares.
    ///
    /// If the pull cannot link a content object, it uses the clone or the
    /// re-ingest path. These paths give the object the inode metadata that a
    /// commit into this repository writes.
    ///
    /// # Hardlink rules
    ///
    /// A hardlink cannot separate the bytes from the ownership. So the pull
    /// links an object only if the ownership of the source inode is the
    /// ownership that a write into this repository gives.
    ///
    /// In a `bare` destination this is always true for a content object. Its
    /// uid, gid, permission bits, and xattrs come from the header that its
    /// checksum covers. Two `bare` repositories thus agree on such an inode
    /// byte for byte.
    ///
    /// In each other mode, the ownership comes from the writing process and
    /// the staging directory. So the pull compares the uid and the gid of the
    /// source inode with the pair that a new object in this repository gets.
    /// If the owners of the two repositories differ, for example two
    /// group-shared repositories of different groups, the pull does not link.
    /// It writes each object again, with a reflink of the bytes if the file
    /// system supports it, and a copy if not.
    ///
    /// The pull reads only the ownership of the source inode. It trusts that
    /// the permission bits and the xattrs match the header of the object, and
    /// does not check them. In `archive`, `bare-user`, and `bare-user-shared`
    /// the checksum of the object covers neither.
    ///
    /// Out-of-band changes to the inodes of a source thus go into this
    /// repository. Examples are a copy that dropped modes and a `chmod` over
    /// `objects/`. A pull of the `ostree` command does the same.
    ///
    /// The pull does not apply again the attributes from the environment of
    /// this repository. Examples are a default POSIX ACL on its directories
    /// and a security label. An object that the pull writes gets them from the
    /// environment, and a linked object keeps those of the source.
    ///
    /// A link fails in these cases:
    ///
    /// - the two repositories are on different file systems.
    /// - the source inode is at its link limit.
    /// - the protected-hardlink rules of the kernel refuse it.
    ///
    /// [`FORCE_COPY`](PullFlags::FORCE_COPY) turns off each link.
    ///
    /// A repository that seals its objects with fs-verity does not hardlink.
    /// Verity is a property of an inode, so a seal of a shared inode also
    /// seals the copy of the source. An unsealed link breaks the rule of the
    /// destination that each object stored as a regular file is sealed. Such a
    /// destination copies each object and seals each copy.
    ///
    /// This is a divergence from the `ostree` command, which hardlinks into a
    /// `fsverity=yes` repository and leaves the imported objects unsealed.
    ///
    /// # Bare-user-only destinations
    ///
    /// A `bare-user-only` destination refuses a content object whose logical
    /// header is not the header that it stores. That mode records no ownership
    /// and no xattrs, and it reduces the permission bits of a regular file to
    /// `perm & 0o755`. A commit into it names each object for that canonical
    /// header. An import keeps the name that the object arrives under.
    ///
    /// The pull refuses each of these with [`Error::Pull`]: a non-zero uid or
    /// gid, an xattr, and a regular-file mode with bits outside `0755`. The
    /// destination can hold such an object only under a name that its stored
    /// form does not hash to. This check applies to each pull, and also to
    /// the objects of a static delta part.
    ///
    /// This is a divergence from the `ostree` command, which hardlinks the
    /// object in and leaves a repository that its own fsck reports corrupt.
    /// [`BAREUSERONLY_FILES`](PullFlags::BAREUSERONLY_FILES) adds a rule of
    /// its own for each destination mode.
    ///
    /// # Free space
    ///
    /// The import charges the blocks that it allocates to the `min-free-space`
    /// budget of the transaction. A hardlinked object allocates no block, and
    /// a reflinked payload shares the extents of the source. So a pull of
    /// objects that the destination shares with the source can run on a file
    /// system with no space for a second copy. A byte-copied or re-ingested
    /// object is charged its full stored size.
    ///
    /// # Trust
    ///
    /// By default the pull does not verify the checksum of an imported object.
    /// This makes the link path and the clone path possible.
    /// [`UNTRUSTED`](PullFlags::UNTRUSTED) fails the pull if an imported
    /// object does not hash to its name.
    ///
    /// The re-ingest path hashes each object as it streams, and compares the
    /// result with the name, whatever the flags say. So that path refuses a
    /// corrupt source with or without the flag. The other paths move bytes
    /// without a hash, and the flag adds one read of each object. An untrusted
    /// pull thus reads each object exactly once.
    ///
    /// # Detached metadata
    ///
    /// The pull stages the detached metadata of a commit in the same
    /// transaction. The transaction writes it at its commit, after the objects
    /// publish and before the ref that names the commit. A verifier that reads
    /// the signatures with the commit needs this order.
    ///
    /// The pull copies the `.commitmeta` of the first source that holds one,
    /// through [`detached_metadata_filter`](PullOptions::detached_metadata_filter).
    /// A zero-length `.commitmeta` in a source is the "no metadata" marker, and
    /// it replaces the copy of this repository. If no source holds a
    /// `.commitmeta`, the signature verification reads the copy of this
    /// repository.
    ///
    /// If the pull fails before the ref step of its commit, a
    /// [`LockTimeout`](Error::LockTimeout) at that step included, it leaves no
    /// `.commitmeta` of its own. A failure can occur in the ref step itself,
    /// at the install of a later `.commitmeta` or at a ref write. Then the
    /// `.commitmeta` files that the step installed before it stay.
    ///
    /// # Static deltas
    ///
    /// Under [`require_static_deltas`](PullOptions::require_static_deltas),
    /// the pull reads the summary of the source and the deltas that it
    /// advertises. It refuses a source with no summary, and a source outside
    /// `archive` mode. It finds each delta before it walks the commit chains
    /// and verifies their signatures.
    ///
    /// The pull applies each delta that it finds into the transaction one part
    /// at a time, and stages the commit from the superblock. The import then
    /// walks each commit and imports what no part produced.
    ///
    /// [`static_deltas`](PullOptions::static_deltas) replaces this search with
    /// a list. The pull then needs no summary for the deltas. For each target
    /// commit, it plans the chain with the fewest steps, by the rules of
    /// [`Repo::pull`] under `# Static deltas`. The pull reads the deltas of
    /// a list only from a source in `archive` mode. A
    /// [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull ignores the list.
    ///
    /// Before the transaction opens, the pull reads the superblock of each
    /// step and compares its SHA-256 with the digest in the list. It checks
    /// the signatures of the superblock, by the rules of [`PullVerify`], and
    /// its inline parts. For each commit of a chain, the target included, it
    /// also checks the signatures of the commit, and the ref binding of each
    /// requested ref that names the commit. The walk of the commit chains
    /// does not check that commit again. A local pull makes no timestamp
    /// check. So a target that the policy or its ref binding refuses costs the
    /// reads of the superblocks, and the pull applies no part. The pull
    /// reports this refusal before a defect that the walk of the commit chains
    /// finds. A target with no chain gets its checks in the walk of the commit
    /// chains, also before the transaction opens.
    ///
    /// The pull applies a chain one level at a time, in its one transaction.
    /// The parts, the loose objects, and the tree walk of one level end before
    /// the next level starts. The pull applies one step at a time, in each
    /// level and in the run of the targets. Before it applies a step, it reads
    /// the superblock of the step again from the source and compares it with
    /// the digest in the list again. Each intermediate commit ends complete,
    /// with no `.commitpartial` marker. The pull writes a ref for an
    /// intermediate commit only if a requested ref names it.
    ///
    /// If the source does not hold a superblock of a chain when the pull reads
    /// it before the transaction, the pull plans again without that delta. If
    /// no chain reaches a target, the pull imports its objects loose, or fails
    /// under `require_static_deltas`.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if [`subpaths`](PullOptions::subpaths) is not
    ///   empty, or if [`collection_id`](PullOptions::collection_id) is set and
    ///   [`no_ref_writes`](PullOptions::no_ref_writes) is not set or
    ///   [`refs`](PullOptions::refs) is empty. The pull makes these checks
    ///   before it reads `src`. Also if the pull requires static deltas or
    ///   applies a [`static_deltas`](PullOptions::static_deltas) list, and
    ///   `src` is not an `archive` repository.
    /// - [`Error::InvalidInput`] if [`depth`](PullOptions::depth) is below
    ///   `-1`, before the pull reads `src`.
    /// - [`Error::InvalidInput`] if
    ///   [`static_deltas`](PullOptions::static_deltas) holds two digests for
    ///   one delta, or is set together with
    ///   [`disable_static_deltas`](PullOptions::disable_static_deltas), before
    ///   the pull reads `src`.
    /// - [`Error::InvalidRefspec`] if the collection id or a name is invalid,
    ///   or if a name holds `:`, before the pull reads `src`.
    /// - [`Error::Pull`] if the options ask for a signature verification and
    ///   name no [`remote`](PullOptions::remote).
    /// - [`Error::Pull`] if the pull requires static deltas and `src` has no
    ///   summary, or no delta for a commit. With a `static_deltas` list, the
    ///   pull needs no summary, and fails if no chain of the list reaches a
    ///   target commit. A listed delta from scratch to the target that the
    ///   rule of [`require_static_deltas`](PullOptions::require_static_deltas)
    ///   leaves alone counts as found: the pull does not fail, and imports
    ///   that target loose.
    /// - [`Error::Pull`] if a superblock of the list produces another commit,
    ///   or from another commit, than its entry of the list.
    /// - [`Error::Pull`] if the ref binding of a commit does not name its ref.
    /// - [`Error::Pull`] if an object fails the
    ///   [`BAREUSERONLY_FILES`](PullFlags::BAREUSERONLY_FILES) check or the
    ///   check of a `bare-user-only` destination.
    /// - [`Error::Signature`] if a commit or the summary fails the signature
    ///   policy, each commit of a chain included. Also if the signatures of
    ///   a superblock fail the policy, or if the policy covers the summary and
    ///   `src` has no `summary` or no `summary.sig`.
    /// - [`Error::RefNotFound`] if `src` does not hold a requested ref or
    ///   collection ref.
    /// - [`Error::ObjectNotFound`] if neither this repository nor a source
    ///   holds an object that a pulled commit reaches. Also if a dirtree that
    ///   this repository holds is a symlink that points to no file.
    /// - [`Error::ChecksumMismatch`] if an imported object does not hash to its
    ///   name, under [`UNTRUSTED`](PullFlags::UNTRUSTED) or on the re-ingest
    ///   path. Also if a delta superblock does not match its advertised digest
    ///   or its digest in the list.
    /// - [`Error::InsufficientFreeSpace`] if an imported object needs more
    ///   space than the free-space budget of the transaction holds.
    /// - [`Error::LockTimeout`] if the wait for the repository lock or the
    ///   update lock passes `[core] lock-timeout-secs`.
    /// - [`Error::Core`] if a commit, a dirtree, or detached metadata does not
    ///   parse.
    /// - [`Error::InvalidFormat`] if the `summary` or `summary.sig` of `src` is
    ///   larger than 64 MiB or is not a regular file. Also if a static delta of
    ///   `src` is malformed, or if `src` does not hold a superblock of a chain
    ///   when the pull applies its step. Also if a filter gets detached
    ///   metadata that is not a dict of `{sv}` entries.
    /// - [`Error::Io`] for an I/O failure of the file system. Also for a held
    ///   dirtree that the pull cannot read, that is not a regular file, or that
    ///   is larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
    pub async fn pull_local(&self, src: &Repo, mut opts: PullOptions) -> Result<PullStats> {
        let started = Instant::now();
        // A local pull copies whole trees. The `ostree pull-local` command
        // takes no subpath either.
        if !opts.subpaths.is_empty() {
            return Err(Error::Unsupported("a local pull takes no subpath".into()));
        }
        check_depth(opts.depth)?;
        check_static_deltas(&opts)?;
        let collection_relpaths = check_local_collection(&opts)?;
        let edges = take_static_deltas(&mut opts).await?;
        // The pull builds the signature policy before it reads the source. So
        // a check that the options ask for with no remote to take keys from
        // fails here, before the walk of a chain.
        let trust = crate::verify::PullTrust::resolve(
            self,
            opts.remote.as_deref(),
            &opts.verify,
            crate::verify::Defaults::Off,
        )
        .await?;
        let verification = verify::Verification::from_trust(trust);
        // A pull that requires static deltas reads the source as a fetch
        // reads a remote: the summary, then the deltas that it advertises. A
        // pull with a list of static deltas reads the deltas of the list and
        // needs no summary. The counts of both pulls are those of a fetch.
        // These steps come before the walk of the commit chains, in the order
        // of the refusals of the `ostree` command:
        //
        // - the summary verification.
        // - the refusal of a source with no summary or outside archive mode.
        // - the search for each delta.
        //
        // The pull reads
        // the summary and its signature under the size cap of a summary. It
        // refuses a file there that is not a regular file.
        let fetching = opts.require_static_deltas && !opts.disable_static_deltas;
        // A commit-only pull ignores the list.
        let list_applies = edges.is_some() && !opts.flags.contains(PullFlags::COMMIT_ONLY);
        let reads_deltas = fetching || list_applies;
        let needs_summary = fetching && edges.is_none();
        let summary = if verification.checks_summary() || needs_summary {
            delta::read_local(
                src,
                crate::summary::SUMMARY_FILE,
                crate::summary::SUMMARY_READ_CAP,
            )
            .await?
        } else {
            None
        };
        if verification.checks_summary() {
            let signature = delta::read_local(
                src,
                crate::summary::SUMMARY_SIG_FILE,
                crate::summary::SUMMARY_READ_CAP,
            )
            .await?;
            verification
                .check_summary(summary.as_deref(), signature)
                .await?;
        }
        if needs_summary && summary.is_none() {
            return Err(delta::no_summary_error());
        }
        if reads_deltas && !src.mode().is_archive() {
            return Err(Error::Unsupported(format!(
                "can't pull from a repository in mode {}: a local pull that reads static \
                 deltas reads an archive repository",
                src.mode().as_mode_str()
            )));
        }
        // The pull drops the bytes here: discovery reads the parsed summary
        // alone. A summary can be as large as `SUMMARY_READ_CAP`, so the parse
        // runs on the blocking pool, and the bytes drop there.
        let summary = match summary {
            Some(bytes) if needs_summary => {
                Some(ostrya_rt::unblock(move || crate::summary::Summary::parse(&bytes)).await?)
            }
            _ => None,
        };

        let targets = resolve_targets(src, &opts, collection_relpaths).await?;
        let flags = opts.flags;
        let verify_bindings = !flags.contains(PullFlags::DISABLE_VERIFY_BINDINGS);

        // The pull finds the deltas before the transaction opens, so a refusal
        // writes no object, no ref, and no marker. With a list, discovery also
        // checks each commit of a chain: the signatures, and the ref binding of
        // each requested ref that names it.
        let counters = PullCounters::new(None);
        let deltas = if summary.is_some() || edges.is_some() {
            delta::discover(
                self,
                &delta::DeltaSource::Local(src),
                summary.as_ref(),
                &targets,
                &opts,
                opts.remote.as_deref(),
                edges,
                // A local pull makes no timestamp check.
                TimestampBase::Off,
                &verification,
                &counters,
            )
            .await?
        } else {
            delta::DeltaPlan::default()
        };
        drop(summary);
        let mut deltas = deltas;
        // The intermediate commits of the chains. The run of the levels
        // imports each of them, and the commit loop skips them.
        let done: HashSet<Checksum> = deltas.levels().iter().flatten().copied().collect();

        let sources: Vec<&Repo> = std::iter::once(src)
            .chain(opts.localcache_repos.iter())
            .collect();

        // The pull checks each commit of the chain before the transaction
        // opens, so a source with signatures that fail the policy imports
        // nothing. The walk of the chain checks each commit over the bytes that
        // it read to find the parent. A check binds to the source objects as
        // they are while it runs. The walk also keeps the root dirtree and
        // dirmeta of each commit, so the plan of the tree reads no source
        // commit again.
        //
        // The import loop reads the `.commitmeta` a second time, where it
        // copies the bytes. If the source changes between the check and the
        // import, the pull imports the source as it is at the import. A
        // concurrent sign of the source commit is the writer that replaces a
        // `.commitmeta` in place. A carry of the verified metadata to the
        // import needs one entry for each commit of the chain. A `depth=-1`
        // pull puts no bound on that count, so the pull reads the metadata
        // twice.
        //
        // Discovery checked each commit of a chain, so the walk does not check
        // it again.
        let mut check = verification.checks_commits().then(|| ChainCheck {
            repo: self,
            sources: &sources,
            verification: &verification,
            plan: &deltas,
            failed: None,
        });

        // The commit chains, in the order of the refs, each commit once.
        let mut commits: Vec<ChainCommit> = Vec::new();
        let mut seen: HashMap<Checksum, i32> = HashMap::new();
        for (ref_name, tip) in &targets {
            let (bytes, commit) = load_commit(src, tip).await?;
            // Discovery made the binding check of each ref that names a
            // commit of a chain.
            if verify_bindings && !deltas.checked(tip) {
                check_ref_binding(tip, &commit, ref_name)?;
            }
            collect_chain(
                src,
                *tip,
                (bytes, commit),
                opts.depth,
                &mut commits,
                &mut seen,
                check.as_mut(),
            )
            .await?;
        }
        // The pull reports a defect that the walk finds before a failed check.
        if let Some(ChainCheck {
            failed: Some(err), ..
        }) = check
        {
            return Err(err);
        }

        let mut txn = self.transaction().await?;
        apply_durability(&mut txn, &opts);

        // The markers that the pull writes. The list is outside the span that
        // writes them, so a failure in that span clears the markers that it
        // left.
        let mut marked: Vec<Checksum> = Vec::new();
        let published = async {
            // Mark each commit partial before the import of its objects. Skip a
            // commit that this repository already holds complete: an unrelated
            // failure must not demote a complete commit. The plan of the tree
            // reads the same answer and plans nothing for a complete commit.
            // The intermediate commits of the chains come first, with one
            // batched check.
            let level_commits: Vec<Checksum> = deltas.levels().iter().flatten().copied().collect();
            let mut held_levels: HashSet<Checksum> = HashSet::new();
            for (commit, held) in chain::check_complete(self, &level_commits).await? {
                if held {
                    held_levels.insert(commit);
                } else {
                    self.write_partial_marker(&commit).await?;
                    marked.push(commit);
                }
            }
            for commit in &mut commits {
                if done.contains(&commit.checksum) {
                    continue;
                }
                commit.held = delta::complete_here(self, &commit.checksum).await?;
                if !commit.held {
                    self.write_partial_marker(&commit.checksum).await?;
                    marked.push(commit.checksum);
                }
            }

            let checks = ModeChecks::new(flags, self.mode());
            let delta_source = delta::DeltaSource::Local(src);
            // A fetch counts each object that the pull reads from the source.
            let count = reads_deltas.then_some(&counters);
            let mut plan = PlanState::default();
            // The read buffer of an untrusted verification. The pull uses it
            // again for each object and sizes it on its first use, so a pull
            // that verifies nothing allocates nothing.
            let mut verify_buf: Vec<u8> = Vec::new();

            // A part of a later step of a chain can patch against an object
            // that an earlier step wrote. So the parts, the loose objects, and
            // the walk of each level of intermediate commits end before the
            // next level starts. The pull parses the job of one step at a
            // time, and drops it after its parts.
            for level in deltas.levels() {
                let mut made: Vec<ChainCommit> = Vec::with_capacity(level.len());
                for commit in level {
                    let job = deltas
                        .parse_record(self, &delta_source, commit)
                        .await?
                        .ok_or_else(|| {
                            Error::InvalidFormat(format!(
                                "static delta to {commit}: the plan holds no step for the commit"
                            ))
                        })?;
                    let held = held_levels.contains(commit);
                    if !held {
                        for index in 0..job.parts() {
                            delta::apply_job_part(
                                &txn,
                                &delta_source,
                                &job,
                                index,
                                checks,
                                &counters,
                            )
                            .await?;
                        }
                        txn.write_metadata(ObjectType::Commit, Some(commit), &job.commit_bytes)
                            .await?;
                    }
                    // A commit object can be as large as `MAX_METADATA_SIZE`,
                    // so the parse runs on the blocking pool.
                    let bytes = Arc::clone(&job.commit_bytes);
                    let parsed = ostrya_rt::unblock(move || Commit::parse(&bytes)).await?;
                    made.push(ChainCommit {
                        checksum: *commit,
                        root_dirtree: parsed.root_dirtree,
                        root_dirmeta: parsed.root_dirmeta,
                        held,
                    });
                }
                // Discovery counted the `.commitmeta` of each intermediate
                // commit.
                for chain_commit in &made {
                    self.import_planned(
                        &txn,
                        &sources,
                        chain_commit,
                        flags,
                        &mut plan,
                        &mut verify_buf,
                        count,
                    )
                    .await?;
                    self.import_detached_metadata(
                        &txn,
                        &sources,
                        &chain_commit.checksum,
                        &opts.detached_metadata_filter,
                        None,
                    )
                    .await?;
                }
            }

            // Apply each delta to a target whole, one part at a time, and then
            // stage its commit from the superblock. The import then walks each
            // commit and imports what no part produced. The pull takes or
            // parses the job of one target at a time, and drops it after its
            // parts. A target that a level made has its commit already.
            for (_, tip) in &targets {
                if done.contains(tip) || txn.is_staged(tip, ObjectType::Commit) {
                    continue;
                }
                let job = match deltas.jobs.remove(tip) {
                    Some(job) => job,
                    None => match deltas.parse_record(self, &delta_source, tip).await? {
                        Some(job) => job,
                        None => continue,
                    },
                };
                for index in 0..job.parts() {
                    delta::apply_job_part(&txn, &delta_source, &job, index, checks, &counters)
                        .await?;
                }
                txn.write_metadata(ObjectType::Commit, Some(tip), &job.commit_bytes)
                    .await?;
            }
            // The pull is done with the deltas, the inline part bodies of the
            // jobs that no target took included.
            drop(std::mem::take(&mut deltas));

            for chain_commit in &commits {
                let commit = &chain_commit.checksum;
                if done.contains(commit) {
                    continue;
                }
                self.import_planned(
                    &txn,
                    &sources,
                    chain_commit,
                    flags,
                    &mut plan,
                    &mut verify_buf,
                    count,
                )
                .await?;
                self.import_detached_metadata(
                    &txn,
                    &sources,
                    commit,
                    &opts.detached_metadata_filter,
                    count,
                )
                .await?;
            }
            if !opts.no_ref_writes {
                for (ref_name, tip) in &targets {
                    txn.set_ref(&refspec(opts.remote.as_deref(), ref_name), Some(tip));
                }
            }
            txn.commit().await
        }
        .await;
        let stats = match published {
            Ok(stats) => stats,
            Err(e) => {
                self.clear_markers_for_absent_commits(&marked).await;
                return Err(e);
            }
        };

        // The content that a marker guarded is published. A commit-only pull
        // keeps its markers, because it did not walk the trees.
        if !flags.contains(PullFlags::COMMIT_ONLY) {
            for commit in &marked {
                self.remove_partial_marker(commit).await?;
            }
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

    /// Plans the objects of `commit` with [`plan_commit`] and imports each
    /// one with [`import_object`](Repo::import_object).
    ///
    /// If `count` is set, the call counts each object that it read from the
    /// source, the first of `sources`, as a fetch counts it. An object from a
    /// localcache repository does not count. An object that a delta part
    /// staged is not planned, so it does not count either.
    #[allow(clippy::too_many_arguments)]
    async fn import_planned(
        &self,
        txn: &Transaction,
        sources: &[&Repo],
        commit: &ChainCommit,
        flags: PullFlags,
        plan: &mut PlanState,
        verify_buf: &mut Vec<u8>,
        count: Option<&PullCounters>,
    ) -> Result<()> {
        for name in plan_commit(txn, sources, commit, flags, plan).await? {
            let imported = self
                .import_object(txn, sources, name, flags, verify_buf)
                .await?;
            if let Some(counters) = count
                && let Some((0, size)) = imported
            {
                count_fetched(counters, name.ty, size);
            }
        }
        Ok(())
    }

    /// Imports one object from the first source repository that holds it.
    ///
    /// Returns the position of that source in `sources` and the stored size of
    /// the object in that source. Returns `None` for an object that this
    /// repository already holds or has staged.
    ///
    /// `verify_buf` is the buffer of an untrusted verification for the payload
    /// of the object. The import loop keeps it, so the pull holds one buffer.
    async fn import_object(
        &self,
        txn: &Transaction,
        sources: &[&Repo],
        name: ObjectName,
        flags: PullFlags,
        verify_buf: &mut Vec<u8>,
    ) -> Result<Option<(usize, u64)>> {
        if txn.is_staged(&name.checksum, name.ty)
            || self.has_object(name.ty, &name.checksum).await?
        {
            return Ok(None);
        }
        for (position, src) in sources.iter().enumerate() {
            if let Some(size) = source_size(src, name.ty, &name.checksum).await? {
                self.import_from(txn, src, name, flags, verify_buf).await?;
                return Ok(Some((position, size)));
            }
        }
        Err(Error::ObjectNotFound {
            checksum: name.checksum,
            ty: name.ty,
        })
    }

    /// Imports one object that is present in `src`.
    async fn import_from(
        &self,
        txn: &Transaction,
        src: &Repo,
        name: ObjectName,
        flags: PullFlags,
        verify_buf: &mut Vec<u8>,
    ) -> Result<()> {
        if name.ty != ObjectType::File {
            // A metadata object is a plain file of its serialized bytes in each
            // mode, so the two repositories always store it in the same form.
            if flags.contains(PullFlags::UNTRUSTED) {
                verify_metadata(src, name).await?;
            }
            link_import(txn, src, name, flags).await?;
            return Ok(());
        }

        let same_mode = src.mode() == self.mode();
        let checks = ModeChecks::new(flags, self.mode());
        let untrusted = flags.contains(PullFlags::UNTRUSTED);

        // The mode checks read the logical form of the object, before each
        // import path. An untrusted verification reads the same form, and it
        // waits for the import path. The link and the clone move bytes without
        // a hash, so the pull verifies them here. A re-ingest hashes the object
        // as it writes it and compares the result with its name. A verification
        // before the re-ingest reads the payload twice, so the pull makes none.
        let loaded = if checks.any() || untrusted {
            let file = src.load_file(&name.checksum).await?;
            if checks.any() {
                checks.check(&name.checksum, &file.meta())?;
            }
            Some(file)
        } else {
            None
        };

        // Two repositories of one mode store a content object in the same form,
        // inode included, so the import shares the source inode.
        if same_mode && link_import(txn, src, name, flags).await? {
            if untrusted && let Some(file) = &loaded {
                verify_content(&name.checksum, file, verify_buf).await?;
            }
            return Ok(());
        }

        // The logical form of the object. The clone applies the inode policy
        // of the destination from its header, and a re-ingest streams its
        // payload. A refused link also gets here, at the cost of one
        // metadata read.
        let file = match loaded {
            Some(file) => file,
            None => src.load_file(&name.checksum).await?,
        };
        let meta = file.meta();
        match &file.kind {
            FileKind::Symlink { target } => {
                if symlink_shared(src.mode(), self.mode())
                    && link_import(txn, src, name, flags).await?
                {
                    if untrusted {
                        verify_content(&name.checksum, &file, verify_buf).await?;
                    }
                    return Ok(());
                }
                // The identity of a symlink is its header alone. `write_symlink`
                // hashes it and compares the result with the name that it gets,
                // so this path verifies the object whatever the flags say.
                txn.write_symlink(target, &meta, Some(&name.checksum))
                    .await?;
            }
            FileKind::Regular { size } => {
                if payload_shared(src.mode(), self.mode()) {
                    if untrusted {
                        verify_content(&name.checksum, &file, verify_buf).await?;
                    }
                    txn.stage_clone_content(
                        src.objects_fd(),
                        name.checksum,
                        src.mode(),
                        meta.regular_header(),
                        *size,
                    )
                    .await?;
                    return Ok(());
                }
                let reader = file.reader().await?;
                txn.write_content(Some(&name.checksum), &meta, reader)
                    .await?;
            }
        }
        Ok(())
    }

    /// Stages the detached metadata of a commit in `txn`, from the first
    /// source that holds it, through `filter`.
    ///
    /// If the filter keeps each property, the stored bytes are the bytes of the
    /// source unchanged. They get to `objects/` when `txn` commits. A source
    /// with no `.commitmeta`, and a filter that allows no property, each leave
    /// the copy of the destination unchanged.
    ///
    /// If `count` is set, the call counts the `.commitmeta` as a fetch counts
    /// it when the bytes come from the source, the first of `sources`. The
    /// count is the length of the bytes that the call read, before the
    /// filter. A filter that fails counts the bytes first.
    ///
    /// The read and the filter run in one call on the blocking pool.
    async fn import_detached_metadata(
        &self,
        txn: &Transaction,
        sources: &[&Repo],
        commit: &Checksum,
        filter: &DetachedMetadataFilter,
        count: Option<&PullCounters>,
    ) -> Result<()> {
        let owned: Vec<Repo> = sources.iter().map(|src| (*src).clone()).collect();
        let filter = filter.clone();
        let key = *commit;
        let read = ostrya_rt::unblock(move || -> Result<_> {
            let Some((at, bytes)) = detached_bytes_from_blocking(&owned, &key)? else {
                return Ok(None);
            };
            let len = bytes.len() as u64;
            Ok(Some((at, len, filter.apply(&key, bytes))))
        })
        .await?;
        let Some((at, len, kept)) = read else {
            return Ok(());
        };
        if at == 0
            && let Some(counters) = count
        {
            count_fetched(counters, ObjectType::CommitMeta, len);
        }
        if let Some(bytes) = kept? {
            txn.stage_commit_detached_bytes(commit, bytes).await?;
        }
        Ok(())
    }

    /// Writes the zero-length `state/<commit>.commitpartial` marker of a
    /// commit, which a pull keeps while the objects of the commit are in
    /// flight.
    ///
    /// The call does not write over a marker that is present, so the one-byte
    /// state that fsck writes stays. The `ostree` command does the same: its
    /// `pull-local` opens a marker that is present read-only, and creates a
    /// marker with `O_EXCL`.
    ///
    /// The module [`pull`](self) states the durability of the markers.
    ///
    /// In a `bare-user-shared` repository, a marker that this call creates gets
    /// [`perm::SHARED_FILE_MODE`]. A marker that is present keeps its mode.
    async fn write_partial_marker(&self, commit: &Checksum) -> Result<()> {
        let path = partial_path(commit);
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            match rustix::fs::openat(
                repo.repo_fd(),
                path.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                Mode::from_raw_mode(PARTIAL_MARKER_MODE),
            ) {
                Ok(fd) => {
                    perm::force_created_mode(&fd, repo.mode(), perm::SHARED_FILE_MODE)?;
                    Ok(())
                }
                Err(rustix::io::Errno::EXIST) => Ok(()),
                Err(e) => Err(Error::from(e)),
            }
        })
        .await
    }

    /// Removes the `.commitpartial` marker of a commit.
    ///
    /// An absent marker is a success. This is the last operation of a pull,
    /// and no barrier follows it, as in the `ostree` command. If a crash occurs
    /// before the unlink gets to the disk, the marker stays on a complete
    /// commit. The next pull of that commit, or a prune of it, clears it.
    async fn remove_partial_marker(&self, commit: &Checksum) -> Result<()> {
        let path = partial_path(commit);
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            match rustix::fs::unlinkat(repo.repo_fd(), path.as_str(), AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
                Err(e) => Err(Error::from(e)),
            }
        })
        .await
    }

    /// Removes the `.commitpartial` marker of each of `commits` in one trip to
    /// the blocking pool, as [`remove_partial_marker`](Repo::remove_partial_marker)
    /// removes one.
    ///
    /// Returns each commit whose marker stays, with the error, in the order of
    /// `commits`.
    #[cfg(feature = "receive")]
    pub(crate) async fn remove_partial_markers(
        &self,
        commits: Vec<Checksum>,
    ) -> Vec<(Checksum, Error)> {
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            commits
                .into_iter()
                .filter_map(|commit| {
                    let path = partial_path(&commit);
                    match rustix::fs::unlinkat(repo.repo_fd(), path.as_str(), AtFlags::empty()) {
                        Ok(()) | Err(rustix::io::Errno::NOENT) => None,
                        Err(e) => Some((commit, Error::from(e))),
                    }
                })
                .collect()
        })
        .await
    }

    /// Removes the markers that a failed pull wrote for commits that this
    /// repository does not hold.
    ///
    /// `marked` is the list of markers that the pull wrote.
    /// The module [`pull`](self) states why such a marker guards nothing. A
    /// commit that this repository holds keeps its marker. The pull found that
    /// commit partial and kept the marker, so the state byte that fsck writes
    /// is in it.
    ///
    /// This function runs on the error path. It leaves a marker that it cannot
    /// remove, so the pull reports the error that ended it.
    async fn clear_markers_for_absent_commits(&self, marked: &[Checksum]) {
        for commit in marked {
            if matches!(self.has_object(ObjectType::Commit, commit).await, Ok(false)) {
                let _ = self.remove_partial_marker(commit).await;
            }
        }
    }
}

/// Returns the `state/` path of the partial marker of a commit, relative to
/// the repository directory.
pub(crate) fn partial_path(commit: &Checksum) -> String {
    format!("state/{}.commitpartial", commit.to_hex())
}

/// Returns the refspec of a pulled ref: `remote:ref` if a remote name is
/// given, and the bare ref name otherwise.
fn refspec(remote: Option<&str>, ref_name: &str) -> String {
    match remote {
        Some(remote) => format!("{remote}:{ref_name}"),
        None => ref_name.to_owned(),
    }
}

/// Resolves the refs to pull against the source: the requested names, or
/// each ref under `refs/heads` of the source if no name is given.
///
/// `collection_relpaths` holds the paths that [`check_local_collection`]
/// gives. With it, each name is the collection ref at its path, and the target
/// keeps the name alone. A path that names a directory, or that goes through a
/// file, holds no ref and fails as an absent ref does.
async fn resolve_targets(
    src: &Repo,
    opts: &PullOptions,
    collection_relpaths: Option<Vec<String>>,
) -> Result<Vec<(String, Checksum)>> {
    if opts.refs.is_empty() {
        return src.list_refs(None).await;
    }
    let mut out = Vec::with_capacity(opts.refs.len());
    match collection_relpaths {
        Some(relpaths) => {
            for (name, relpath) in opts.refs.iter().zip(relpaths) {
                let checksum = match src.resolve_relpath_tip(relpath.clone()).await {
                    Err(Error::Io(e))
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::IsADirectory | std::io::ErrorKind::NotADirectory
                        ) =>
                    {
                        None
                    }
                    other => other?,
                };
                out.push((name.clone(), checksum.ok_or(Error::RefNotFound(relpath))?));
            }
        }
        None => {
            for name in &opts.refs {
                let checksum = src
                    .resolve_rev(name, false)
                    .await?
                    .ok_or_else(|| Error::RefNotFound(name.clone()))?;
                out.push((name.clone(), checksum));
            }
        }
    }
    Ok(out)
}

/// Follows the parents of a commit in the source, and appends each commit
/// that is not collected yet.
///
/// `depth` is the number of parents to follow, `-1` for all of them. A parent
/// that the source does not hold ends the chain.
///
/// `seen` records, for each commit, the number of parents left to follow when
/// the walk got to it. If a chain gets to a commit with more parents left than
/// an earlier chain had, the walk continues from that commit. So the commits
/// of a pull do not depend on the order of the refs. The walk appends a commit
/// the first time that it gets to it, and not again.
///
/// `tip_commit` holds the bytes of the tip and the commit parsed from them. If
/// `check` is present, it runs on each commit when the walk appends it, over
/// the bytes that the walk read. The walk appends each commit with the root of
/// its tree, so the plan of the tree does not read the commit object again.
async fn collect_chain(
    src: &Repo,
    tip: Checksum,
    tip_commit: (Vec<u8>, Commit),
    depth: i32,
    out: &mut Vec<ChainCommit>,
    seen: &mut HashMap<Checksum, i32>,
    mut check: Option<&mut ChainCheck<'_>>,
) -> Result<()> {
    let mut current = Some((tip, tip_commit));
    let mut remaining = depth;
    while let Some((checksum, (bytes, commit))) = current {
        if let Some(&prev) = seen.get(&checksum)
            && reaches_at_least(prev, remaining)
        {
            return Ok(());
        }
        if seen.insert(checksum, remaining).is_none() {
            out.push(ChainCommit {
                checksum,
                root_dirtree: commit.root_dirtree,
                root_dirmeta: commit.root_dirmeta,
                held: false,
            });
            if let Some(check) = check.as_deref_mut() {
                check.check(&checksum, &bytes).await;
            }
        }
        drop(bytes);
        if remaining == 0 {
            return Ok(());
        }
        let Some(parent) = commit.parent else {
            return Ok(());
        };
        current = try_load_commit(src, &parent)
            .await?
            .map(|parent_commit| (parent, parent_commit));
        if remaining > 0 {
            remaining -= 1;
        }
    }
    Ok(())
}

/// A commit that the walk of the chain collected, with the root of its tree
/// from the commit object that the walk read.
struct ChainCommit {
    checksum: Checksum,
    root_dirtree: Checksum,
    root_dirmeta: Checksum,
    /// The completeness state: `true` if this repository holds the commit
    /// object and no `.commitpartial` marker for it.
    ///
    /// The pull sets it when the transaction is open, where it writes the
    /// markers.
    held: bool,
}

/// The signature verification that a local pull runs on each commit of the
/// chain during the walk of the chain.
struct ChainCheck<'a> {
    /// The repository that the pull writes into. If no source holds a
    /// `.commitmeta`, the check reads the detached metadata of this repository.
    repo: &'a Repo,
    /// The source and the localcache repositories, in the order of the reads.
    sources: &'a [&'a Repo],
    verification: &'a verify::Verification,
    /// The deltas that discovery found. The check skips each commit whose
    /// signatures discovery checked.
    plan: &'a delta::DeltaPlan,
    /// The first check that failed.
    ///
    /// The commits after it get no check, and the walk continues, so the pull
    /// reports a defect that the walk finds before this failure.
    failed: Option<Error>,
}

impl ChainCheck<'_> {
    /// Checks `commit`, whose object holds `bytes`, unless a check failed
    /// before, and records a failure.
    async fn check(&mut self, commit: &Checksum, bytes: &[u8]) {
        if self.failed.is_none()
            && let Err(err) = self.check_one(commit, bytes).await
        {
            self.failed = Some(err);
        }
    }

    /// Checks `commit`, whose object holds `bytes`, against the commit policy.
    ///
    /// A commit that discovery checked passes with no read.
    async fn check_one(&self, commit: &Checksum, bytes: &[u8]) -> Result<()> {
        if self.plan.checked(commit) {
            return Ok(());
        }
        // The verification reads the detached metadata as the source holds
        // it. That is the `.commitmeta` of the first source that holds one,
        // else that of this repository. A filter makes the stored metadata
        // smaller, so a later verification of the stored commit reads what the
        // filter kept.
        let sources: Vec<Repo> = self.sources.iter().map(|src| (*src).clone()).collect();
        check_local_commit_signatures(self.repo, self.verification, sources, commit, bytes)
            .await
            .map(drop)
    }
}

/// Checks the signatures of `commit`, whose object holds `bytes`, against the
/// commit policy of `verification`, and gives back `detached`.
///
/// `detached` is the `.commitmeta` that the pull puts in place. If it is
/// `None`, the check reads the detached metadata of `repo`. A policy that does
/// not apply to commits passes each commit and reads nothing.
///
/// The parse of the detached metadata runs on the blocking pool, because the
/// bytes can be as large as
/// [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE).
async fn check_commit_signatures(
    repo: &Repo,
    verification: &verify::Verification,
    commit: &Checksum,
    bytes: &[u8],
    detached: Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>> {
    if !verification.checks_commits() {
        return Ok(detached);
    }
    let (dict, detached) = match detached {
        Some(detached) => {
            let (dict, detached) = parse_detached(detached).await;
            (dict?, Some(detached))
        }
        None => match repo.load_object_bytes(ObjectType::CommitMeta, commit).await {
            Ok(held) => (parse_detached(held).await.0?, None),
            Err(Error::ObjectNotFound { .. }) => (None, None),
            Err(e) => return Err(e),
        },
    };
    verification
        .check_commit(commit, bytes, dict.as_ref())
        .await?;
    Ok(detached)
}

/// Checks the signatures of `commit`, whose object holds `bytes`, against the
/// commit policy of `verification`, for a pull from local sources.
///
/// The check reads the `.commitmeta` of the first repository of `sources` that
/// holds one, as [`detached_bytes_from_blocking`] does. If no source holds
/// one, it reads the `.commitmeta` of `repo`, this repository. The reads and
/// the parse run in one call on the blocking pool, because the bytes can be as
/// large as [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE). The errors are
/// the errors of [`check_commit_signatures`] over the bytes of the sources, in
/// the same order.
///
/// Returns the position in `sources` and the length of the `.commitmeta` that
/// the check read from a source, or `None` if no source holds one. The caller
/// makes sure that the policy checks commits.
async fn check_local_commit_signatures(
    repo: &Repo,
    verification: &verify::Verification,
    sources: Vec<Repo>,
    commit: &Checksum,
    bytes: &[u8],
) -> Result<Option<(usize, u64)>> {
    let repo = repo.clone();
    let key = *commit;
    let (read, dict) = ostrya_rt::unblock(move || -> Result<_> {
        if let Some((at, held)) = detached_bytes_from_blocking(&sources, &key)? {
            let dict = crate::summary::parse_signature_dict(&held)?;
            return Ok((Some((at, held.len() as u64)), dict));
        }
        match repo.load_object_bytes_blocking(ObjectType::CommitMeta, &key) {
            Ok(held) => Ok((None, crate::summary::parse_signature_dict(&held)?)),
            Err(Error::ObjectNotFound { .. }) => Ok((None, None)),
            Err(e) => Err(e),
        }
    })
    .await?;
    verification
        .check_commit(commit, bytes, dict.as_ref())
        .await?;
    Ok(read)
}

/// The `.commitmeta` that the pull puts in place for a commit, after the
/// signature check of the commit.
enum CheckedMeta {
    /// The bytes as the source holds them. The filter did not run.
    Source(Vec<u8>),
    /// The result of the filter: the bytes to stage, or `None` if the pull
    /// stages nothing.
    Filtered(Option<Vec<u8>>),
}

impl CheckedMeta {
    /// Gives the bytes that the pull stages, or `None` if it stages nothing.
    ///
    /// [`CheckedMeta::Source`] goes through
    /// [`apply_on_pool`](DetachedMetadataFilter::apply_on_pool).
    async fn filtered(
        self,
        filter: &DetachedMetadataFilter,
        commit: &Checksum,
    ) -> Result<Option<Vec<u8>>> {
        match self {
            CheckedMeta::Source(bytes) => filter.apply_on_pool(commit, bytes).await,
            CheckedMeta::Filtered(kept) => Ok(kept),
        }
    }
}

/// Checks the signatures of `commit` as [`check_commit_signatures`] does, and
/// runs `filter` over `detached` if the check parses it.
///
/// If the policy checks commits, `filter` is set, and `detached` is `Some`,
/// the filter reads the dict that the check parsed. The filter runs on the
/// blocking pool after the check, so the call parses `detached` one time and
/// gives [`CheckedMeta::Filtered`]. Else the call gives the bytes that
/// [`check_commit_signatures`] gives back, as [`CheckedMeta::Source`].
async fn check_commit_signatures_filtered(
    repo: &Repo,
    verification: &verify::Verification,
    filter: &DetachedMetadataFilter,
    commit: &Checksum,
    bytes: &[u8],
    detached: Option<Vec<u8>>,
) -> Result<Option<CheckedMeta>> {
    match detached {
        Some(detached) if verification.checks_commits() && filter.0.is_some() => {
            let (dict, detached) = parse_detached(detached).await;
            let dict = dict?;
            verification
                .check_commit(commit, bytes, dict.as_ref())
                .await?;
            // The zero-length marker parses to `None`, and `apply` gives it
            // back unchanged.
            let Some(dict) = dict else {
                return Ok(Some(CheckedMeta::Filtered(Some(detached))));
            };
            let filter = filter.clone();
            let commit = *commit;
            let kept =
                ostrya_rt::unblock(move || filter.apply_parsed(&commit, detached, dict)).await?;
            Ok(Some(CheckedMeta::Filtered(kept)))
        }
        detached => Ok(
            check_commit_signatures(repo, verification, commit, bytes, detached)
                .await?
                .map(CheckedMeta::Source),
        ),
    }
}

/// Parses the `.commitmeta` bytes `bytes` on the blocking pool, and gives
/// back the bytes with the result.
///
/// A zero-length file reads as `None`, as
/// [`Repo::read_commit_detached_metadata`] states.
async fn parse_detached(bytes: Vec<u8>) -> (Result<Option<Value>>, Vec<u8>) {
    ostrya_rt::unblock(move || {
        let dict = crate::summary::parse_signature_dict(&bytes);
        (dict, bytes)
    })
    .await
}

/// The object names that the plans of a pull met so far, planned or found
/// present.
///
/// The commit loop keeps it, so the walk reads the trees of the chain as one
/// tree.
#[derive(Default)]
struct PlanState {
    seen: HashSet<ObjectName>,
}

impl PlanState {
    /// Adds a name to `out` unless a walk met it before.
    ///
    /// The held state of the name starts as `false`, and [`plan_absent`] sets
    /// it.
    fn meet(&mut self, name: ObjectName, out: &mut Vec<(ObjectName, bool)>) {
        if self.seen.insert(name) {
            out.push((name, false));
        }
    }
}

/// Returns the objects of one commit, in import order.
///
/// The metadata and the content of the tree come first, and the commit object
/// last. So a partly imported transaction never holds a commit before the
/// objects that it refers to. Under [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY)
/// the walk skips the tree, and the commit object is the whole plan. A commit
/// that this repository holds complete gives no object: the objects that it
/// refers to are present, and the walk reads nothing.
///
/// The root of the tree comes from the commit object that the walk of the
/// chain read. [`plan_absent`] finds the objects that this repository lacks:
/// first the root dirtree and dirmeta, then the children of each dirtree. It
/// makes one blocking call for each dirtree.
/// [`pull_local`](Repo::pull_local) states the rules of the walk. A dirtree
/// that `txn` staged from a delta part counts as held. A dirtree that neither
/// this repository nor a source holds gives its own name and nothing below it.
///
/// `state` holds what the commits before this one met. So the walk descends
/// into a dirtree that the chain shares once, and checks each object once.
async fn plan_commit(
    txn: &Transaction,
    sources: &[&Repo],
    commit: &ChainCommit,
    flags: PullFlags,
    state: &mut PlanState,
) -> Result<Vec<ObjectName>> {
    if commit.held {
        return Ok(Vec::new());
    }
    let commit_name = ObjectName::new(commit.checksum, ObjectType::Commit);
    if flags.contains(PullFlags::COMMIT_ONLY) {
        return Ok(vec![commit_name]);
    }
    // The own tree of this commit. The walk of the chain supplies the parents.
    let mut names: Vec<ObjectName> = Vec::new();
    // The dirtrees left to read, each with its held state in this repository.
    let mut stack: Vec<(Checksum, bool)> = Vec::new();
    let mut met: Vec<(ObjectName, bool)> = Vec::new();
    state.meet(
        ObjectName::new(commit.root_dirmeta, ObjectType::DirMeta),
        &mut met,
    );
    state.meet(
        ObjectName::new(commit.root_dirtree, ObjectType::DirTree),
        &mut met,
    );
    plan_absent(txn, met, &mut names, &mut stack).await?;
    while let Some((checksum, here)) = stack.pop() {
        let dirtree = if here {
            txn.load_dirtree_staged_first(&checksum).await?
        } else {
            match load_dirtree_from(sources, &checksum).await? {
                Some(dirtree) => dirtree,
                None => continue,
            }
        };
        let mut met: Vec<(ObjectName, bool)> = Vec::new();
        for (_, file) in dirtree.files {
            state.meet(ObjectName::new(file, ObjectType::File), &mut met);
        }
        for (_, subtree, submeta) in dirtree.dirs {
            state.meet(ObjectName::new(submeta, ObjectType::DirMeta), &mut met);
            state.meet(ObjectName::new(subtree, ObjectType::DirTree), &mut met);
        }
        plan_absent(txn, met, &mut names, &mut stack).await?;
    }
    // `Checksum` sorts by its raw bytes, which gives the ASCII order of the hex
    // names, so the key needs no formatting.
    names.sort_by_key(|name| (name.ty.as_u32(), name.checksum));
    names.push(commit_name);
    Ok(names)
}

/// Adds each name of `met` that this repository lacks to `names`, and pushes
/// each dirtree of `met` on `stack` with its held state.
///
/// A name that `txn` staged is held. Each other name is held if
/// [`Repo::has_object`] finds it: a `stat` that does not follow a symlink, the
/// same check as the import. One blocking call checks the names that `txn`
/// did not stage. If `met` holds no such name, the function makes no call.
async fn plan_absent(
    txn: &Transaction,
    mut met: Vec<(ObjectName, bool)>,
    names: &mut Vec<ObjectName>,
    stack: &mut Vec<(Checksum, bool)>,
) -> Result<()> {
    let mut unstaged = false;
    for (name, here) in &mut met {
        *here = txn.is_staged(&name.checksum, name.ty);
        unstaged |= !*here;
    }
    if unstaged {
        let repo = txn.repo().clone();
        met = ostrya_rt::unblock(move || -> Result<Vec<(ObjectName, bool)>> {
            for (name, here) in &mut met {
                if !*here {
                    *here = repo.has_object_blocking(name.ty, &name.checksum)?;
                }
            }
            Ok(met)
        })
        .await?;
    }
    for (name, here) in met {
        if name.ty == ObjectType::DirTree {
            stack.push((name.checksum, here));
        }
        if !here {
            names.push(name);
        }
    }
    Ok(())
}

/// Counts one object that a local pull read from its source, as a fetch counts
/// it.
///
/// The count is one metadata or content object fetched, and `size`, the stored
/// size in the source, transferred.
fn count_fetched(counters: &PullCounters, ty: ObjectType, size: u64) {
    if ty == ObjectType::File {
        counters.content_fetched();
    } else {
        counters.metadata_fetched();
    }
    counters.add_transferred(size);
}

/// Returns the stored size of a loose object in `repo`, or `None` if `repo`
/// does not hold it.
async fn source_size(repo: &Repo, ty: ObjectType, checksum: &Checksum) -> Result<Option<u64>> {
    match repo.loose_object_size(ty, checksum).await {
        Ok(size) => Ok(Some(size)),
        Err(Error::ObjectNotFound { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Loads a commit from a repository: its bytes and the commit parsed from them.
///
/// A commit object can be as large as [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE),
/// so the read and the parse run in one call on the blocking pool.
async fn load_commit(repo: &Repo, checksum: &Checksum) -> Result<(Vec<u8>, Commit)> {
    let repo = repo.clone();
    let checksum = *checksum;
    ostrya_rt::unblock(move || {
        let bytes = repo.load_object_bytes_blocking(ObjectType::Commit, &checksum)?;
        let commit = Commit::parse(&bytes)?;
        Ok((bytes, commit))
    })
    .await
}

/// Loads a commit, or returns `None` for an absent object.
async fn try_load_commit(repo: &Repo, checksum: &Checksum) -> Result<Option<(Vec<u8>, Commit)>> {
    match load_commit(repo, checksum).await {
        Ok(loaded) => Ok(Some(loaded)),
        Err(Error::ObjectNotFound { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Reads the `.commitmeta` bytes of a commit from the first source that holds
/// that object, or returns `None` if no source holds one.
///
/// The result holds the position of that source in `sources` and the bytes.
///
/// This function alone selects the detached metadata of a local pull. The
/// signature verification reads these bytes, and
/// [`Repo::import_detached_metadata`] writes them, so the verified metadata
/// and the stored metadata agree. A
/// zero-length file counts as a source that holds one. It is the "no metadata"
/// marker, and it replaces the copy of the destination.
///
/// The function reads on the calling thread. A caller on the executor calls
/// it in one call on the blocking pool for all sources.
fn detached_bytes_from_blocking(
    sources: &[Repo],
    commit: &Checksum,
) -> Result<Option<(usize, Vec<u8>)>> {
    for (at, src) in sources.iter().enumerate() {
        match src.load_object_bytes_blocking(ObjectType::CommitMeta, commit) {
            Ok(bytes) => return Ok(Some((at, bytes))),
            Err(Error::ObjectNotFound { .. }) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Loads a dirtree from the first source that holds it, or returns `None` if
/// no source holds it.
async fn load_dirtree_from(sources: &[&Repo], checksum: &Checksum) -> Result<Option<DirTree>> {
    for src in sources {
        match src.load_dirtree(checksum).await {
            Ok(dirtree) => return Ok(Some(dirtree)),
            Err(Error::ObjectNotFound { .. }) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Checks the collection options of a local pull.
///
/// The function refuses a local pull of collection refs that writes refs,
/// because no rule names the ref of such a pull. It refuses a pull that names
/// no ref, because an empty list reads `refs/heads` and no collection ref. It
/// then refuses each name that gives no collection ref path, and each name
/// that holds `:`. Delta discovery reads the name as a refspec, where a `:`
/// changes what the name refers to.
///
/// The checks read nothing. The result holds the path of the collection ref of
/// each name, in order, and is `None` without a collection id.
fn check_local_collection(opts: &PullOptions) -> Result<Option<Vec<String>>> {
    let Some(id) = &opts.collection_id else {
        return Ok(None);
    };
    if !opts.no_ref_writes {
        return Err(Error::Unsupported(
            "a local pull with a collection id needs no_ref_writes".into(),
        ));
    }
    if opts.refs.is_empty() {
        return Err(Error::Unsupported(
            "a local pull with a collection id needs at least one ref name".into(),
        ));
    }
    opts.refs
        .iter()
        .map(|name| {
            if name.contains(':') {
                return Err(Error::InvalidRefspec(format!("{id}:{name}")));
            }
            collection_ref_to_relpath(&CollectionRef::new(id.as_str(), name.as_str()))
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// Refuses a collection id on a pull from a remote, which reads no collection
/// ref.
fn refuse_remote_collection(opts: &PullOptions) -> Result<()> {
    if opts.collection_id.is_some() {
        return Err(Error::Unsupported(
            "only a local pull takes a collection id".into(),
        ));
    }
    Ok(())
}

/// Refuses a [`remote`](PullOptions::remote) that
/// [`valid_remote_name`](crate::config::valid_remote_name) refuses.
///
/// The name is the prefix of the written refs. A pull from a remote makes this
/// check before its first request, also under [`MIRROR`](PullFlags::MIRROR).
fn check_remote_option(opts: &PullOptions) -> Result<()> {
    match opts.remote.as_deref() {
        Some(name) if !crate::config::valid_remote_name(name) => {
            Err(Error::InvalidInput(format!("invalid remote name: {name}")))
        }
        _ => Ok(()),
    }
}

/// Refuses a depth below -1.
fn check_depth(depth: i32) -> Result<()> {
    if depth < -1 {
        return Err(Error::InvalidInput(format!("depth {depth} is below -1")));
    }
    Ok(())
}

/// Refuses a list of static deltas that a pull cannot take with its other
/// options.
///
/// The check reads `opts` alone, so a refusal sends no request and opens no
/// transaction. A pull with no list passes.
fn check_static_deltas(opts: &PullOptions) -> Result<()> {
    if opts.static_deltas.is_none() {
        return Ok(());
    }
    if opts.disable_static_deltas {
        return Err(Error::InvalidInput(
            "a pull with static_deltas takes no disable_static_deltas option".into(),
        ));
    }
    if !opts.subpaths.is_empty() {
        return Err(Error::InvalidInput(
            "a pull with static_deltas takes no subpath".into(),
        ));
    }
    Ok(())
}

/// Takes the list of static deltas out of `opts` as the index of its deltas.
///
/// The index sorts the list on the blocking pool. The entry points call this
/// function after their other checks, because the sort of a long list costs
/// time. A pull with no list gets `None`. After the call,
/// `opts.static_deltas` is `None`, and the pull reads the list from the index
/// alone.
///
/// # Errors
///
/// [`Error::InvalidInput`] if two entries have the same source and target
/// and different digests.
async fn take_static_deltas(opts: &mut PullOptions) -> Result<Option<chain::Edges>> {
    let Some(list) = opts.static_deltas.take() else {
        return Ok(None);
    };
    ostrya_rt::unblock(move || chain::Edges::new(list))
        .await
        .map(Some)
}

/// Checks that the `ostree.ref-binding` of a commit names the ref that the pull
/// reads.
///
/// A commit with no binding key is older than the convention and passes. A
/// commit with a binding list that does not name the ref fails.
fn check_ref_binding(checksum: &Checksum, commit: &Commit, ref_name: &str) -> Result<()> {
    if commit.metadata_value("ostree.ref-binding").is_none() {
        return Ok(());
    }
    let bindings = commit.ref_bindings();
    if bindings.contains(&ref_name) {
        return Ok(());
    }
    let listed = if bindings.is_empty() {
        "no refs".to_owned()
    } else {
        bindings.join(", ")
    };
    Err(Error::Pull(format!(
        "commit {checksum}: no requested ref '{ref_name}' in ref binding metadata ({listed})"
    )))
}

/// The commit that the timestamp check of a pull compares against, as the
/// pull resolves it before discovery.
#[derive(Debug, Clone, Copy)]
enum TimestampBase {
    /// No check.
    Off,
    /// The commit that the ref names in this repository, read for each ref.
    CurrentRef,
    /// The commit of [`TimestampCheck::Rev`] and its timestamp, read one time
    /// for each pull.
    Rev {
        /// The checksum of the commit.
        commit: Checksum,
        /// The timestamp of the commit.
        timestamp: u64,
    },
}

impl TimestampBase {
    /// Resolves `check` against this repository.
    ///
    /// For [`TimestampCheck::Rev`], the call reads the timestamp of the
    /// commit. If this repository does not hold the commit, the call fails
    /// with [`Error::ObjectNotFound`].
    async fn resolve(repo: &Repo, check: &TimestampCheck) -> Result<TimestampBase> {
        Ok(match check {
            TimestampCheck::Off => TimestampBase::Off,
            TimestampCheck::CurrentRef => TimestampBase::CurrentRef,
            TimestampCheck::Rev(commit) => TimestampBase::Rev {
                commit: *commit,
                timestamp: commit_timestamp(repo, commit).await?,
            },
        })
    }
}

/// Reads the timestamp of the commit `commit` of this repository.
///
/// The read and the decode run in one call on the blocking pool. The decode
/// reads the timestamp alone, with the checks of [`Commit::parse_timestamp`].
async fn commit_timestamp(repo: &Repo, commit: &Checksum) -> Result<u64> {
    let repo = repo.clone();
    let commit = *commit;
    ostrya_rt::unblock(move || {
        let bytes = repo.load_object_bytes_blocking(ObjectType::Commit, &commit)?;
        Ok(Commit::parse_timestamp(&bytes)?)
    })
    .await
}

/// Reads the commit that the ref `refspec` of this repository names, and the
/// timestamp of that commit. Returns `None` if this repository holds no such
/// ref.
///
/// The ref, the read of the commit, and the decode run in one call on the
/// blocking pool. The errors come in this order: the refspec, the read and
/// the parse of the ref, then the read and the decode of the commit, as
/// [`commit_timestamp`] states.
async fn current_ref_timestamp(repo: &Repo, refspec: &str) -> Result<Option<(Checksum, u64)>> {
    let relpath = refspec_to_relpath(refspec)?;
    let repo = repo.clone();
    ostrya_rt::unblock(move || {
        let Some(current) = repo.resolve_relpath_tip_blocking(&relpath)? else {
            return Ok(None);
        };
        let bytes = repo.load_object_bytes_blocking(ObjectType::Commit, &current)?;
        Ok(Some((current, Commit::parse_timestamp(&bytes)?)))
    })
    .await
}

/// The checks that a pull makes for each requested ref that names a tip
/// commit.
#[derive(Clone, Copy)]
struct TipChecks<'a> {
    /// `true` if the pull makes the ref-binding check.
    bindings: bool,
    /// The timestamp check of the pull.
    timestamp: TimestampBase,
    /// The prefix of the pulled refs. The timestamp check resolves the current
    /// tip of a ref through it. `None` is a local ref.
    ref_prefix: Option<&'a str>,
}

/// Makes the ref-binding check and the timestamp check of each ref of `refs`,
/// in order, for the tip commit `tip`, which parses to `commit`.
///
/// The first check that fails stops the call.
async fn check_tip_refs(
    repo: &Repo,
    checks: TipChecks<'_>,
    tip: &Checksum,
    commit: &Commit,
    refs: &[&str],
) -> Result<()> {
    for ref_name in refs {
        if checks.bindings {
            check_ref_binding(tip, commit, ref_name)?;
        }
        check_timestamp(
            repo,
            checks.timestamp,
            checks.ref_prefix,
            ref_name,
            tip,
            commit,
        )
        .await?;
    }
    Ok(())
}

/// Refuses a fetched tip that is older than the commit of the check.
///
/// Under [`TimestampBase::CurrentRef`], the call reads the ref and the
/// timestamp of its commit in one call on the blocking pool, through
/// [`current_ref_timestamp`].
async fn check_timestamp(
    repo: &Repo,
    check: TimestampBase,
    ref_prefix: Option<&str>,
    ref_name: &str,
    tip: &Checksum,
    fetched: &Commit,
) -> Result<()> {
    let (against, timestamp) = match check {
        TimestampBase::Off => return Ok(()),
        TimestampBase::CurrentRef => {
            // A ref that this repository does not hold has nothing to be
            // older than.
            let Some(current) = current_ref_timestamp(repo, &refspec(ref_prefix, ref_name)).await?
            else {
                return Ok(());
            };
            current
        }
        TimestampBase::Rev { commit, timestamp } => (commit, timestamp),
    };
    if fetched.timestamp >= timestamp {
        return Ok(());
    }
    Err(Error::Pull(format!(
        "commit {tip} (timestamp {}) is chronologically older than \
         {against} (timestamp {})",
        fetched.timestamp, timestamp
    )))
}

/// Imports an object that the two repositories store in the same form, inode
/// included, with a hardlink into the staging directory of the transaction.
///
/// Returns `true` if the object is staged. `false` is a content object with a
/// refused link, which the caller imports through the header of the object.
/// The link is refused in these cases:
///
/// - the destination seals its objects with fs-verity.
/// - the repositories are on different file systems.
/// - the source inode is at its link limit.
/// - the protected-hardlink rules of the kernel refuse it.
/// - [`FORCE_COPY`](PullFlags::FORCE_COPY) is set.
///
/// A metadata object has no header. The function copies it if its link is
/// refused, so it is always staged.
async fn link_import(
    txn: &Transaction,
    src: &Repo,
    name: ObjectName,
    flags: PullFlags,
) -> Result<bool> {
    txn.stage_import(
        src.objects_fd(),
        name.checksum,
        name.ty,
        src.mode(),
        flags.contains(PullFlags::FORCE_COPY),
    )
    .await
}

/// Returns `true` if the two modes store the payload bytes of a regular file in
/// the same form.
///
/// The bare family stores the raw payload, so each pair of its modes
/// qualifies. `archive` stores a framed, deflated form that shares bytes with
/// no other mode.
fn payload_shared(src: RepoMode, dest: RepoMode) -> bool {
    !src.is_archive() && !dest.is_archive()
}

/// Returns `true` if the two modes store a symlink object in the same form,
/// inode included.
///
/// `bare-user` and `bare-user-shared` both store it as a 0644 regular file
/// that holds the target and a NUL, with the logical metadata in
/// `user.ostreemeta`. So the two modes can share the object.
fn symlink_shared(src: RepoMode, dest: RepoMode) -> bool {
    matches!(
        (src, dest),
        (RepoMode::BareUser, RepoMode::BareUserShared)
            | (RepoMode::BareUserShared, RepoMode::BareUser)
    )
}

/// The mode checks of a content object before the write.
///
/// Two rules apply to a content object from each source.
/// [`BAREUSERONLY_FILES`](PullFlags::BAREUSERONLY_FILES) limits the logical
/// mode of a regular file. A `bare-user-only` destination takes only an object
/// whose logical form is the form that it stores. Both rules read the logical
/// metadata alone, so one value holds them. Each path into the object store
/// makes the same checks: a local import, a fetched loose object, and the
/// objects of a static delta part.
#[derive(Clone, Copy)]
pub(crate) struct ModeChecks {
    /// The request of [`BAREUSERONLY_FILES`](PullFlags::BAREUSERONLY_FILES).
    bareuseronly_files: bool,
    /// The state of a `bare-user-only` destination.
    canonical: bool,
}

impl ModeChecks {
    /// Creates the checks of an import under `flags` into a repository of mode
    /// `dest`.
    ///
    /// A path with no pull flags of its own, the offline application of a
    /// static delta, passes [`PullFlags::empty()`]. The rule of the destination
    /// then stays alone.
    pub(crate) fn new(flags: PullFlags, dest: RepoMode) -> ModeChecks {
        ModeChecks {
            bareuseronly_files: flags.contains(PullFlags::BAREUSERONLY_FILES),
            canonical: dest == RepoMode::BareUserOnly,
        }
    }

    /// Returns `true` if a check applies.
    ///
    /// A path that does not read the logical metadata of an object for another
    /// purpose reads it only if this function returns `true`.
    pub(crate) fn any(&self) -> bool {
        self.bareuseronly_files || self.canonical
    }

    /// Refuses a content object whose logical metadata fails a check that
    /// applies.
    ///
    /// The caller calls it before the write of the bytes of the object, so a
    /// refused object leaves nothing.
    pub(crate) fn check(&self, checksum: &Checksum, meta: &FileMeta) -> Result<()> {
        if self.bareuseronly_files {
            check_bareuseronly(checksum, meta)?;
        }
        if self.canonical {
            check_canonical(checksum, meta)?;
        }
        Ok(())
    }
}

/// Refuses a content object whose logical metadata is not the metadata that a
/// `bare-user-only` destination stores.
///
/// That mode records no ownership and no xattrs, and it reduces the permission
/// bits of a regular file to `perm & 0o755`. So a write into it makes the
/// header canonical and names the object for the result. An import keeps the
/// name that the object arrives under. This is possible only if that name
/// covers the canonical header. Another object gets a name that its stored
/// form does not hash to. The object model fixes the mode of a symlink, so a
/// symlink is exempt.
pub(crate) fn check_canonical(checksum: &Checksum, meta: &FileMeta) -> Result<()> {
    let extra = if meta.is_symlink() {
        0
    } else {
        // S_IFREG and the permission bits that the mode keeps.
        meta.mode & !0o100755
    };
    if extra == 0 && meta.uid == 0 && meta.gid == 0 && meta.xattrs.is_empty() {
        return Ok(());
    }
    Err(Error::Pull(format!(
        "content object {checksum}: a bare-user-only repository stores neither \
         ownership nor xattrs and reduces the mode to 0755, so this object -- uid \
         {}, gid {}, mode 0{:o}, {} xattr(s) -- cannot be imported under its own name",
        meta.uid,
        meta.gid,
        meta.mode,
        meta.xattrs.len()
    )))
}

/// Refuses a regular-file content object whose logical mode has bits outside
/// `0775`.
///
/// A symlink has a fixed mode and is exempt.
fn check_bareuseronly(checksum: &Checksum, meta: &FileMeta) -> Result<()> {
    if meta.is_symlink() {
        return Ok(());
    }
    let extra = meta.mode & !0o100775;
    if extra == 0 {
        return Ok(());
    }
    Err(Error::Pull(format!(
        "content object {checksum}: invalid mode 0{:o} with bits 0{:o}",
        meta.mode, extra
    )))
}

/// Verifies that the serialized bytes of a metadata object hash to its name.
async fn verify_metadata(src: &Repo, name: ObjectName) -> Result<()> {
    let bytes = src.load_object_bytes(name.ty, &name.checksum).await?;
    let actual = Checksum::from_bytes(Sha256::digest(&bytes).into());
    if actual != name.checksum {
        return Err(Error::ChecksumMismatch {
            expected: name.checksum,
            actual,
        });
    }
    Ok(())
}

/// Verifies that the framed header and the streamed payload of a content
/// object hash to its name.
///
/// `buf` is the read buffer of the caller. The function grows it to
/// [`READ_CHUNK`] on its first use, and uses it again for each later object.
async fn verify_content(
    checksum: &Checksum,
    file: &crate::file::FileObject,
    buf: &mut Vec<u8>,
) -> Result<()> {
    let mut hasher = ContentHasher::new(&file.header())?;
    let mut reader = file.reader().await?;
    if buf.len() < READ_CHUNK {
        buf.resize(READ_CHUNK, 0);
    }
    loop {
        match reader.read(buf).await? {
            0 => break,
            n => hasher.update(&buf[..n]),
        }
    }
    let actual = hasher.finish();
    if actual != *checksum {
        return Err(Error::ChecksumMismatch {
            expected: *checksum,
            actual,
        });
    }
    Ok(())
}

/// A compile-time check that the pull options and the timestamp check are
/// `Send` and `Sync`.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PullOptions>();
    assert_send_sync::<TimestampCheck>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refspec_uses_the_remote_when_given() {
        assert_eq!(refspec(None, "test/main"), "test/main");
        assert_eq!(refspec(Some("origin"), "test/main"), "origin:test/main");
    }

    #[test]
    fn flags_combine_and_test() {
        let flags = PullFlags::UNTRUSTED | PullFlags::COMMIT_ONLY;
        assert!(flags.contains(PullFlags::UNTRUSTED));
        assert!(flags.contains(PullFlags::COMMIT_ONLY));
        assert!(!flags.contains(PullFlags::FORCE_COPY));
        assert!(PullFlags::empty().contains(PullFlags::NONE));
    }
}
