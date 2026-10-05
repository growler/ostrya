//! Delta-accelerated pull: finding a static delta on a remote, or in the source
//! directory of a local pull, reading it, and applying it into the pull's
//! transaction.
//!
//! A remote that publishes static deltas can deliver a commit as one delta
//! instead of one request per object. What a pull asks for, in order: the delta
//! index for the target commit, where the remote serves a summary that states
//! `indexed-deltas` or omits it, the delta's `superblock`, then the objects the
//! delta hands over loose and its numbered part files. The commit object itself
//! rides in the superblock and is staged from there, so no `.commit` request
//! follows. A part the superblock carries inline, in its metadata dict, is
//! applied from there, and no request is made for it.
//!
//! Which delta. A pull takes one per target commit, the first the advertised
//! map names of: `<from>-<to>` where `from` is the commit the ref being pulled
//! names in this repository, `<c>-<to>` for any other commit `c` held here
//! complete, and the from-scratch `<to>` where the ref names none. A from-to
//! delta patches against the source commit's objects, so the source commit has
//! to be here complete for the delta to apply; a ref whose commit is absent or
//! partial is treated as naming none. A repository whose ref names a commit it
//! holds does not take a from-scratch delta, which would re-deliver every object
//! of the target including the ones it already holds -- the objects it is
//! missing are fetched loose instead. A ref that names the target commit itself,
//! held here partial, leaves the from-scratch delta alone in the same way. This
//! is what the tool was observed to do. A remote with no summary has no map, and
//! the ref's delta is asked for by name. A target commit held here complete is
//! not looked for, and one held partial is looked for as one not held.
//!
//! Where the delta is advertised. With a summary present, the remote's
//! `delta-indexes/<to_b64[0:2]>/<to_b64[2:]>.index` is fetched first; a remote
//! serving no index falls back to the summary's own `ostree.static-deltas` map.
//! Both hold the same thing: a delta name mapped to the SHA-256 of that delta's
//! superblock. A delta the map does not name is not fetched, so a client holding
//! a commit the remote publishes no delta from fetches loose. With no summary at
//! all nothing is advertised and the delta's `superblock` is requested by name,
//! which is the one case a superblock arrives with no digest to check it against.
//!
//! What is checked. A superblock the remote advertised a digest for is hashed and
//! compared against it before it is parsed, so a delta swapped underneath a
//! signed summary fails the pull with [`Error::ChecksumMismatch`]. The parsed
//! superblock has to name the commit being pulled and the source commit the
//! delta's name claims. The delta's own signatures are then checked over the raw
//! superblock bytes, ahead of any part request, so a delta that fails
//! verification costs no part bytes; the policy is the pull's own, described in
//! [`verify`](super::verify). Each inline part is then checked against the size
//! and the checksum its meta-entry declares, also ahead of any part request.
//! Every object a part produces is written with its expected checksum asserted,
//! which is the read path's own rule. Each part is
//! taken off the connection under the size its meta-entry declares and hashed
//! against the checksum that entry names before it is decompressed, so what a
//! remote can drive onto the staging filesystem for one part is the size the
//! superblock states. A superblock the remote does not hold (a stale
//! advertisement) is a 404, which leaves the pull to fetch the objects loose.
//!
//! The requirement. A pull that
//! [requires static deltas](PullOptions::require_static_deltas) refuses a
//! source with no summary, and a target commit it looks for a delta for and
//! takes none: the map names none it can take, or the superblock of the one
//! taken is absent. A from-scratch delta the map names and the pull leaves
//! alone satisfies the requirement.
//!
//! The source. A [`DeltaSource`] is the remote of the pull, over HTTP or over
//! ssh, or the directory of the source repository of a local pull. The same paths are read from either, under
//! the same size caps, and a local read of a file that is not a regular file is
//! refused, so no read waits on a FIFO. A local pull reads the source's summary
//! and its signature in the same way, under the summary's own size cap.
//!
//! Concurrency. A local pull applies one part at a time. Over HTTP two part
//! fetches are in flight at once ([`PART_CAP`]), whatever
//! the pull's slot count is: a part is decompressed into a random-access blob to
//! be applied, so each one in flight costs an xz decoder, the verified body, and
//! the payload, each blob spilling to a temp file past its heap threshold. Parts
//! are applied as they
//! arrive rather than in part order, which the format allows: a part patches
//! against the source commit's objects, which are present before the delta is
//! applied, and never against another part's output.
//!
//! Completeness. The tool takes the delta plus the objects it hands over loose as
//! the whole of what a target commit needs. This pull queues the commit's tree
//! walk as well, once every part is applied, so an object no part delivered is
//! found and fetched loose. The walk reads what the delta staged and asks the
//! network for nothing when the delta was complete, which keeps a pull's
//! invariant that a published commit is whole.

use std::collections::HashMap;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use ostrya_core::{Checksum, ObjectName, ObjectType, RepoMode, Type, Value, from_bytes};
use ostrya_rt::FileReader;
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::delta::{
    Blob, DeltaFallback, DeltaPart, DeltaSuperblock, MAX_SUPERBLOCK, apply_part, concat_to_blob,
    decode_inline_part, decode_part_stream, inline_part_at, verify_inline_part,
};
use crate::deltagen::{
    STATIC_DELTAS_KEY, SUPERBLOCK_FILE, delta_index_relative_path, delta_name, delta_relative_dir,
};
use crate::error::{Error, Result};
use crate::fetch::{FetchRequest, Fetched, Fetcher, Priority};
use crate::object::MAX_METADATA_SIZE;
use crate::pull::verify::Verification;
use crate::pull::{ModeChecks, PullCounters, PullFlags, PullOptions, refspec};
use crate::read::CommitState;
use crate::repo::Repo;
use crate::summary::{INDEXED_DELTAS_KEY, Summary};
use crate::transaction::Transaction;

use super::source::{RemoteSource, session_error};

/// How many delta parts one pull fetches at once.
pub(crate) const PART_CAP: usize = 2;

/// A delta one pull applies for one target commit.
///
/// A job is built during discovery and lives until the pull returns, so a pull
/// retains one of these per target commit. It holds what application reads and
/// nothing else: the superblock's raw bytes, its signature array, and its
/// metadata dict are read at acquisition and dropped there, so what a job
/// retains on the heap is bounded by the target commit -- one meta-entry per
/// part, listing every object the delta produces -- plus 128 KiB at most of
/// inline part bodies, rather than by the superblock size a remote chooses.
/// The inline part bodies are kept in one [`Blob`]: on the heap where they
/// total 128 KiB or less, and otherwise one read-only map of an anonymous temp
/// file in the repository's `tmp/`. That file costs disk space and address
/// space up to the size of the superblock, and it is released when the pull
/// returns.
pub(crate) struct DeltaJob {
    /// The delta's request path prefix, `deltas/<fanout>/<rest>`.
    dir: String,
    /// The delta's name in hex, `<to>` or `<from>-<to>`, as the advertisement
    /// keys it and as a message names it.
    name: String,
    /// The normal-form bytes of the target commit, which the superblock carries
    /// and the pull stages from here.
    pub(crate) commit_bytes: Vec<u8>,
    /// The per-part meta-entries, in part order: what each part hashes to, the
    /// size it is fetched under, and the objects it produces.
    meta_entries: Vec<DeltaPart>,
    /// The objects the delta references and hands over loose.
    fallbacks: Vec<DeltaFallback>,
    /// One slot per part, in part order: the part where the superblock carries
    /// it inline, already checked against its meta-entry, and `None` where the
    /// part is fetched as a file.
    inline: Vec<Option<InlinePart>>,
    /// The bodies of the inline parts, one after the other in part order.
    inline_bodies: Blob,
}

/// A part the superblock carries inline, copied out of the metadata dict.
struct InlinePart {
    /// The compression byte.
    compression: u8,
    /// Where the body that follows the compression byte starts in
    /// [`DeltaJob::inline_bodies`].
    start: usize,
    /// The length of that body.
    len: usize,
}

impl DeltaJob {
    /// The objects the delta names but does not carry, which the pull fetches
    /// loose.
    pub(crate) fn fallbacks(&self) -> Vec<ObjectName> {
        self.fallbacks
            .iter()
            .map(|fallback| ObjectName::new(fallback.checksum, fallback.objtype))
            .collect()
    }

    /// How many parts the delta carries, inline or as files.
    pub(crate) fn parts(&self) -> usize {
        self.meta_entries.len()
    }

    /// How many parts the pull fetches as files, and the sizes the superblock
    /// declares for them.
    pub(crate) fn fetched_parts(&self) -> (u32, u64) {
        self.meta_entries
            .iter()
            .zip(&self.inline)
            .filter(|(_, inline)| inline.is_none())
            .fold((0, 0), |(parts, bytes), (entry, _)| {
                (parts + 1, bytes + entry.size)
            })
    }
}

/// Find the delta to pull each target commit with, keyed by that commit.
///
/// A commit with no entry is pulled object by object. Discovery is skipped for a
/// commit this repository already holds complete, since the walk then fetches
/// nothing, for a
/// [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull, whose plan is the commit objects
/// alone, for a pull held to [`subpaths`](PullOptions::subpaths) into an
/// `archive` repository that does not
/// [`require_static_deltas`](PullOptions::require_static_deltas), which fetches
/// the subpaths loose, and when
/// [`disable_static_deltas`](PullOptions::disable_static_deltas) is set.
///
/// A pull that requires static deltas from a source with no summary is refused
/// before any of these skips, and one that finds no delta for a commit it looks
/// for is refused as [`discover_one`] states.
///
/// Two refs naming one commit share one delta, since the plan fetches that commit
/// once. The source commit is read from the ref this repository holds, so the
/// refs are tried in the order they were requested and the first that yields a
/// delta decides.
///
/// Each delta index request and each superblock request adds one to the
/// metadata fetched in `progress`, whatever the source answers, which is what
/// the tool counts.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn discover(
    repo: &Repo,
    source: &DeltaSource<'_>,
    summary: Option<&Summary>,
    targets: &[(String, Checksum)],
    opts: &PullOptions,
    ref_prefix: Option<&str>,
    verification: &Verification,
    progress: &PullCounters,
) -> Result<HashMap<Checksum, DeltaJob>> {
    let mut jobs = HashMap::new();
    if opts.disable_static_deltas {
        return Ok(jobs);
    }
    // With no summary nothing advertises a delta, so a pull that requires one
    // is refused whatever it would look for.
    if opts.require_static_deltas && summary.is_none() {
        return Err(no_summary_error());
    }
    if opts.flags.contains(PullFlags::COMMIT_ONLY)
        || (!opts.subpaths.is_empty()
            && repo.mode() == RepoMode::Archive
            && !opts.require_static_deltas)
    {
        return Ok(jobs);
    }
    for (ref_name, to) in targets {
        if jobs.contains_key(to) || complete_here(repo, to).await? {
            continue;
        }
        let tip = repo.resolve_ref_tip(&refspec(ref_prefix, ref_name)).await?;
        let from = source_commit(repo, tip, to).await?;
        // A ref that names the target, which is here partial, leaves the
        // from-scratch delta alone as a ref naming a complete commit does.
        let scratch = from.is_none() && tip != Some(*to);
        if let Some(job) = discover_one(
            repo,
            source,
            summary,
            ref_name,
            from,
            scratch,
            *to,
            opts,
            verification,
            progress,
        )
        .await?
        {
            jobs.insert(*to, job);
        }
    }
    Ok(jobs)
}

/// Whether this repository already holds a commit and everything it references.
async fn complete_here(repo: &Repo, commit: &Checksum) -> Result<bool> {
    Ok(repo.has_object(ObjectType::Commit, commit).await?
        && repo.commit_state(commit).await? == CommitState::Normal)
}

/// The commit a from-to delta would patch against: `tip`, the commit the ref
/// being pulled names in this repository, when this repository holds it
/// complete.
///
/// A ref that names nothing, or names a commit whose objects are not all here,
/// yields `None`, and the pull looks for a from-scratch delta instead: a delta
/// patches against the source commit's objects, and the ones a partial commit is
/// missing are what a part would fail to read. A ref that already names the
/// target yields `None` as well, since a delta from a commit to itself carries
/// nothing.
async fn source_commit(
    repo: &Repo,
    tip: Option<Checksum>,
    to: &Checksum,
) -> Result<Option<Checksum>> {
    let Some(current) = tip else {
        return Ok(None);
    };
    if current == *to || !complete_here(repo, &current).await? {
        return Ok(None);
    }
    Ok(Some(current))
}

/// Where a pull reads a delta from.
pub(crate) enum DeltaSource<'a> {
    /// A remote, over HTTP or over ssh.
    Remote(&'a RemoteSource),
    /// Another local repository, read from its directory.
    Local(&'a Repo),
}

impl DeltaSource<'_> {
    /// Read a delta index or a superblock whole, under `cap`, or `None` when
    /// the source does not hold it.
    ///
    /// A remote source adds the bytes of a fetched body to the transferred
    /// count itself. A local read adds its bytes to `progress` here.
    async fn read(&self, path: &str, cap: u64, progress: &PullCounters) -> Result<Option<Vec<u8>>> {
        match self {
            DeltaSource::Remote(source) => source.read_optional(path, Priority::High, cap).await,
            DeltaSource::Local(repo) => {
                let bytes = read_local(repo, path, cap).await?;
                if let Some(bytes) = &bytes {
                    progress.add_transferred(bytes.len() as u64);
                }
                Ok(bytes)
            }
        }
    }
}

/// Open a regular file at `path` under `repo_fd`, and return it with its
/// length, or `None` when it does not exist.
///
/// The open does not block, so a FIFO at the path is refused with every other
/// file that is not a regular file, and no read waits on a writer.
fn open_local_blocking(
    repo_fd: BorrowedFd<'_>,
    path: &str,
) -> Result<Option<(std::fs::File, u64)>> {
    let fd = match rustix::fs::openat(
        repo_fd,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(Error::from(e)),
    };
    let file = std::fs::File::from(fd);
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(Error::InvalidFormat(format!(
            "{path} in the source repository is not a regular file"
        )));
    }
    Ok(Some((file, meta.len())))
}

/// Open a regular file at `path` under the directory of `repo`, as
/// [`open_local_blocking`] states.
async fn open_local(repo: &Repo, path: &str) -> Result<Option<(std::fs::File, u64)>> {
    let repo_fd = repo.repo_fd().try_clone_to_owned()?;
    let path = path.to_owned();
    ostrya_rt::unblock(move || open_local_blocking(repo_fd.as_fd(), &path)).await
}

/// Read a regular file at `path` under the directory of `repo` whole, under
/// `cap`, or `None` when it does not exist. A file longer than `cap` is
/// refused having read `cap` bytes and one more, and a file that is not a
/// regular file is refused as [`open_local_blocking`] states.
pub(crate) async fn read_local(repo: &Repo, path: &str, cap: u64) -> Result<Option<Vec<u8>>> {
    let repo_fd = repo.repo_fd().try_clone_to_owned()?;
    let path = path.to_owned();
    ostrya_rt::unblock(move || {
        use std::io::Read;
        let Some((file, len)) = open_local_blocking(repo_fd.as_fd(), &path)? else {
            return Ok(None);
        };
        let hint = len.min(cap) + 1;
        let mut bytes = Vec::with_capacity(usize::try_from(hint).unwrap_or(0));
        file.take(cap + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > cap {
            return Err(Error::InvalidFormat(format!(
                "{path} in the source repository exceeds the size ceiling of {cap} bytes"
            )));
        }
        Ok(Some(bytes))
    })
    .await
}

/// The refusal of a pull that requires a static delta from a source that
/// serves no summary, in the tool's words.
pub(crate) fn no_summary_error() -> Error {
    Error::Pull(
        "Fetch configured to require static deltas, but no summary deltas or delta index \
         found"
            .into(),
    )
}

/// The refusal of a pull that requires a static delta and finds none that
/// produces `to` for `ref_name`, in the tool's words.
fn none_found_error(ref_name: &str, to: &Checksum) -> Error {
    Error::Pull(format!(
        "Static deltas required, but none found for {ref_name} to {to}"
    ))
}

/// Which delta an advertised map offers for one target commit.
#[derive(Debug, PartialEq, Eq)]
enum Choice {
    /// Take the delta from `from`, `None` for the from-scratch delta, whose
    /// superblock hashes to `digest`.
    Take {
        from: Option<Checksum>,
        digest: Checksum,
    },
    /// The map names a from-scratch delta, which the pull leaves alone because
    /// the ref names a commit held here.
    Declined,
    /// The map names no delta that produces the commit from what is here.
    None,
}

/// Choose the delta to `to` that `map` offers, with `from` the commit the ref
/// names here when this repository holds it complete, and `scratch` whether
/// the from-scratch delta may be taken. [`discover_one`] states the order.
async fn choose_delta(
    repo: &Repo,
    map: &Value,
    from: Option<Checksum>,
    scratch: bool,
    to: &Checksum,
) -> Result<Choice> {
    if let Some(from) = from
        && let Some(digest) = map_digest(map, &delta_name(Some(&from), to))?
    {
        return Ok(Choice::Take {
            from: Some(from),
            digest,
        });
    }
    let suffix = format!("-{}", to.to_hex());
    for entry in map.as_array().unwrap_or_default() {
        let Some([key, value]) = entry.as_tuple() else {
            continue;
        };
        let Some(name) = key.as_str() else {
            continue;
        };
        let Some(candidate) = name
            .strip_suffix(&suffix)
            .and_then(|hex| Checksum::from_hex(hex).ok())
        else {
            continue;
        };
        if Some(candidate) != from && complete_here(repo, &candidate).await? {
            return Ok(Choice::Take {
                from: Some(candidate),
                digest: entry_digest(name, value)?,
            });
        }
    }
    Ok(match map_digest(map, &delta_name(None, to))? {
        Some(digest) if scratch => Choice::Take { from: None, digest },
        Some(_) => Choice::Declined,
        None => Choice::None,
    })
}

/// What a remote states about the deltas it holds.
enum Advertisement {
    /// A map of delta name to superblock digest: the index file for the target
    /// commit, or the summary's own map.
    Map(Value),
    /// The remote serves no summary, so it advertises nothing and a delta is
    /// asked for by name.
    Unlisted,
    /// The remote serves a summary and names no delta in it.
    Nothing,
}

/// Find and read the delta that produces `to`, or `None` when the pull fetches
/// the objects loose.
///
/// `from` is the commit the pulled ref names here, when this repository holds it
/// complete. `scratch` is set where the ref names no commit held complete and
/// does not name `to`. Where the remote advertises a map, the delta taken is
/// the first of these that the map names: `<from>-<to>`, then `<c>-<to>` for
/// any commit `c` this repository holds complete, in map order, then the
/// from-scratch `<to>` where `scratch` is set. The tool was observed to take a
/// from-to delta from a commit it holds under no ref in the same way. Where
/// nothing advertises a map, the delta from `from`, or from scratch where
/// `from` is `None`, is asked for by name.
///
/// A pull that [requires](PullOptions::require_static_deltas) a delta and finds
/// none is refused. A from-scratch delta the map names and the pull leaves
/// alone, because the ref names a commit held here, complete or partial, counts
/// as found, so that pull fetches loose. A superblock the map names and the
/// remote does not hold counts as none.
#[allow(clippy::too_many_arguments)]
async fn discover_one(
    repo: &Repo,
    source: &DeltaSource<'_>,
    summary: Option<&Summary>,
    ref_name: &str,
    from: Option<Checksum>,
    scratch: bool,
    to: Checksum,
    opts: &PullOptions,
    verification: &Verification,
    progress: &PullCounters,
) -> Result<Option<DeltaJob>> {
    let advertised = match summary {
        None => Advertisement::Unlisted,
        Some(summary) => match advertised_map(source, summary, &to, progress).await? {
            Some(map) => Advertisement::Map(map),
            None => Advertisement::Nothing,
        },
    };
    let none_found = || -> Result<Option<DeltaJob>> {
        if opts.require_static_deltas {
            return Err(none_found_error(ref_name, &to));
        }
        Ok(None)
    };

    let (from, digest) = match &advertised {
        Advertisement::Map(map) => match choose_delta(repo, map, from, scratch, &to).await? {
            Choice::Take { from, digest } => (from, Some(digest)),
            // A remote that publishes a from-scratch delta for this commit
            // satisfies a requirement the pull does not act on: the objects
            // the ref's commit already supplies are fetched loose instead.
            Choice::Declined => return Ok(None),
            Choice::None => return none_found(),
        },
        // Nothing states a digest, so the delta is asked for by name and its
        // superblock arrives unchecked against an advertisement. What it produces
        // is still checked object by object as the parts are applied.
        Advertisement::Unlisted => (from, None),
        Advertisement::Nothing => return none_found(),
    };
    let name = delta_name(from.as_ref(), &to);

    let path = format!(
        "{}/{SUPERBLOCK_FILE}",
        delta_relative_dir(from.as_ref(), &to)
    );
    // A superblock the remote no longer holds is a stale advertisement, which
    // leaves the objects to be fetched loose, unless the pull requires static
    // deltas.
    let fetched = source.read(&path, MAX_SUPERBLOCK, progress).await?;
    progress.metadata_fetched();
    let Some(bytes) = fetched else {
        return none_found();
    };
    if let Some(expected) = digest {
        let actual = Checksum::sha256(&bytes);
        if actual != expected {
            return Err(Error::ChecksumMismatch { expected, actual });
        }
    }

    let superblock = DeltaSuperblock::parse(bytes)?;
    if superblock.to != to || superblock.from != from {
        return Err(Error::Pull(format!(
            "static delta {name}: its superblock produces {} from {}",
            superblock.to,
            match superblock.from {
                Some(from) => from.to_hex(),
                None => "scratch".to_owned(),
            }
        )));
    }
    // Destructured, so the compiler establishes that the raw bytes, the
    // signature array, and the metadata dict reach verification and the inline
    // parts and go no further: what the job carries is what application reads.
    let DeltaSuperblock {
        commit_bytes,
        meta_entries,
        fallbacks,
        signatures,
        superblock_bytes,
        metadata,
        inline_index,
        ..
    } = superblock;
    verify_fetched_delta(verification, &name, &superblock_bytes, signatures.as_ref()).await?;
    drop(superblock_bytes);
    let dir = delta_relative_dir(from.as_ref(), &to);
    let (inline, inline_bodies) =
        take_inline_parts(repo, &metadata, &inline_index, &dir, &meta_entries).await?;
    drop(metadata);
    Ok(Some(DeltaJob {
        dir,
        name,
        commit_bytes,
        meta_entries,
        fallbacks,
        inline,
        inline_bodies,
    }))
}

/// Check each part the superblock carries inline against its meta-entry, in
/// part order, and copy the bodies out of the metadata dict into one [`Blob`],
/// so the dict can be dropped. Where the bodies total more than the heap
/// threshold of 128 KiB, the blob is one anonymous temp file in the
/// repository's `tmp/`, mapped read-only, and the job keeps no copy of them on
/// the heap.
async fn take_inline_parts(
    repo: &Repo,
    metadata: &Value,
    index: &[Option<usize>],
    dir: &str,
    meta_entries: &[DeltaPart],
) -> Result<(Vec<Option<InlinePart>>, Blob)> {
    let mut inline = Vec::with_capacity(meta_entries.len());
    let mut bodies: Vec<&[u8]> = Vec::new();
    let mut start = 0usize;
    for (part, entry) in meta_entries.iter().enumerate() {
        let Some((compression, body)) = inline_part_at(metadata, index, part, || dir.to_owned())?
        else {
            inline.push(None);
            continue;
        };
        verify_inline_part(compression, body, entry)?;
        inline.push(Some(InlinePart {
            compression,
            start,
            len: body.len(),
        }));
        start += body.len();
        bodies.push(body);
    }
    if bodies.is_empty() {
        return Ok((inline, Blob::Ram(Vec::new())));
    }
    let tmp = repo.open_tmp_dir().await?;
    Ok((inline, concat_to_blob(&bodies, &tmp).await?))
}

/// Verify a fetched delta's detached signatures over the raw superblock bytes.
///
/// The pull's own policy decides: the sign-api engines it checks a commit with
/// check the delta too, since a delta carries sign-api signatures alone. A delta
/// carrying none of those signatures is accepted, and the commit it delivers is
/// held to the commit policy like any other. The call sits here so the
/// superblock's raw bytes and its signature array are read where they are
/// available and dropped afterwards, rather than held for the length of the
/// pull.
async fn verify_fetched_delta(
    verification: &Verification,
    name: &str,
    superblock_bytes: &[u8],
    signatures: Option<&Value>,
) -> Result<()> {
    verification
        .check_delta(name, superblock_bytes, signatures)
        .await
}

/// The delta map the remote advertises for `to`: the index file when it serves
/// one, the summary's own `ostree.static-deltas` map otherwise, and `None` when
/// it advertises neither.
///
/// The index is asked for first whenever the summary states `indexed-deltas`,
/// which is the default a repository that says nothing carries. A remote that
/// holds deltas but has never been reindexed answers 404 there and is read
/// through the summary map instead.
async fn advertised_map(
    source: &DeltaSource<'_>,
    summary: &Summary,
    to: &Checksum,
    progress: &PullCounters,
) -> Result<Option<Value>> {
    if indexed_deltas(summary) {
        let path = delta_index_relative_path(to);
        let fetched = source.read(&path, MAX_METADATA_SIZE, progress).await?;
        progress.metadata_fetched();
        if let Some(bytes) = fetched {
            let ty = Type::parse("a{sv}").map_err(ostrya_core::Error::from)?;
            let dict = from_bytes(&ty, &bytes).map_err(ostrya_core::Error::from)?;
            let map = dict
                .dict_get(STATIC_DELTAS_KEY)
                .and_then(Value::as_variant)
                .map(|(_, map)| map.clone())
                .ok_or_else(|| {
                    Error::InvalidFormat(format!(
                        "the remote's delta index for {to} holds no {STATIC_DELTAS_KEY} map"
                    ))
                })?;
            return Ok(Some(map));
        }
    }
    Ok(summary.metadata_value(STATIC_DELTAS_KEY).cloned())
}

/// Whether the summary states that the remote indexes its deltas. A summary that
/// does not carry the key is read as indexing them, which is the repository
/// default.
fn indexed_deltas(summary: &Summary) -> bool {
    summary
        .metadata_value(INDEXED_DELTAS_KEY)
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

/// The superblock digest a delta map holds for `name`.
fn map_digest(map: &Value, name: &str) -> Result<Option<Checksum>> {
    let Some(entry) = map.dict_get(name) else {
        return Ok(None);
    };
    entry_digest(name, entry).map(Some)
}

/// The superblock digest of the map entry `entry` for the delta `name`.
fn entry_digest(name: &str, entry: &Value) -> Result<Checksum> {
    let bytes = entry
        .as_variant()
        .map(|(_, value)| value)
        .and_then(Value::as_bytes)
        .ok_or_else(|| {
            Error::InvalidFormat(format!(
                "the remote advertises static delta {name} with no superblock digest"
            ))
        })?;
    Ok(Checksum::from_ay(bytes)?)
}

/// Read one part of a delta from `source` and apply it into the pull's
/// transaction.
///
/// A part the superblock carries inline was checked at discovery, so it is
/// decompressed and applied with no request.
///
/// The part streams off the connection, or out of the source repository's part
/// file, under the size the superblock declares for it and is hashed against
/// the superblock's checksum for it; the verified body then decompresses into
/// the random-access blob the operations read, which is on the heap while it is
/// small and a mapped temp file when it is not. A remote that answers a part
/// request with more than the part is, or with other bytes altogether, and a
/// part file that grew or changed, therefore write at most the declared size
/// before the refusal. Applying the blob produces the part's objects, each
/// written under the checksum the superblock names, so a part that produces
/// something else fails there.
///
/// `checks` are the pull's mode checks, which every content object a part
/// produces is held to exactly as a loose fetch of that object would be. A
/// part read as a file adds one part and its declared size to `progress`
/// once its body has passed the checksum, and a part read from a local
/// source adds that size to the transferred count as well.
pub(crate) async fn apply_job_part(
    txn: &Transaction,
    source: &DeltaSource<'_>,
    job: &DeltaJob,
    index: usize,
    checks: ModeChecks,
    progress: &PullCounters,
) -> Result<()> {
    let entry = job.meta_entries.get(index).ok_or_else(|| {
        Error::InvalidFormat(format!(
            "static delta {}: no part {index} in its superblock",
            job.name
        ))
    })?;
    if let Some(Some(part)) = job.inline.get(index) {
        let staging = txn.staging_fd().try_clone_to_owned()?;
        let body = &job.inline_bodies.as_slice()[part.start..part.start + part.len];
        let payload = decode_inline_part(part.compression, body, &staging).await?;
        return apply_part(txn, payload.as_slice(), &entry.objects, &staging, checks).await;
    }
    let path = format!("{}/{index}", job.dir);
    let staging = txn.staging_fd().try_clone_to_owned()?;
    let blob = match source {
        DeltaSource::Remote(RemoteSource::Http(fetcher)) => {
            fetch_part_blob(fetcher, &path, entry, &staging).await?
        }
        // The superblock states the size of the part, which caps the body.
        DeltaSource::Remote(RemoteSource::Ssh(ssh)) => {
            let body = ssh.get(&path, entry.size).await?.ok_or_else(|| {
                Error::InvalidFormat(format!(
                    "static delta {}: the remote holds no part {index}",
                    job.name
                ))
            })?;
            decode_part_stream(body, entry, &staging)
                .await
                .map_err(session_error)?
        }
        DeltaSource::Local(repo) => {
            let (file, len) = open_local(repo, &path).await?.ok_or_else(|| {
                Error::InvalidFormat(format!(
                    "static delta {}: the source repository holds no part {index}",
                    job.name
                ))
            })?;
            // A part file longer than the superblock declares is refused
            // before any read, since the async reader reads ahead of what
            // the declared-size limit lets it write.
            if len > entry.size {
                return Err(Error::InvalidFormat(format!(
                    "static delta {}: part {index} holds {len} byte(s), past the {} \
                     declared for it",
                    job.name, entry.size
                )));
            }
            let blob =
                decode_part_stream(FileReader::with_len_hint(file, len), entry, &staging).await?;
            progress.add_transferred(entry.size);
            blob
        }
    };
    progress.part_fetched(entry.size);
    apply_part(txn, blob.as_slice(), &entry.objects, &staging, checks).await
}

/// Fetch the part file at `path` into a verified, decompressed blob.
async fn fetch_part_blob(
    fetcher: &Fetcher,
    path: &str,
    entry: &DeltaPart,
    staging: &OwnedFd,
) -> Result<Blob> {
    // The superblock states the part file's size, so the fetcher refuses a
    // `Content-Length` above it before the body arrives and stops a body that
    // passes it as the bytes land.
    // A body that fails in transit is fetched again from the start, into a new
    // blob, while the fetcher's retry count has a repeat left.
    let mut refetch = fetcher.refetching(FetchRequest {
        priority: Priority::High,
        max_size: Some(entry.size),
        ..FetchRequest::path(path)
    });
    loop {
        let body = match refetch.fetch().await? {
            Fetched::Body(body) => body,
            Fetched::NotModified => {
                return Err(Error::Fetch(format!(
                    "{path}: the remote answered 304 to an unconditional request"
                )));
            }
        };
        match decode_part_stream(body, entry, staging).await {
            Ok(blob) => return Ok(blob),
            Err(e) => refetch.retry(e).await?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    /// The digest lookup reads the `ay` behind the variant, reports an absent
    /// delta as absent, and refuses an entry holding something else.
    #[test]
    fn map_digest_reads_the_advertised_ay() {
        let digest = checksum(0x33);
        let ay = Type::parse("ay").unwrap();
        let mut map = Value::Array(Vec::new());
        crate::commit::append_dict_entry(
            &mut map,
            "delta-name",
            Value::variant(ay, Value::Bytes(digest.as_bytes().to_vec())),
        )
        .unwrap();
        crate::commit::append_dict_entry(
            &mut map,
            "not-a-digest",
            Value::variant(Type::parse("s").unwrap(), Value::Str("nope".to_owned())),
        )
        .unwrap();

        assert_eq!(map_digest(&map, "delta-name").unwrap(), Some(digest));
        assert_eq!(map_digest(&map, "absent").unwrap(), None);
        assert!(matches!(
            map_digest(&map, "not-a-digest"),
            Err(Error::InvalidFormat(_))
        ));
    }
}
