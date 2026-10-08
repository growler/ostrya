//! Static deltas in a pull: the search for a delta on the source and its
//! application into the transaction of the pull.
//!
//! A [`DeltaSource`] is the remote of the pull, over HTTP or over ssh, or the
//! directory of the source repository of a local pull. The pull reads the same
//! paths from each source, under the same size caps. [`PART_CAP`] sets the
//! limit of part fetches in flight from a remote. The rules that a caller
//! sees are on `Repo::pull`, under `# Static deltas`, and on
//! `PullOptions::require_static_deltas`.

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

/// The number of delta parts that one pull fetches at a time.
pub(crate) const PART_CAP: usize = 2;

/// A static delta that a pull applies for one target commit.
///
/// Discovery builds a job, and the job lives until the pull returns. A pull
/// keeps one job for each target commit. A job holds only what the
/// application of the parts reads.
///
/// Discovery reads the raw superblock bytes, the signature array, and the
/// metadata dict, and drops them there. The heap cost of a job is one
/// meta-entry for each part and at most 128 KiB of inline part bodies. The
/// meta-entries list each object that the delta produces. The superblock size
/// that a remote chooses does not change this cost.
///
/// The job keeps the inline part bodies in one [`Blob`]. If the bodies total
/// 128 KiB or less, the blob is on the heap. If they total more, the blob is
/// one read-only map of an anonymous temp file in `tmp/` of the repository.
/// This file costs disk space and address space up to the superblock size,
/// and the pull releases it when it returns.
pub(crate) struct DeltaJob {
    /// The request path prefix of the delta, `deltas/<fanout>/<rest>`.
    dir: String,
    /// The name of the delta in hex, `<to>` or `<from>-<to>`. It is the key in
    /// the advertisement and the name in a message.
    name: String,
    /// The normal-form bytes of the target commit. The superblock carries them,
    /// and the pull stages the commit from them.
    pub(crate) commit_bytes: Vec<u8>,
    /// The meta-entries of the parts, in part order: the checksum of each part,
    /// the size that caps its fetch, and the objects that it produces.
    meta_entries: Vec<DeltaPart>,
    /// The objects that the delta references and hands over loose.
    fallbacks: Vec<DeltaFallback>,
    /// One slot for each part, in part order. A slot holds the part if the
    /// superblock carries it inline, already verified against its meta-entry.
    /// A slot is `None` if the pull fetches the part as a file.
    inline: Vec<Option<InlinePart>>,
    /// The bodies of the inline parts, one after the other, in part order.
    inline_bodies: Blob,
}

/// A part that the superblock carries inline, copied out of the metadata dict.
struct InlinePart {
    /// The compression byte.
    compression: u8,
    /// The start, in [`DeltaJob::inline_bodies`], of the body that follows the
    /// compression byte.
    start: usize,
    /// The length of that body.
    len: usize,
}

impl DeltaJob {
    /// Returns the objects that the delta names and does not carry.
    ///
    /// The pull fetches these objects loose.
    pub(crate) fn fallbacks(&self) -> Vec<ObjectName> {
        self.fallbacks
            .iter()
            .map(|fallback| ObjectName::new(fallback.checksum, fallback.objtype))
            .collect()
    }

    /// Returns the number of parts of the delta, inline parts and part files.
    pub(crate) fn parts(&self) -> usize {
        self.meta_entries.len()
    }

    /// Returns the number of part files and the sum of their declared sizes.
    ///
    /// A part file is a part that the pull fetches as a file. The superblock
    /// declares the size of each part.
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

/// Finds the delta for each target commit, keyed by that commit.
///
/// The pull fetches a commit with no entry object by object. Discovery looks
/// for no delta in these cases:
///
/// - a commit that this repository already holds complete, because the walk
///   then fetches nothing
/// - a [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull, whose plan holds the
///   commit objects alone
/// - a pull held to [`subpaths`](PullOptions::subpaths) into an `archive`
///   repository with no
///   [`require_static_deltas`](PullOptions::require_static_deltas), which
///   fetches the subpaths loose
/// - a pull with
///   [`disable_static_deltas`](PullOptions::disable_static_deltas) set
///
/// If `disable_static_deltas` is set, discovery returns before all other
/// checks. A pull that requires static deltas from a source with no summary
/// fails before the other skips. A pull that requires static deltas and finds
/// no delta for a commit fails as [`discover_one`] states.
///
/// Two refs that name one commit share one delta, because the plan fetches
/// that commit once. Discovery reads the source commit from the ref in this
/// repository, so it tries the refs in request order. The first ref that
/// yields a delta decides.
///
/// Each delta index request and each superblock request adds one to the
/// metadata count in `progress`, whatever the source answers. The `ostree`
/// command counts the same way.
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
    // If there is no summary, nothing advertises a delta, so a pull that
    // requires a delta fails whatever it looks for.
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
        // If the ref names the target and the target is partial here, the
        // pull takes no from-scratch delta. A ref that names a complete
        // commit has the same effect.
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

/// Returns `true` if this repository holds a commit and each object that it
/// references.
pub(super) async fn complete_here(repo: &Repo, commit: &Checksum) -> Result<bool> {
    Ok(repo.has_object(ObjectType::Commit, commit).await?
        && repo.commit_state(commit).await? == CommitState::Normal)
}

/// Returns the source commit of a from-to delta: `tip`, if this repository
/// holds it complete.
///
/// `tip` is the commit that the pulled ref names in this repository. If the
/// ref names no commit, or a commit whose objects are not all here, the
/// result is `None`. The pull then looks for a from-scratch delta. A delta
/// patches against the objects of the source commit, and a part fails to read
/// the objects that a partial commit does not hold.
///
/// If the ref names the target, the result is also `None`, because a delta
/// from a commit to itself carries nothing.
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

/// The source from which a pull reads a delta.
pub(crate) enum DeltaSource<'a> {
    /// A remote, over HTTP or over ssh.
    Remote(&'a RemoteSource),
    /// Another local repository, read through its directory.
    Local(&'a Repo),
}

impl DeltaSource<'_> {
    /// Reads a whole delta index or superblock under `cap`, or `None` if it is
    /// absent.
    ///
    /// A remote source adds the bytes of a fetched body to the transferred
    /// count itself. For a local read, this method adds the bytes to
    /// `progress`.
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

/// Opens the regular file at `path` under `repo_fd`, with its length, or
/// `None` if it is absent.
///
/// The open does not block, so an open of a FIFO does not wait for a writer.
/// The function then refuses each file that is not a regular file, a FIFO
/// included, with [`Error::InvalidFormat`]. As a result, no read waits for a
/// writer.
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

/// Opens the regular file at `path` under the directory of `repo`.
///
/// The open runs on the blocking pool. [`open_local_blocking`] states the
/// rules.
async fn open_local(repo: &Repo, path: &str) -> Result<Option<(std::fs::File, u64)>> {
    let repo_fd = repo.repo_fd().try_clone_to_owned()?;
    let path = path.to_owned();
    ostrya_rt::unblock(move || open_local_blocking(repo_fd.as_fd(), &path)).await
}

/// Reads the whole regular file at `path` under `repo`, or `None` if it is
/// absent.
///
/// If the file is longer than `cap`, the function reads `cap` bytes and one
/// more, then refuses the file with [`Error::InvalidFormat`]. A file that is
/// not a regular file fails as [`open_local_blocking`] states.
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

/// Returns the error of a pull that requires static deltas from a source with
/// no summary.
///
/// The message is the message of the `ostree` command.
pub(crate) fn no_summary_error() -> Error {
    Error::Pull(
        "Fetch configured to require static deltas, but no summary deltas or delta index \
         found"
            .into(),
    )
}

/// Returns the error of a pull that requires a static delta and finds none.
///
/// The error names the ref `ref_name` and the target commit `to`. The message
/// is the message of the `ostree` command.
fn none_found_error(ref_name: &str, to: &Checksum) -> Error {
    Error::Pull(format!(
        "Static deltas required, but none found for {ref_name} to {to}"
    ))
}

/// The delta that an advertised map offers for one target commit.
#[derive(Debug, PartialEq, Eq)]
enum Choice {
    /// The delta from `from` (`None` for the from-scratch delta), with
    /// `digest` as the SHA-256 of its superblock.
    Take {
        from: Option<Checksum>,
        digest: Checksum,
    },
    /// A from-scratch delta in the map, which the pull does not take because
    /// the ref names a commit held here complete, or names the target.
    Declined,
    /// No delta in the map produces the commit from the objects here.
    None,
}

/// Chooses the delta to `to` that `map` offers.
///
/// `from` is the commit that the ref names here, if this repository holds it
/// complete. `scratch` is `true` if the pull can take the from-scratch delta.
/// [`discover_one`] states the order of the choice.
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

/// What a remote states about the deltas that it holds.
enum Advertisement {
    /// A map from delta name to superblock digest: the index file of the
    /// target commit, or the map of the summary.
    Map(Value),
    /// The remote serves no summary. It advertises nothing, and the pull
    /// requests a delta by name.
    Unlisted,
    /// The remote serves a summary and advertises no delta map.
    Nothing,
}

/// Finds and reads the delta that produces `to`, or `None` if the pull fetches
/// the objects loose.
///
/// `from` is the commit that the pulled ref names here, if this repository
/// holds it complete. `scratch` is `true` if the ref names no commit held
/// complete and does not name `to`.
///
/// If the remote advertises a map, the pull takes the first of these deltas
/// that the map names:
///
/// 1. `<from>-<to>`
/// 2. `<c>-<to>`, for each commit `c` that this repository holds complete, in
///    map order
/// 3. the from-scratch `<to>`, if `scratch` is `true`
///
/// Observed: the `ostree` command also takes a from-to delta from a commit
/// that it holds under no ref. If nothing advertises a map, the pull requests
/// the delta from `from` by name. If `from` is `None`, it requests the
/// from-scratch delta.
///
/// A pull that [requires](PullOptions::require_static_deltas) a delta and
/// finds none fails with [`Error::Pull`]. If the ref names a commit held here
/// complete, or names `to`, the pull does not take a from-scratch delta in
/// the map. That delta counts as found, and the pull fetches loose. A
/// superblock that the map names and the remote does not hold counts as none.
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
            // A from-scratch delta for this commit on the remote satisfies the
            // requirement, and the pull does not take it. The pull fetches
            // loose each object of the commit that this repository lacks.
            Choice::Declined => return Ok(None),
            Choice::None => return none_found(),
        },
        // Nothing states a digest, so the pull requests the delta by name, and
        // no advertised digest verifies the superblock. The application of the
        // parts still verifies each object that the delta produces.
        Advertisement::Unlisted => (from, None),
        Advertisement::Nothing => return none_found(),
    };
    let name = delta_name(from.as_ref(), &to);

    let path = format!(
        "{}/{SUPERBLOCK_FILE}",
        delta_relative_dir(from.as_ref(), &to)
    );
    // If the remote does not hold an advertised superblock, the advertisement
    // is stale. The pull then fetches the objects loose. If the pull requires
    // static deltas, it fails.
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
    // The destructure lets the compiler prove where the raw bytes, the
    // signature array, and the metadata dict go. They go to verification and
    // to the inline parts alone. The job carries only what the application
    // reads.
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

/// Verifies each inline part against its meta-entry and copies the bodies into
/// one [`Blob`].
///
/// The function works in part order and copies the bodies out of the metadata
/// dict, so the caller can drop the dict. The heap threshold is 128 KiB. If
/// the bodies total more, the blob is one anonymous temp file in `tmp/` of the
/// repository, mapped read-only. The job then keeps no copy of the bodies on
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

/// Verifies the detached signatures of a fetched delta over the raw superblock
/// bytes.
///
/// The policy of the pull decides. The sign-api engines that verify a commit
/// also verify the delta, because a delta carries sign-api signatures alone.
/// A delta with none of those signatures passes, and the pull holds the
/// commit that it delivers to the commit policy, as any other commit.
///
/// The call is in discovery, where the raw superblock bytes and the signature
/// array are available. The pull drops them after the call and does not keep
/// them until it ends.
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

/// Returns the delta map that the remote advertises for `to`, or `None` if it
/// advertises no map.
///
/// The map is the index file if the remote serves one. If it serves no index,
/// the map is the `ostree.static-deltas` map of the summary.
///
/// If the summary states `indexed-deltas`, the pull requests the index first.
/// A summary that omits the key counts as `true`, because that is the
/// repository default. A remote that holds deltas and no index (no reindex
/// ran) answers 404 for the index. The pull then reads the summary map.
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

/// Returns `true` if the summary states that the remote indexes its deltas.
///
/// A summary without the key counts as `true`, which is the repository
/// default.
fn indexed_deltas(summary: &Summary) -> bool {
    summary
        .metadata_value(INDEXED_DELTAS_KEY)
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

/// Returns the superblock digest that a delta map holds for `name`, or `None`
/// if the map does not name it.
fn map_digest(map: &Value, name: &str) -> Result<Option<Checksum>> {
    let Some(entry) = map.dict_get(name) else {
        return Ok(None);
    };
    entry_digest(name, entry).map(Some)
}

/// Returns the superblock digest in the map entry `entry` of the delta `name`.
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

/// Reads one part of a delta from `source` and applies it into the
/// transaction of the pull.
///
/// Discovery verified each inline part, so the function decompresses and
/// applies an inline part with no request.
///
/// A part file streams from the connection, or from the part file of the
/// source repository, under the size that the superblock declares for it.
/// The function verifies the body against the checksum that the superblock
/// states for the part. The verified body then decompresses into the
/// random-access blob that the operations read. The blob is on the heap while
/// it is small, and a mapped temp file when it is large.
///
/// A remote can answer a part request with more bytes than the part holds, or
/// with other bytes. A part file in a local source can grow or change. In
/// each case, the pull writes at most the declared size before it refuses the
/// part. The application of the blob writes each object under the checksum
/// that the superblock names, so a part that produces other objects fails.
///
/// `checks` are the mode checks of the pull. Each content object that a part
/// produces must pass them, as a loose fetch of that object must. After the
/// body of a part file passes the checksum, the function adds one part and
/// its declared size to `progress`. For a local source, it also adds that
/// size to the transferred count.
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
        // The size of the part in the superblock caps the body.
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
            // If the part file is longer than the declared size, the pull
            // refuses it before any read. The async reader reads ahead of the
            // bytes that the declared-size limit lets it write.
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

/// Fetches the part file at `path` into a verified, decompressed blob.
async fn fetch_part_blob(
    fetcher: &Fetcher,
    path: &str,
    entry: &DeltaPart,
    staging: &OwnedFd,
) -> Result<Blob> {
    // The superblock states the size of the part file, so the fetcher refuses
    // a larger `Content-Length` before the body arrives. It also stops a body
    // that passes the size as the bytes arrive.
    // If a body fails in transit, the pull fetches it again from the start
    // into a new blob. It does so while the retry count of the fetcher has a
    // repeat left.
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

    /// The digest lookup reads the `ay` in the variant, returns `None` for an
    /// absent delta, and refuses an entry of another type.
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
