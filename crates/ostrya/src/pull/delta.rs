//! Delta-accelerated pull: finding a static delta on a remote, fetching it, and
//! applying it into the pull's transaction.
//!
//! A remote that publishes static deltas can deliver a commit as one delta
//! instead of one request per object. What a pull asks for, in order: the delta
//! index for the target commit, the delta's `superblock`, then the objects the
//! delta hands over loose and its numbered part files. The commit object itself
//! rides in the superblock and is staged from there, so no `.commit` request
//! follows.
//!
//! Which delta. A pull looks for exactly one: `<from>-<to>` where `from` is the
//! commit the ref being pulled names in this repository, and the from-scratch
//! `<to>` where the ref names none. A from-to delta patches against the source
//! commit's objects, so the source commit has to be here complete for the delta
//! to apply; a ref whose commit is absent or partial is treated as naming none. A
//! repository that holds the ref's commit does not take a from-scratch delta,
//! which would re-deliver every object of the target including the ones it
//! already holds -- the objects it is missing are fetched loose instead. This is
//! what the tool was observed to do.
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
//! [`verify`](super::verify). Every object a part produces is written with its
//! expected checksum asserted, which is the read path's own rule. Each part is
//! taken off the connection under the size its meta-entry declares and hashed
//! against the checksum that entry names before it is decompressed, so what a
//! remote can drive onto the staging filesystem for one part is the size the
//! superblock states. A superblock the remote does not hold (a stale
//! advertisement) is a 404, which leaves the pull to fetch the objects loose.
//!
//! Concurrency. Two part fetches are in flight at once ([`PART_CAP`]), whatever
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

use ostrya_core::{Checksum, ObjectName, ObjectType, Type, Value, from_bytes};

use crate::delta::{
    Fallback, MAX_SUPERBLOCK, MetaEntry, Superblock, apply_part, decode_part_stream,
};
use crate::deltagen::{
    STATIC_DELTAS_KEY, SUPERBLOCK_FILE, delta_index_relative_path, delta_name, delta_relative_dir,
};
use crate::error::{Error, Result};
use crate::fetch::{FetchRequest, Fetched, Fetcher, Priority};
use crate::object::MAX_METADATA_SIZE;
use crate::pull::verify::Verification;
use crate::pull::{ModeChecks, PullFlags, PullOptions, refspec};
use crate::read::CommitState;
use crate::repo::Repo;
use crate::summary::{INDEXED_DELTAS_KEY, Summary};
use crate::transaction::Transaction;

use super::http::fetch_optional;

/// How many delta parts one pull fetches at once.
pub(crate) const PART_CAP: usize = 2;

/// A delta one pull applies for one target commit.
///
/// A job is built during discovery and lives until the pull returns, so a pull
/// retains one of these per target commit. It holds what application reads and
/// nothing else: the superblock's raw bytes and its signature array are read at
/// acquisition and dropped there, so what a job retains is bounded by the target
/// commit -- one meta-entry per part, listing every object the delta produces --
/// rather than by the superblock size a remote chooses.
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
    meta_entries: Vec<MetaEntry>,
    /// The objects the delta references and hands over loose.
    fallbacks: Vec<Fallback>,
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

    /// How many part files the delta carries.
    pub(crate) fn parts(&self) -> usize {
        self.meta_entries.len()
    }
}

/// Find the delta to pull each target commit with, keyed by that commit.
///
/// A commit with no entry is pulled object by object. Discovery is skipped for a
/// commit this repository already holds complete, for a
/// [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull, whose plan is the commit objects
/// alone, and when [`disable_static_deltas`](PullOptions::disable_static_deltas)
/// is set.
///
/// Two refs naming one commit share one delta, since the plan fetches that commit
/// once. The source commit is read from the ref this repository holds, so the
/// refs are tried in the order they were requested and the first that yields a
/// delta decides.
pub(crate) async fn discover(
    repo: &Repo,
    fetcher: &Fetcher,
    summary: Option<&Summary>,
    targets: &[(String, Checksum)],
    opts: &PullOptions,
    ref_prefix: Option<&str>,
    verification: &Verification,
) -> Result<HashMap<Checksum, DeltaJob>> {
    let mut jobs = HashMap::new();
    if opts.disable_static_deltas || opts.flags.contains(PullFlags::COMMIT_ONLY) {
        return Ok(jobs);
    }
    for (ref_name, to) in targets {
        if jobs.contains_key(to) || complete_here(repo, to).await? {
            continue;
        }
        let from = source_commit(repo, ref_name, to, ref_prefix).await?;
        if let Some(job) = discover_one(fetcher, summary, from, *to, opts, verification).await? {
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

/// The commit a from-to delta would patch against: the one the ref being pulled
/// names in this repository, when this repository holds it complete.
///
/// A ref that names nothing, or names a commit whose objects are not all here,
/// yields `None`, and the pull looks for a from-scratch delta instead: a delta
/// patches against the source commit's objects, and the ones a partial commit is
/// missing are what a part would fail to read. A ref that already names the
/// target yields `None` as well, since a delta from a commit to itself carries
/// nothing.
async fn source_commit(
    repo: &Repo,
    ref_name: &str,
    to: &Checksum,
    ref_prefix: Option<&str>,
) -> Result<Option<Checksum>> {
    let Some(current) = repo.resolve_ref_tip(&refspec(ref_prefix, ref_name)).await? else {
        return Ok(None);
    };
    if current == *to || !complete_here(repo, &current).await? {
        return Ok(None);
    }
    Ok(Some(current))
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

/// Find and read the delta from `from` to `to`, or `None` when the remote
/// publishes none.
async fn discover_one(
    fetcher: &Fetcher,
    summary: Option<&Summary>,
    from: Option<Checksum>,
    to: Checksum,
    opts: &PullOptions,
    verification: &Verification,
) -> Result<Option<DeltaJob>> {
    let name = delta_name(from.as_ref(), &to);
    let advertised = match summary {
        None => Advertisement::Unlisted,
        Some(summary) => match advertised_map(fetcher, summary, &to).await? {
            Some(map) => Advertisement::Map(map),
            None => Advertisement::Nothing,
        },
    };
    if opts.require_static_deltas && !matches!(advertised, Advertisement::Map(_)) {
        return Err(Error::Pull(format!(
            "a static delta was required to pull {to}, but the remote advertises \
             neither a delta index nor summary deltas"
        )));
    }

    let digest = match &advertised {
        // A map that does not name this delta ends the search: the remote
        // publishes deltas and none of them produces this commit from what is
        // here, so the objects are fetched loose.
        Advertisement::Map(map) => match map_digest(map, &name)? {
            Some(digest) => Some(digest),
            None => return Ok(None),
        },
        // Nothing states a digest, so the delta is asked for by name and its
        // superblock arrives unchecked against an advertisement. What it produces
        // is still checked object by object as the parts are applied.
        Advertisement::Unlisted => None,
        Advertisement::Nothing => return Ok(None),
    };

    let path = format!(
        "{}/{SUPERBLOCK_FILE}",
        delta_relative_dir(from.as_ref(), &to)
    );
    // A superblock the remote no longer holds is a stale advertisement, which
    // leaves the objects to be fetched loose.
    let Some(bytes) = fetch_optional(fetcher, &path, Priority::High, MAX_SUPERBLOCK).await? else {
        return Ok(None);
    };
    if let Some(expected) = digest {
        let actual = Checksum::sha256(&bytes);
        if actual != expected {
            return Err(Error::ChecksumMismatch { expected, actual });
        }
    }

    let superblock = Superblock::parse(bytes)?;
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
    // Destructured, so the compiler establishes that the raw bytes and the
    // signature array reach verification and go no further: what the job carries
    // is what application reads.
    let Superblock {
        commit_bytes,
        meta_entries,
        fallbacks,
        signatures,
        superblock_bytes,
        ..
    } = superblock;
    verify_fetched_delta(verification, &name, &superblock_bytes, signatures.as_ref()).await?;
    Ok(Some(DeltaJob {
        dir: delta_relative_dir(from.as_ref(), &to),
        name,
        commit_bytes,
        meta_entries,
        fallbacks,
    }))
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
    fetcher: &Fetcher,
    summary: &Summary,
    to: &Checksum,
) -> Result<Option<Value>> {
    if indexed_deltas(summary) {
        let path = delta_index_relative_path(to);
        if let Some(bytes) =
            fetch_optional(fetcher, &path, Priority::High, MAX_METADATA_SIZE).await?
        {
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
    let bytes = entry
        .as_variant()
        .map(|(_, value)| value)
        .and_then(Value::as_bytes)
        .ok_or_else(|| {
            Error::InvalidFormat(format!(
                "the remote advertises static delta {name} with no superblock digest"
            ))
        })?;
    Ok(Some(Checksum::from_ay(bytes)?))
}

/// Fetch one part of a delta and apply it into the pull's transaction.
///
/// The part streams off the connection under the size the superblock declares for
/// it and is hashed against the superblock's checksum for it; the verified body
/// then decompresses into the random-access blob the operations read, which is on
/// the heap while it is small and a mapped temp file when it is not. A remote that
/// answers a part request with more than the part is, or with other bytes
/// altogether, therefore writes at most the declared size before the refusal.
/// Applying the blob produces the part's objects, each written under the checksum
/// the superblock names, so a part that produces something else fails there.
///
/// `checks` are the pull's mode checks, which every content object a part
/// produces is held to exactly as a loose fetch of that object would be.
pub(crate) async fn fetch_part(
    txn: &Transaction,
    fetcher: &Fetcher,
    job: &DeltaJob,
    index: usize,
    checks: ModeChecks,
) -> Result<()> {
    let entry = job.meta_entries.get(index).ok_or_else(|| {
        Error::InvalidFormat(format!(
            "static delta {}: no part {index} in its superblock",
            job.name
        ))
    })?;
    let path = format!("{}/{index}", job.dir);
    // The superblock states the part file's size, so the fetcher refuses a
    // `Content-Length` above it before the body arrives and stops a body that
    // passes it as the bytes land.
    let request = FetchRequest {
        path: &path,
        priority: Priority::High,
        validators: None,
        max_size: Some(entry.size),
    };
    let body = match fetcher.fetch(request).await? {
        Fetched::Body(body) => body,
        Fetched::NotModified => {
            return Err(Error::Fetch(format!(
                "{path}: the remote answered 304 to an unconditional request"
            )));
        }
    };
    let staging = txn.staging_fd().try_clone_to_owned()?;
    let blob = decode_part_stream(body, entry, &staging).await?;
    apply_part(txn, &blob, &entry.objects, &staging, checks).await
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
