//! The summary of a bucket repository.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use futures_lite::AsyncReadExt;
use ostrya_core::{Checksum, ObjectName, ObjectType, RepoMode, loose_path};
use sha2::{Digest, Sha256};

use super::state::{BucketRefs, summary_refs};
use super::{BucketRepo, ObjectListing, WriterLock};
use crate::config::RepoConfig;
use crate::delta::{MAX_SUPERBLOCK, parse_delta_dir};
use crate::deltagen::{DeltaDigest, delta_name, summary_delta_map};
use crate::error::Result;
use crate::object::MAX_METADATA_SIZE;
use crate::pull::drive::Slots;
use crate::repo::Repo;
use crate::sign::Signer;
use crate::summary::{
    CommitFacts, SummaryParts, build_summary, check_summary_size, resolve_last_modified,
    sign_summary_bytes, summary_floor,
};

/// The size of the chunks in which the digest of a superblock reads it:
/// 64 KiB.
const DIGEST_CHUNK: usize = 64 * 1024;

/// The inputs of [`BucketRepo::prepare_summary`].
pub(crate) struct SummaryInput<'a> {
    /// The refs that the summary lists.
    pub(crate) refs: &'a BucketRefs,
    /// The `config` of the bucket repository.
    pub(crate) config: &'a RepoConfig,
    /// A local repository that gives the facts of the commits that it
    /// holds. The caller checks that the bucket holds each of these commits.
    pub(crate) local: Option<&'a Repo>,
    /// The listing of the objects of the bucket. Each commit that the local
    /// repository does not hold must be in it, and its size in the listing
    /// bounds the read of the commit object. With `None`, a read of the
    /// commit decides.
    pub(crate) listing: Option<&'a ObjectListing>,
    /// The engines that sign the summary.
    pub(crate) signers: &'a [Arc<dyn Signer>],
    /// The `ostree.summary.last-modified` value, or `None` for the time of
    /// the run.
    pub(crate) last_modified: Option<u64>,
}

/// A summary and its signature file, which
/// [`BucketRepo::write_summary`] writes.
pub(crate) struct SignedSummary {
    /// The bytes of `summary`.
    bytes: Vec<u8>,
    /// The bytes of `summary.sig`, or `None` with no signer.
    signatures: Option<Vec<u8>>,
}

impl BucketRepo {
    /// Builds and signs the summary of `input`. The call writes nothing to
    /// the bucket.
    ///
    /// The summary is the root summary of a local repository with the same
    /// refs, commits, deltas, `config`, and `last-modified`, and with no
    /// `ostree-metadata` anchor commit: [`build_summary`] builds both.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if a ref names
    ///   a commit that the local repository does not hold and that the
    ///   listing does not hold, if a commit object of the bucket is larger
    ///   than its cap or than its size in the listing, or does not have the
    ///   checksum of its name, if a delta directory has a name that does not
    ///   decode, if a superblock is larger than its cap, or if the summary is
    ///   larger than its cap.
    /// - [`Error::Core`](crate::Error::Core) if a commit object does not
    ///   parse, or if `tombstone-commits` or `indexed-deltas` of the config
    ///   is not a boolean.
    /// - [`Error::Signature`](crate::Error::Signature) that names the key of
    ///   the signer if a signer fails, and the error of the build of the
    ///   signature file.
    /// - [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    ///   client.
    #[cfg_attr(not(feature = "push"), allow(dead_code))]
    pub(crate) async fn prepare_summary(&self, input: SummaryInput<'_>) -> Result<SignedSummary> {
        let (local, collections) = summary_refs(input.refs);
        check_summary_size(summary_floor(&local, &collections))?;
        let config = input.config;
        let tombstone_commits = config.tombstone_commits()?;
        let indexed_deltas = config.indexed_deltas()?;
        let last_modified = resolve_last_modified(input.last_modified)?;
        let facts = self.commit_facts(&local, &collections, &input).await?;
        let deltas = self.delta_digests().await?;
        let deltas = if deltas.is_empty() {
            None
        } else {
            Some(summary_delta_map(
                deltas
                    .iter()
                    .map(|delta| (delta.name.as_str(), &delta.digest)),
            )?)
        };
        let lookup = |commit: &Checksum| facts.get(commit);
        let bytes = build_summary(SummaryParts {
            local: &local,
            collections: &collections,
            facts: &lookup,
            deltas,
            mode: config.mode(),
            names_deltas: true,
            tombstone_commits,
            indexed_deltas,
            collection_id: config.collection_id(),
            last_modified,
            added: &[],
        })?;
        let signers: Vec<&dyn Signer> = input.signers.iter().map(|s| s.as_ref()).collect();
        let signatures = sign_summary_bytes(&bytes, &signers)
            .await
            .map_err(|(key, error)| match key {
                Some(key) => signer_error(&key, error),
                None => error,
            })?;
        Ok(SignedSummary { bytes, signatures })
    }

    /// Checks the writer lock, and writes `summary`, then `summary.sig` if a
    /// signer signed the summary.
    ///
    /// # Errors
    ///
    /// - The errors of [`WriterLock::check`].
    /// - [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    ///   client.
    #[cfg_attr(not(feature = "push"), allow(dead_code))]
    pub(crate) async fn write_summary(
        &self,
        lock: &WriterLock<'_>,
        summary: SignedSummary,
    ) -> Result<()> {
        lock.check().await?;
        self.bucket.put("summary", summary.bytes).await?;
        if let Some(signatures) = summary.signatures {
            self.bucket.put("summary.sig", signatures).await?;
        }
        Ok(())
    }

    /// Returns the facts of each commit of the refs `local` and
    /// `collections`.
    ///
    /// A commit that the local repository of `input` holds gives its facts
    /// from the local object store. Each other commit is read from the
    /// bucket, at most `max_outstanding` reads at a time, and checked
    /// against its name. With a listing in `input`, each of these commits
    /// must be in it, and the check runs before the first read.
    async fn commit_facts(
        &self,
        local: &[(String, Checksum)],
        collections: &BTreeMap<String, Vec<(String, Checksum)>>,
        input: &SummaryInput<'_>,
    ) -> Result<HashMap<Checksum, CommitFacts>> {
        let commits: HashSet<Checksum> = local
            .iter()
            .chain(collections.values().flatten())
            .map(|(_, commit)| *commit)
            .collect();
        let (held, remote): (HashSet<Checksum>, Vec<Checksum>) = match input.local {
            Some(repo) => {
                let repo = repo.clone();
                ostrya_rt::unblock(move || -> Result<_> {
                    let mut held = HashSet::new();
                    let mut remote = Vec::new();
                    for commit in commits {
                        if repo.has_object_blocking(ObjectType::Commit, &commit)? {
                            held.insert(commit);
                        } else {
                            remote.push(commit);
                        }
                    }
                    Ok((held, remote))
                })
                .await?
            }
            None => (HashSet::new(), commits.into_iter().collect()),
        };
        // The size of each commit object to read: its size in the listing,
        // or `None` with no listing.
        let mut sized = Vec::with_capacity(remote.len());
        for commit in remote {
            let size = match input.listing {
                Some(listing) => {
                    let name = ObjectName::new(commit, ObjectType::Commit);
                    let Some(size) = listing.objects.get(&name) else {
                        return Err(self.malformed(format!(
                            "a ref names the commit {commit}, which the bucket does not hold"
                        )));
                    };
                    Some(*size)
                }
                None => None,
            };
            sized.push((commit, size));
        }
        let mut facts = match input.local {
            Some(repo) if !held.is_empty() => repo.commit_facts(held).await?,
            _ => HashMap::new(),
        };
        let mut reads = Slots::new(self.max_outstanding);
        let mut pending = sized.into_iter();
        loop {
            while reads.has_room()
                && let Some((commit, size)) = pending.next()
            {
                reads.push(async move { (commit, self.read_commit_facts(&commit, size).await) });
            }
            let Some((commit, read)) = reads.next_ready().await else {
                break;
            };
            facts.insert(commit, read?);
        }
        Ok(facts)
    }

    /// Reads the commit object `commit` from the bucket, checks it against
    /// its name, and returns its facts.
    ///
    /// `listed` is the size of the object in the listing. The call refuses
    /// a listed size over the cap before the read, and reads at most the
    /// listed size.
    async fn read_commit_facts(
        &self,
        commit: &Checksum,
        listed: Option<u64>,
    ) -> Result<CommitFacts> {
        let key = format!(
            "objects/{}",
            loose_path(commit, ObjectType::Commit, RepoMode::Archive)
        );
        let cap = match listed {
            Some(size) if size > MAX_METADATA_SIZE => {
                return Err(self.malformed(format!(
                    "the commit object {key} is larger than {MAX_METADATA_SIZE} bytes"
                )));
            }
            Some(size) => size,
            None => MAX_METADATA_SIZE,
        };
        let bytes = match self.bucket.get(&key, cap).await {
            Ok(Some(object)) => object.bytes,
            Ok(None) => {
                return Err(self.malformed(format!(
                    "a ref names the commit {commit}, which the bucket does not hold"
                )));
            }
            Err(crate::remote::Error::LimitExceeded(_)) => {
                return Err(self.malformed(format!(
                    "the commit object {key} is larger than {cap} bytes"
                )));
            }
            Err(e) => return Err(e.into()),
        };
        let actual = Checksum::sha256(&bytes);
        if actual != *commit {
            return Err(
                self.malformed(format!("the commit object {key} has the checksum {actual}"))
            );
        }
        CommitFacts::parse(&bytes)
    }

    /// Returns each static delta of the repository with a superblock, sorted
    /// by name.
    ///
    /// The call lists `deltas/` and reads each key
    /// `deltas/<fanout>/<leaf>/superblock` as a stream, to take its SHA-256,
    /// at most `max_outstanding` reads at a time. The check of the name and
    /// of the listed size of each superblock runs before the first read. A
    /// superblock that is gone at its read is skipped, as the local scan
    /// skips a superblock that went away. Each other key under `deltas/` is
    /// ignored.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if the
    ///   directory names of a superblock key do not decode as a delta, or if
    ///   a superblock is larger than its cap.
    /// - [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    ///   client, and [`Error::Io`](crate::Error::Io) for a read that fails in
    ///   transit.
    #[cfg_attr(not(feature = "push"), allow(dead_code))]
    pub(crate) async fn delta_digests(&self) -> Result<Vec<DeltaDigest>> {
        let listing = self.bucket.list("deltas/").await?;
        let mut superblocks = Vec::new();
        for listed in &listing.objects {
            let Some(dir) = listed.key.strip_suffix("/superblock") else {
                continue;
            };
            let parsed = match dir.split('/').collect::<Vec<_>>()[..] {
                ["deltas", fanout, leaf] => parse_delta_dir(fanout, leaf).ok(),
                _ => None,
            };
            let Some((from, to)) = parsed else {
                return Err(self.malformed(format!(
                    "the superblock key '{}' names no delta",
                    listed.key.escape_debug()
                )));
            };
            if listed.size > MAX_SUPERBLOCK {
                return Err(self.superblock_too_large(&listed.key));
            }
            superblocks.push((from, to, listed.key.as_str()));
        }
        let mut out = Vec::new();
        let mut reads = Slots::new(self.max_outstanding);
        let mut pending = superblocks.into_iter();
        loop {
            while reads.has_room()
                && let Some((from, to, key)) = pending.next()
            {
                reads.push(async move { (from, to, self.superblock_digest(key).await) });
            }
            let Some((from, to, digest)) = reads.next_ready().await else {
                break;
            };
            let Some(digest) = digest? else {
                continue;
            };
            out.push(DeltaDigest {
                name: delta_name(from.as_ref(), &to),
                to,
                digest,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Returns the SHA-256 of the superblock at `key`, or `None` if the key
    /// holds no object. The call reads the superblock in chunks of 64 KiB.
    async fn superblock_digest(&self, key: &str) -> Result<Option<Checksum>> {
        let Some(mut stream) = self.bucket.get_stream(key).await? else {
            return Ok(None);
        };
        let mut hasher = Sha256::new();
        let mut chunk = vec![0u8; DIGEST_CHUNK];
        let mut total = 0u64;
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX_SUPERBLOCK {
                return Err(self.superblock_too_large(key));
            }
            hasher.update(&chunk[..n]);
        }
        Ok(Some(Checksum::from_bytes(hasher.finalize().into())))
    }

    /// Returns the error of the superblock at `key` that is larger than its
    /// cap.
    fn superblock_too_large(&self, key: &str) -> crate::Error {
        self.malformed(format!(
            "the superblock {} is larger than {MAX_SUPERBLOCK} bytes",
            key.escape_debug()
        ))
    }
}

/// Returns the error of the summary signer `key` that failed with `error`.
fn signer_error(key: &str, error: crate::Error) -> crate::Error {
    let what = format!("the summary signature with the {key} key");
    match error {
        crate::Error::Signature(message) => crate::Error::Signature(format!("{what}: {message}")),
        other => crate::Error::Signature(format!("{what}: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delta_directory_with_a_plus_decodes() {
        let mut bytes = [7u8; 32];
        bytes[0] = 0xfb;
        bytes[1] = 0xff;
        let to = Checksum::from_bytes(bytes);
        let b64 = to.to_base64_modified();
        assert!(b64.contains('+'), "{b64}");
        assert_eq!(parse_delta_dir(&b64[..2], &b64[2..]).unwrap(), (None, to));
        let from = Checksum::from_bytes([1u8; 32]);
        let from_b64 = from.to_base64_modified();
        assert_eq!(
            parse_delta_dir(&from_b64[..2], &format!("{}-{b64}", &from_b64[2..])).unwrap(),
            (Some(from), to)
        );
        assert!(parse_delta_dir("!!", "x").is_err());
    }
}
