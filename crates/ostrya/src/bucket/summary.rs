//! The summary of a bucket repository, and its update.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use futures_lite::AsyncReadExt;
use futures_lite::future::zip;
use ostrya_core::{Checksum, ObjectName, ObjectType};
use sha2::{Digest, Sha256};

use super::lock::{LockHolder, LockOperation, WriterLock};
use super::prune::UNBLOCK_SIZE;
use super::state::{BucketRefs, check_prefixes, summary_refs};
use super::{BucketRepo, invalid, object_key, release_on_error};
use crate::config::RepoConfig;
use crate::delta::{MAX_SUPERBLOCK, parse_delta_dir};
use crate::deltagen::{DeltaDigest, delta_name, summary_delta_map};
use crate::error::Result;
use crate::object::MAX_METADATA_SIZE;
use crate::pull::drive::Slots;
use crate::remote::s3::Address;
use crate::sign::Signer;
use crate::summary::{
    CommitFacts, SummaryParts, build_summary, check_summary_size, resolve_last_modified,
    sign_summary_bytes, summary_floor,
};

/// The size of the chunks in which the digest of a superblock reads it:
/// 64 KiB.
const DIGEST_CHUNK: usize = 64 * 1024;

/// The options of [`BucketRepo::update_summary`].
///
/// A caller sets the fields of [`default`](Default::default), because the
/// struct is `#[non_exhaustive]`.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct BucketSummaryOptions {
    /// The engines that sign the summary.
    ///
    /// Each engine signs once, in order, and `summary.sig` holds the
    /// signatures. Empty by default, which writes no `summary.sig`. A bucket
    /// repository that holds a `summary.sig` refuses an update with no
    /// signer.
    pub summary_signers: Vec<Arc<dyn Signer>>,
    /// The `ostree.summary.last-modified` timestamp, in seconds since the Unix
    /// epoch (UTC).
    ///
    /// If `None`, the update uses the current time, as
    /// [`SummaryOptions::last_modified`](crate::SummaryOptions::last_modified)
    /// does. A set value makes the output reproducible.
    pub last_modified: Option<u64>,
    /// Remove the writer lock of another writer before the run takes its
    /// own, as [`BucketRepo::lock`] states.
    pub break_lock: bool,
}

impl std::fmt::Debug for BucketSummaryOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let signers: Vec<&str> = self
            .summary_signers
            .iter()
            .map(|signer| signer.name())
            .collect();
        f.debug_struct("BucketSummaryOptions")
            .field("summary_signers", &signers)
            .field("last_modified", &self.last_modified)
            .field("break_lock", &self.break_lock)
            .finish()
    }
}

/// The result of [`BucketRepo::update_summary`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BucketSummaryReport {
    /// The number of refs that the summary lists: the refs of field 0 and
    /// the refs of `ostree.summary.collection-map`.
    pub refs: usize,
    /// The number of static deltas that `ostree.static-deltas` lists.
    pub deltas: usize,
    /// The name of the engine of each signer, in the order of the
    /// signatures, as [`Signer::name`](crate::Signer::name) gives it. Empty
    /// if the update wrote no `summary.sig`.
    pub signers: Vec<String>,
    /// The `ostree.summary.last-modified` value of the summary.
    pub last_modified: u64,
    /// The holder of the lock that the break of the lock deleted, or `None`
    /// if the run deleted no lock.
    ///
    /// The holder is reported on success alone. A run that breaks the lock
    /// and then fails returns its error, and the holder of the deleted lock
    /// is not in it.
    pub broken_lock: Option<LockHolder>,
}

/// The inputs of [`BucketRepo::prepare_summary`].
struct SummaryInput<'a> {
    /// The refs that the summary lists.
    refs: &'a BucketRefs,
    /// The `config` of the bucket repository.
    config: &'a RepoConfig,
    /// The engines that sign the summary.
    signers: &'a [Arc<dyn Signer>],
    /// The `ostree.summary.last-modified` value, or `None` for the time of
    /// the run.
    last_modified: Option<u64>,
}

/// One superblock key of a bucket repository, whose directory names decode
/// as a delta.
pub(crate) struct SuperblockKey {
    /// The name of the delta, as [`DeltaDigest`] names it.
    pub(crate) name: String,
    /// The target commit of the delta.
    to: Checksum,
    /// The key `deltas/<fanout>/<leaf>/superblock`.
    key: String,
}

/// A summary and its signature file, which
/// [`BucketRepo::write_summary`] writes.
struct SignedSummary {
    /// The bytes of `summary`.
    bytes: Vec<u8>,
    /// The bytes of `summary.sig`, or `None` with no signer.
    signatures: Option<Vec<u8>>,
    /// The number of refs that the summary lists.
    refs: usize,
    /// The number of static deltas that the summary lists.
    deltas: usize,
    /// The `ostree.summary.last-modified` value of the summary.
    last_modified: u64,
}

impl BucketRepo {
    /// Writes the summary of the bucket repository, and signs it with the
    /// signers of `opts`.
    ///
    /// The summary is the root summary of the repository. It holds the refs
    /// of `refs/heads/` in field 0, and the refs of each `refs/mirrors/ID/`
    /// in `ostree.summary.collection-map` under `ID`. It names each static
    /// delta with a superblock. Its bytes are the bytes of the root summary
    /// that [`Repo::regenerate_summaries`](crate::Repo::regenerate_summaries)
    /// writes for a local repository with the same refs, commits, deltas,
    /// `config`, and `last_modified`, and with no `ostree-metadata` anchor
    /// commit. The update writes no summary of an auth item, no key under
    /// `extensions/ostrya/summary/`, and no anchor commit. It writes the
    /// summary each time it runs, also when the refs did not change.
    ///
    /// # Steps
    ///
    /// 1. The read of the `config`, by the strict rule of an absent key.
    /// 2. The take of the writer lock for [`LockOperation::Summary`] with
    ///    [`break_lock`](BucketSummaryOptions::break_lock).
    /// 3. The refs: one list of `refs/` and a read of each ref file. With no
    ///    signer in `opts`, the probe of `summary.sig` runs at the same time.
    ///    The probe reads the headers of the key alone. Only an answer 404
    ///    `NoSuchKey` is an absent key. With a signer, the update sends no
    ///    request for `summary.sig` before its write.
    /// 4. The refusals of the ref names and of the signers, below.
    /// 5. At the same time: the read of the commit object of each ref, and
    ///    the list of `deltas/` with the read of each superblock as a
    ///    stream, to take its SHA-256. Each of the two runs at most
    ///    `max_outstanding` reads at a time. Each read of a commit takes at
    ///    most the cap of a metadata object, and the update checks the
    ///    SHA-256 of each commit against its name.
    /// 6. The build and the signatures of the summary.
    /// 7. A check of the lock, the write of `summary`, and then the write of
    ///    `summary.sig` if a signer signed the summary.
    /// 8. The release of the lock.
    ///
    /// The update sends no list of `objects/`, and reads no
    /// partial-commit marker. A commit with a marker under `state/` is in
    /// the summary as each other commit. A bucket repository with no ref
    /// gets a summary with an empty list of refs.
    ///
    /// `ostree.summary.mode`, `ostree.summary.tombstone-commits`,
    /// `ostree.summary.indexed-deltas`, and `ostree.summary.collection-id`
    /// come from the `[core]` group of the `config` of the bucket, as the
    /// local summary takes them from a local `config`. A delta directory
    /// with no superblock is not in `ostree.static-deltas`. A superblock that
    /// is gone at its read, with an answer 404 `NoSuchKey`, is not in it
    /// either. Each other answer 404 to the read of a superblock fails the
    /// update.
    ///
    /// # Signers
    ///
    /// A bucket repository that holds a `summary.sig` refuses an update with
    /// no signer. The refusal changes nothing in the bucket but the probe key
    /// of the writer lock. So an update never makes a signed bucket
    /// repository unsigned. An update with a signer writes `summary.sig` in
    /// place of the old one. The update never deletes `summary.sig`.
    ///
    /// Between the two writes of step 7, a reader sees the new summary and
    /// the old `summary.sig`. A reader that verifies the summary refuses it
    /// in that window, because the old signatures do not cover the new
    /// bytes. A read after the update ends finds a matching pair.
    ///
    /// # Errors
    ///
    /// - [`Error::Remote`](crate::Error::Remote) with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the bucket
    ///   repository has no `config`. The update then takes no lock.
    /// - [`Error::Remote`](crate::Error::Remote) with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the bucket
    ///   repository holds a `summary.sig` and `opts` has no signer, or if a
    ///   ref name of `refs/heads/` or of one `refs/mirrors/ID/` is a
    ///   directory of another ref name of the same directory, as `a` is of
    ///   `a/b`.
    /// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if the
    ///   `config` breaks a rule of a bucket repository, if a key under
    ///   `refs/` is no ref key, if a ref file is malformed or is gone at its
    ///   read, if a ref names a commit that the bucket does not hold, if a
    ///   commit object is larger than its cap or does not have the checksum
    ///   of its name, if a superblock key names no delta, if a superblock is
    ///   larger than its cap, or if the summary is larger than its cap.
    /// - [`Error::Core`](crate::Error::Core) if a commit object does not
    ///   parse.
    /// - [`Error::Signature`](crate::Error::Signature) if a signer fails. The
    ///   message names the engine of the signer.
    /// - The errors of [`lock`](BucketRepo::lock). A lock of another writer
    ///   fails the update before it reads a ref.
    /// - [`Error::BucketLockLost`](crate::Error::BucketLockLost) if the check
    ///   of the lock or the release fails. A failed check stops the update
    ///   before it writes `summary`. The update then releases no lock.
    /// - [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    ///   client, also for an answer 404 that is not `NoSuchKey` to the probe
    ///   of `summary.sig` or to the read of a superblock, and
    ///   [`Error::Io`](crate::Error::Io) for a read of a superblock that
    ///   fails in transit.
    ///
    /// A failure before step 7 changes nothing in the bucket but the probe
    /// key of the writer lock. A failure between the two writes of step 7
    /// leaves the window above, and a run again writes a matching pair.
    /// After each failure other than a lost lock or a lock of another
    /// writer, the update releases its lock and drops an error of that
    /// release.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use ostrya::Ed25519Signer;
    /// use ostrya::bucket::{BucketRepo, BucketSummaryOptions};
    /// use ostrya::remote::s3::{Environment, S3Endpoint, Settings};
    /// # async fn run(secret_b64: &str) -> ostrya::Result<()> {
    /// let endpoint =
    ///     S3Endpoint::resolve("s3://builds/exampleos", &Settings::default(), &Environment::Process)
    ///         .await?;
    /// let repo = BucketRepo::open(&endpoint).await?;
    /// let mut opts = BucketSummaryOptions::default();
    /// opts.summary_signers = vec![Arc::new(Ed25519Signer::from_base64(secret_b64)?)];
    /// let report = repo.update_summary(&opts).await?;
    /// println!("the summary lists {} refs", report.refs);
    /// # Ok(()) }
    /// ```
    pub async fn update_summary(&self, opts: &BucketSummaryOptions) -> Result<BucketSummaryReport> {
        let Some(config) = self.read_config_strict().await? else {
            return Err(invalid(format!(
                "the bucket repository {} has no config; init it first",
                self.address()
            )));
        };
        let lock = self.lock(LockOperation::Summary, opts.break_lock).await?;
        let broken_lock = lock.broken().cloned();
        let mut report = match self.summary_update(&config, opts, &lock).await {
            Ok(report) => report,
            Err(e) => return Err(release_on_error(lock, e).await),
        };
        lock.release().await?;
        report.broken_lock = broken_lock;
        Ok(report)
    }

    /// Runs the steps 3 to 7 of [`update_summary`](BucketRepo::update_summary)
    /// under `lock`. The report holds no holder of a broken lock.
    async fn summary_update(
        &self,
        config: &RepoConfig,
        opts: &BucketSummaryOptions,
        lock: &WriterLock<'_>,
    ) -> Result<BucketSummaryReport> {
        let (refs, signed) = if opts.summary_signers.is_empty() {
            let (refs, signed) =
                zip(self.read_refs(config.collection_id()), self.is_signed()).await;
            (refs?, signed?)
        } else {
            (self.read_refs(config.collection_id()).await?, false)
        };
        check_prefixes(&refs.heads)?;
        for dir in refs.mirrors.values() {
            check_prefixes(dir)?;
        }
        refuse_unsigned(self.address(), signed, opts.summary_signers.len())?;
        let summary = self
            .prepare_summary(SummaryInput {
                refs: &refs,
                config,
                signers: &opts.summary_signers,
                last_modified: opts.last_modified,
            })
            .await?;
        let report = BucketSummaryReport {
            refs: summary.refs,
            deltas: summary.deltas,
            signers: opts
                .summary_signers
                .iter()
                .map(|signer| signer.name().to_owned())
                .collect(),
            last_modified: summary.last_modified,
            broken_lock: None,
        };
        self.write_summary(lock, summary).await?;
        Ok(report)
    }

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
    ///   a commit that the bucket does not hold, if a commit object is larger
    ///   than its cap or does not have the checksum of its name, if a delta
    ///   directory has a name that does not decode, if a superblock is larger
    ///   than its cap, or if the summary is larger than its cap.
    /// - [`Error::Core`](crate::Error::Core) if a commit object does not
    ///   parse, or if `tombstone-commits` or `indexed-deltas` of the config
    ///   is not a boolean.
    /// - [`Error::Signature`](crate::Error::Signature) that names the key of
    ///   the signer if a signer fails, and the error of the build of the
    ///   signature file.
    /// - [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    ///   client.
    async fn prepare_summary(&self, input: SummaryInput<'_>) -> Result<SignedSummary> {
        let (local, collections) = summary_refs(input.refs);
        check_summary_size(summary_floor(&local, &collections))?;
        let config = input.config;
        let tombstone_commits = config.tombstone_commits()?;
        let indexed_deltas = config.indexed_deltas()?;
        let last_modified = resolve_last_modified(input.last_modified)?;
        let (facts, deltas) = zip(
            self.commit_facts(&local, &collections),
            self.delta_digests(),
        )
        .await;
        let (facts, deltas) = (facts?, deltas?);
        let delta_count = deltas.len();
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
        Ok(SignedSummary {
            bytes,
            signatures,
            refs: local.len() + collections.values().map(Vec::len).sum::<usize>(),
            deltas: delta_count,
            last_modified,
        })
    }

    /// Checks the writer lock, and writes `summary`, then `summary.sig` if a
    /// signer signed the summary. The call never deletes `summary.sig`.
    ///
    /// # Errors
    ///
    /// - The errors of [`WriterLock::check`].
    /// - [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    ///   client.
    async fn write_summary(&self, lock: &WriterLock<'_>, summary: SignedSummary) -> Result<()> {
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
    /// Each commit is read from the bucket, at most `max_outstanding` reads
    /// at a time, and checked against its name.
    async fn commit_facts(
        &self,
        local: &[(String, Checksum)],
        collections: &BTreeMap<String, Vec<(String, Checksum)>>,
    ) -> Result<HashMap<Checksum, CommitFacts>> {
        let commits: BTreeSet<Checksum> = local
            .iter()
            .chain(collections.values().flatten())
            .map(|(_, commit)| *commit)
            .collect();
        let mut facts = HashMap::with_capacity(commits.len());
        let mut reads = Slots::new(self.max_outstanding);
        let mut pending = commits.into_iter();
        loop {
            while reads.has_room()
                && let Some(commit) = pending.next()
            {
                reads.push(async move { (commit, self.read_commit_facts(commit).await) });
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
    /// The read takes at most the cap of a metadata object. The check and
    /// the parse of an object larger than 1 MiB run on the blocking pool.
    async fn read_commit_facts(&self, commit: Checksum) -> Result<CommitFacts> {
        let key = object_key(&ObjectName::new(commit, ObjectType::Commit));
        let bytes = match self.bucket.get(&key, MAX_METADATA_SIZE).await {
            Ok(Some(object)) => object.bytes,
            Ok(None) => {
                return Err(self.malformed(format!(
                    "a ref names the commit {commit}, which the bucket does not hold"
                )));
            }
            Err(crate::remote::Error::LimitExceeded(_)) => {
                return Err(self.malformed(format!(
                    "the commit object {key} is larger than {MAX_METADATA_SIZE} bytes"
                )));
            }
            Err(e) => return Err(e.into()),
        };
        let large = bytes.len() > UNBLOCK_SIZE;
        let check = move || {
            let actual = Checksum::sha256(&bytes);
            let facts = (actual == commit).then(|| CommitFacts::parse(&bytes));
            (actual, facts)
        };
        let (actual, facts) = if large {
            ostrya_rt::unblock(check).await
        } else {
            check()
        };
        match facts {
            Some(facts) => facts,
            None => {
                Err(self.malformed(format!("the commit object {key} has the checksum {actual}")))
            }
        }
    }

    /// Returns each static delta of the repository with a superblock, sorted
    /// by name.
    ///
    /// The call lists `deltas/` and reads each key
    /// `deltas/<fanout>/<leaf>/superblock` as a stream, to take its SHA-256,
    /// at most `max_outstanding` reads at a time. The check of the name and
    /// of the listed size of each superblock runs before the first read.
    /// Each read takes the strict rule of an absent key. A superblock that
    /// is gone at its read, with an answer 404 `NoSuchKey`, is skipped, as
    /// the local scan skips a superblock that went away. Each other 404
    /// fails the call. Each other key under `deltas/` is ignored.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if the
    ///   directory names of a superblock key do not decode as a delta, or if
    ///   a superblock is larger than its cap.
    /// - [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    ///   client, also for a 404 that is not an absent key, and
    ///   [`Error::Io`](crate::Error::Io) for a read that fails in transit.
    pub(crate) async fn delta_digests(&self) -> Result<Vec<DeltaDigest>> {
        let keys = self.superblock_keys().await?;
        self.superblock_digests(keys).await
    }

    /// Lists `deltas/`, and returns the key of each superblock
    /// `deltas/<fanout>/<leaf>/superblock`, sorted by the name of its delta.
    /// Each other key under `deltas/` is ignored. The call reads no
    /// superblock.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if the
    ///   directory names of a superblock key do not decode as a delta, or if
    ///   the listed size of a superblock is larger than its cap.
    /// - [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    ///   client.
    pub(crate) async fn superblock_keys(&self) -> Result<Vec<SuperblockKey>> {
        let listing = self.bucket.list("deltas/").await?;
        let mut keys = Vec::new();
        for listed in listing.objects {
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
            keys.push(SuperblockKey {
                name: delta_name(from.as_ref(), &to),
                to,
                key: listed.key,
            });
        }
        keys.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(keys)
    }

    /// Reads each superblock of `keys` as a stream, to take its SHA-256, at
    /// most `max_outstanding` reads at a time, and returns the deltas, sorted
    /// by name.
    ///
    /// Each read takes the strict rule of an absent key of
    /// [`Bucket::get_stream_strict`](crate::remote::s3::Bucket::get_stream_strict).
    /// A superblock that is gone at its read, by that rule, is skipped.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if a
    ///   superblock is larger than its cap.
    /// - [`Error::Remote`](crate::Error::Remote) for an error of the bucket
    ///   client, and [`Error::Io`](crate::Error::Io) for a read that fails in
    ///   transit.
    pub(crate) async fn superblock_digests(
        &self,
        keys: Vec<SuperblockKey>,
    ) -> Result<Vec<DeltaDigest>> {
        let mut out = Vec::new();
        let mut reads = Slots::new(self.max_outstanding);
        let mut pending = keys.into_iter();
        loop {
            while reads.has_room()
                && let Some(key) = pending.next()
            {
                reads.push(async move {
                    let digest = self.superblock_digest(&key.key).await;
                    (key, digest)
                });
            }
            let Some((key, digest)) = reads.next_ready().await else {
                break;
            };
            let Some(digest) = digest? else {
                continue;
            };
            out.push(DeltaDigest {
                name: key.name,
                to: key.to,
                digest,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Returns the SHA-256 of the superblock at `key`, or `None` if the key
    /// holds no object, by the strict rule of an absent key. The call reads
    /// the superblock in chunks of 64 KiB.
    async fn superblock_digest(&self, key: &str) -> Result<Option<Checksum>> {
        let Some(mut stream) = self.bucket.get_stream_strict(key).await? else {
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

/// Refuses an update of the summary of the bucket repository at `address`
/// with `signers` signers, when the repository holds a `summary.sig`, as
/// `signed` states, and the update has no signer.
fn refuse_unsigned(address: &Address, signed: bool, signers: usize) -> Result<()> {
    if signed && signers == 0 {
        return Err(invalid(format!(
            "the bucket repository {address} holds a summary.sig, and an update of its summary \
             with no summary signer would leave a summary that no signature covers; give a \
             summary signer"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_bucket_refuses_an_update_with_no_signer() {
        let address = Address::parse("s3://bkt/repo").unwrap();
        refuse_unsigned(&address, false, 0).unwrap();
        refuse_unsigned(&address, false, 1).unwrap();
        refuse_unsigned(&address, true, 2).unwrap();
        match refuse_unsigned(&address, true, 0) {
            Err(crate::Error::Remote(crate::remote::Error::InvalidInput(message))) => {
                assert!(
                    message.starts_with("the bucket repository s3://bkt/repo holds a summary.sig"),
                    "{message}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_failed_signer_names_its_engine() {
        let error = signer_error("ed25519", crate::Error::Signature("no key".into()));
        match error {
            crate::Error::Signature(message) => assert_eq!(
                message,
                "the summary signature with the ed25519 key: no key"
            ),
            other => panic!("{other:?}"),
        }
        let error = signer_error("gpg", crate::Error::InvalidFormat("bad".into()));
        match error {
            crate::Error::Signature(message) => {
                assert!(
                    message.starts_with("the summary signature with the gpg key: "),
                    "{message}"
                );
                assert!(message.ends_with("bad"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }

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
