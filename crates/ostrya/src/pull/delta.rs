//! Static deltas in a pull: the search for a delta on the source and its
//! application into the transaction of the pull.
//!
//! A [`DeltaSource`] is the remote of the pull, over HTTP or over ssh, or the
//! directory of the source repository of a local pull. The pull reads the same
//! paths from each source, under the same size caps. [`PART_CAP`] sets the
//! limit of part fetches in flight from a remote. The rules that a caller
//! sees are on `Repo::pull`, under `# Static deltas`, and on
//! `PullOptions::require_static_deltas`.
//!
//! `PullOptions::static_deltas` replaces the search with a list of deltas
//! that the caller gives. The sibling module `chain` plans chains of deltas
//! from such a list, and [`discover`] then fetches the steps of the chains. A
//! pull from a remote runs its plan one time for each level of intermediate
//! commits, with the jobs of that level, and then one time for the targets.
//! A local pull applies and imports each level of intermediate commits in
//! turn, and then the targets. It parses, applies, and drops the job of one
//! step of a list at a time, so the heap holds one job of the list.
//!
//! The discovery of a chain keeps one record for each step of the plan, and
//! drops each parsed superblock after its checks. So the heap holds one
//! parsed superblock at a time. A record from a remote keeps the raw
//! superblock in one unlinked temp file in `tmp/` of the repository, with no
//! map. Discovery writes the bytes to the file after the digest check and
//! before the other checks. A failed check stops the pull, so each record
//! that discovery keeps holds verified bytes. The file has a size limit,
//! [`MAX_RECORD_FILE`]. A discovery that would pass it fails the pull. A
//! record from a local source keeps no bytes, and the parse of a level reads
//! the superblock from the source again and checks its digest. The parse of a
//! level gives the jobs of that level alone, and the parse of a record gives
//! the job of one step.
//!
//! For the commit of each step, discovery fetches the `.commitmeta` from a
//! remote. From a local source it reads the `.commitmeta` only if the policy
//! checks commits. Then it checks the signatures of the commit that the
//! superblock carries. For a remote source, if the check parsed the
//! `.commitmeta` and the pull has a filter, discovery then runs the detached
//! metadata filter of the pull over that parse, and the record file keeps the
//! result. For a target, it also makes the ref-binding check of
//! each requested ref that names it. For a remote source it also makes the
//! timestamp check of each of these refs, and for a local source it makes
//! none, because a local pull has none. So a refused target costs no part.
//!
//! The pull checks no commit of the last plan a second time. A commit that
//! has no record in the last plan gets the check of the pull when the pull
//! fetches it. This is a target whose chain a later plan drops, or a dropped
//! intermediate commit that a depth walk reaches as a parent. If discovery
//! fetched the `.commitmeta` of such a commit, the pull requests it again.
//!
//! Over HTTP, discovery requests the `.commitmeta` after the superblock. On a
//! stream session, discovery sends the request of the superblock and the
//! request of the `.commitmeta` as one pair, as [`fetch_step`] states. The
//! reply of the `.commitmeta` arrives while discovery parses the superblock,
//! so the heap then holds one superblock and one `.commitmeta`: up to
//! [`MAX_SUPERBLOCK`] plus [`MAX_METADATA_SIZE`] bytes, and the parse of the
//! superblock. A missing superblock costs its paired `.commitmeta` request.
//! If a later plan reaches the same commit, discovery requests and counts the
//! `.commitmeta` again, so the metadata count can be one higher than over
//! HTTP for each such superblock.
//!
//! If the source does not hold a superblock of the plan, discovery excludes
//! that delta, plans again, and fetches only the steps that it did not fetch
//! before. The planner limits the number of deltas that one discovery plans
//! again around.
//!
//! The digest check, the parse, and the check of the inline parts of a
//! superblock run on the blocking pool.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use ostrya_core::{Checksum, Commit, ObjectName, ObjectType, RepoMode, Value};
use ostrya_rt::FileReader;
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::delta::{
    Blob, DeltaFallback, DeltaPart, DeltaSuperblock, MAX_SUPERBLOCK, apply_part, carries_image,
    check_inline_part, concat_to_blob, decode_inline_part, decode_part_stream, image_key,
    inline_part_at, open_rw_temp, verify_inline_part,
};
use crate::deltagen::{
    STATIC_DELTAS_KEY, SUPERBLOCK_FILE, delta_index_relative_path, delta_name, delta_relative_dir,
    index_delta_map, parse_delta_name,
};
use crate::error::{Error, Result};
use crate::fetch::{FetchRequest, Fetched, Fetcher, Priority};
use crate::object::MAX_METADATA_SIZE;
use crate::pull::verify::Verification;
use crate::pull::{ModeChecks, PullCounters, PullFlags, PullOptions, RefPlace};
use crate::read::CommitState;
use crate::repo::Repo;
use crate::summary::{AdvertisedDelta, INDEXED_DELTAS_KEY, Summary, delta_digest};
use crate::transaction::Transaction;

use super::chain::{
    ChainPlan, ChainSearch, Edges, Planned, check_complete, complete_sources, scratch_allowed,
};
use super::http::{cached_source, fetch_remote_detached};
use super::source::{RemoteSource, Transfer, session_error};
use super::{
    CheckedMeta, DetachedMetadataFilter, TipChecks, check_commit_signatures_filtered,
    check_local_commit_signatures, check_tip_refs, count_fetched, source_size,
};

/// The number of delta parts that one pull fetches at a time.
pub(crate) const PART_CAP: usize = 2;

/// The size limit of the record file of one discovery, 1 GiB.
///
/// One step keeps at most [`MAX_SUPERBLOCK`] bytes of superblock and
/// [`MAX_METADATA_SIZE`] bytes of `.commitmeta`, 256 MiB in total. So the file
/// holds four steps of the maximum size. The limit applies to the length of
/// the file, the bytes of the records that discovery drops included.
const MAX_RECORD_FILE: u64 = 8 * MAX_METADATA_SIZE;

/// A static delta that a pull applies for one commit.
///
/// Without a list of static deltas, discovery builds the job of each target
/// commit that has a delta, and the job lives until the pull returns. With a
/// list, discovery keeps a record for each step of the chains, and the pull
/// builds the jobs from the records. For a pull from a remote,
/// [`DeltaPlan::parse_level`] builds the jobs of the intermediate commits of
/// one level before the run of that level, and the jobs live for that run
/// alone. [`DeltaPlan::target_jobs`] builds the jobs of the target commits
/// after the run of the last level. A local pull builds the job of one step
/// at a time with [`DeltaPlan::parse_record`], and drops it after its parts.
/// A job holds only what the application of the parts reads.
///
/// The parse of a superblock reads the raw superblock bytes, the signature
/// array, and the metadata dict, and drops them before the job exists. The
/// heap cost of a job is one meta-entry for each part and at most 128 KiB of
/// inline part bodies. The meta-entries list each object that the delta
/// produces. The superblock size that a remote chooses does not change this
/// cost.
///
/// The job keeps the inline part bodies in one [`Blob`]. If the bodies total
/// 128 KiB or less, the blob is on the heap. If they total more, the blob is
/// one read-only map of an anonymous temp file in `tmp/` of the repository.
/// This file costs disk space and address space up to the superblock size,
/// and the pull releases it when it drops the job.
pub(crate) struct DeltaJob {
    /// The request path prefix of the delta, `deltas/<fanout>/<rest>`.
    dir: String,
    /// The name of the delta in hex, `<to>` or `<from>-<to>`. It is the key in
    /// the advertisement and the name in a message.
    name: String,
    /// The normal-form bytes of the target commit. The superblock carries them,
    /// and the pull stages the commit from them.
    ///
    /// The jobs of a pull from a remote are in a map that the concurrent steps
    /// share. The step of the commit takes a shared reference to the bytes,
    /// and does not copy them.
    pub(crate) commit_bytes: Arc<Vec<u8>>,
    /// The meta-entries of the parts, in part order: the checksum of each part,
    /// the size that caps its fetch, and the objects that it produces.
    meta_entries: Vec<DeltaPart>,
    /// The objects that the delta references and hands over loose.
    fallbacks: Vec<DeltaFallback>,
    /// The key `ostree.composefs.digest.v0` of the target commit, if a part
    /// carries the composefs image. `None` if no part carries the image, or
    /// if the commit has no valid key.
    image_key: Option<[u8; 32]>,
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
    /// The pull fetches these objects loose. The list holds no composefs
    /// image: the pull requests the image of the commit by its own rules,
    /// after the other objects of the pull.
    pub(crate) fn fallbacks(&self) -> Vec<ObjectName> {
        self.fallbacks
            .iter()
            .filter(|fallback| fallback.objtype != ObjectType::ComposefsImage)
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
                (parts + 1, bytes.saturating_add(entry.size))
            })
    }
}

/// The deltas that discovery found for one pull.
///
/// Without a list of static deltas, `jobs` holds the delta of each target
/// commit that has one, and the plan holds no record. With a list, `jobs` is
/// empty. The plan then holds one record for each commit that a chain makes,
/// and the levels of the intermediate commits. The pull applies the levels in
/// order. A commit with a record and in no level is a target, and the pull
/// applies it last.
#[derive(Default)]
pub(crate) struct DeltaPlan {
    /// The job of each target commit, from the search for one delta.
    pub(crate) jobs: HashMap<Checksum, DeltaJob>,
    /// The record of the step that makes each commit of the chains.
    records: HashMap<Checksum, StepRecord>,
    /// The intermediate commits of the chains, by level, in plan order. A
    /// commit of level `k + 1` is made from a commit of level `k`. A commit
    /// with a record and in no level is a target, which the pull applies
    /// last.
    levels: Vec<Vec<Checksum>>,
    /// The file of the raw bytes of the records from a remote.
    store: Option<RecordStore>,
}

impl DeltaPlan {
    /// Adds the part files of each job and of each record, and their declared
    /// sizes, to the planned counts in `progress`.
    pub(crate) fn plan_parts(&self, progress: &PullCounters) {
        let jobs = self.jobs.values().map(DeltaJob::fetched_parts);
        let records = self.records.values().map(|record| record.parts);
        for (parts, bytes) in jobs.chain(records) {
            progress.parts_planned(parts, bytes);
        }
    }

    /// Parses the records of `commits` again, and returns the job of each
    /// commit that has a record.
    ///
    /// A record from a remote reads the bytes that discovery verified from
    /// the record file. A record from a local source reads the superblock
    /// from `source` again and checks it against the listed digest. The parse
    /// takes the inline parts of each job, as [`take_inline_parts`] states.
    ///
    /// # Errors
    ///
    /// - [`Error::ChecksumMismatch`] if a superblock of a local source does
    ///   not have the listed digest.
    /// - [`Error::InvalidFormat`] if a local source no longer holds a
    ///   superblock.
    pub(crate) async fn parse_level(
        &self,
        repo: &Repo,
        source: &DeltaSource<'_>,
        commits: &[Checksum],
    ) -> Result<HashMap<Checksum, DeltaJob>> {
        let mut jobs = HashMap::with_capacity(commits.len());
        for commit in commits {
            if let Some(job) = self.parse_record(repo, source, commit).await? {
                jobs.insert(*commit, job);
            }
        }
        Ok(jobs)
    }

    /// Parses the record of `commit` again, as
    /// [`parse_level`](DeltaPlan::parse_level) does, and returns its job.
    /// Returns `None` if the plan holds no record of `commit`.
    ///
    /// # Errors
    ///
    /// The errors of [`parse_level`](DeltaPlan::parse_level).
    pub(crate) async fn parse_record(
        &self,
        repo: &Repo,
        source: &DeltaSource<'_>,
        commit: &Checksum,
    ) -> Result<Option<DeltaJob>> {
        let Some(record) = self.records.get(commit) else {
            return Ok(None);
        };
        let fetched = read_record(self.store.as_ref(), source, record).await?;
        fetched.into_job(repo).await.map(Some)
    }

    /// Returns the intermediate commits of the chains, by level, in plan
    /// order.
    pub(crate) fn levels(&self) -> &[Vec<Checksum>] {
        &self.levels
    }

    /// Takes the jobs of the target commits.
    ///
    /// Without a list, these are the jobs of the search for one delta. With a
    /// list, the call also parses the records of the commits that are in no
    /// level, as [`parse_level`](DeltaPlan::parse_level) does, in checksum
    /// order. A pull from a remote calls it after the run of the last level,
    /// so the heap holds the jobs of one run at a time.
    ///
    /// # Errors
    ///
    /// The errors of [`parse_level`](DeltaPlan::parse_level).
    pub(crate) async fn target_jobs(
        &mut self,
        repo: &Repo,
        source: &DeltaSource<'_>,
    ) -> Result<HashMap<Checksum, DeltaJob>> {
        let mut jobs = std::mem::take(&mut self.jobs);
        let in_level: HashSet<&Checksum> = self.levels.iter().flatten().collect();
        let mut targets: Vec<Checksum> = self
            .records
            .keys()
            .filter(|commit| !in_level.contains(commit))
            .copied()
            .collect();
        targets.sort_unstable();
        jobs.extend(self.parse_level(repo, source, &targets).await?);
        Ok(jobs)
    }

    /// Returns the check that discovery made of `commit`.
    ///
    /// For a checked commit, the result holds the verified `.commitmeta` from
    /// the record file, and states whether the filter of the pull ran over it.
    /// It holds `None` if no repository holds a `.commitmeta`, or if the
    /// filter allows no property. A record from a local source keeps no bytes,
    /// so for a plan from a local source the result holds `None` and states
    /// only whether discovery checked the commit. The call then reads nothing.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the record file cannot be read.
    /// - [`Error::InvalidFormat`] if the plan holds no record file.
    pub(crate) async fn commit_check(&self, commit: &Checksum) -> Result<CommitCheck> {
        let Some(record) = self.records.get(commit) else {
            return Ok(CommitCheck::NotChecked);
        };
        match (&record.detached, self.store.as_ref()) {
            (Detached::NotChecked, _) => Ok(CommitCheck::NotChecked),
            (
                Detached::Checked {
                    kept: Some(range),
                    filtered,
                },
                Some(store),
            ) => Ok(CommitCheck::Checked {
                detached: Some(store.read(range.clone()).await?),
                filtered: *filtered,
            }),
            (Detached::Checked { kept: Some(_), .. }, None) => Err(Error::InvalidFormat(
                "the record file holds no record".into(),
            )),
            (
                Detached::Checked {
                    kept: None,
                    filtered,
                },
                _,
            ) => Ok(CommitCheck::Checked {
                detached: None,
                filtered: *filtered,
            }),
        }
    }

    /// Returns `true` if discovery checked `commit`, as
    /// [`CommitCheck::Checked`] states. The call reads nothing.
    pub(crate) fn checked(&self, commit: &Checksum) -> bool {
        self.records
            .get(commit)
            .is_some_and(|record| matches!(record.detached, Detached::Checked { .. }))
    }
}

/// The check that discovery made of one commit.
pub(crate) enum CommitCheck {
    /// Discovery did not check the commit. The commit step checks it.
    NotChecked,
    /// Discovery checked the signatures of the commit, and made the
    /// ref-binding check of each requested ref that names it. For a remote
    /// source, discovery also made the timestamp check of each of these refs.
    Checked {
        /// The verified `.commitmeta`. It is `None` if no repository holds a
        /// `.commitmeta`, or if the filter allows no property.
        detached: Option<Vec<u8>>,
        /// `true` if `detached` is the result of the filter of the pull.
        /// `false` if `detached` holds the bytes as the source holds them, and
        /// the commit step runs the filter over them.
        filtered: bool,
    },
}

/// A step of a chain whose superblock discovery fetched and verified.
struct StepRecord {
    /// The delta of the step, as the list gives it.
    delta: AdvertisedDelta,
    /// The number of part files of the delta and the sum of their declared
    /// sizes.
    parts: (u32, u64),
    /// The range of the raw superblock in the record file. `None` for a local
    /// source, which keeps no bytes.
    superblock: Option<Range<u64>>,
    /// The check of the commit of the step.
    detached: Detached,
}

/// The check of the commit of a step, which discovery runs for each commit of
/// a chain.
enum Detached {
    /// Discovery did not check the commit yet.
    NotChecked,
    /// Discovery checked the commit, as [`CommitCheck::Checked`] states.
    Checked {
        /// The range of the verified `.commitmeta` in the record file. `None`
        /// if the remote and the localcache repositories hold none, if the
        /// filter allows no property, and for a local source, which keeps no
        /// bytes.
        kept: Option<Range<u64>>,
        /// `true` if `kept` holds the result of the filter of the pull, as
        /// [`CommitCheck::Checked`] states.
        filtered: bool,
    },
}

/// The result of the check of one commit of a chain.
struct Checked {
    /// The range of the verified `.commitmeta` in the record file, from a
    /// remote.
    kept: Option<Range<u64>>,
    /// `true` if `kept` holds the result of the filter of the pull, as
    /// [`CommitCheck::Checked`] states.
    filtered: bool,
    /// What the check read of the `.commitmeta` in a local source.
    local: LocalRead,
}

/// What the check of a commit of a chain read of its `.commitmeta` in a local
/// source.
enum LocalRead {
    /// The check read nothing from a local source: the source is a remote,
    /// or the policy checks no commit.
    Nothing,
    /// The local source holds no `.commitmeta` of the commit.
    Absent,
    /// The local source holds a `.commitmeta` of this size.
    Size(u64),
}

/// The file that keeps the raw superblocks and the verified `.commitmeta`
/// files of a discovery from a remote. If the check of the signatures parsed a
/// `.commitmeta` and the pull has a filter, the file keeps the result of the
/// filter. Else it keeps the `.commitmeta` as the source holds it.
///
/// The file is one unlinked temp file in `tmp/` of the repository, open for
/// reads and writes and not mapped. It opens at the first write. Discovery
/// appends to it, and a record holds the range of its bytes. The bytes of a
/// record that discovery drops stay in the file. The file goes away when the
/// pull drops it.
///
/// The length of the file has a limit. Discovery checks the limit before each
/// write, so the file never passes it. A write that would pass the limit
/// fails the pull with [`Error::Pull`].
struct RecordStore {
    /// The repository whose `tmp/` holds the file.
    repo: Repo,
    /// The file, after the first write.
    file: Option<Arc<std::fs::File>>,
    /// The length of the file.
    len: u64,
    /// The limit of the length of the file.
    limit: u64,
}

impl RecordStore {
    /// Returns a record store in `tmp/` of `repo`, with no file yet, and with
    /// the limit [`MAX_RECORD_FILE`].
    fn new(repo: &Repo) -> RecordStore {
        RecordStore {
            repo: repo.clone(),
            file: None,
            len: 0,
            limit: MAX_RECORD_FILE,
        }
    }

    /// Checks that `len` more bytes keep the file in its limit.
    ///
    /// `what` names the bytes in the error.
    ///
    /// # Errors
    ///
    /// [`Error::Pull`] if the file would pass its limit.
    fn check_room(&self, len: u64, what: impl FnOnce() -> String) -> Result<()> {
        match self.len.checked_add(len) {
            Some(end) if end <= self.limit => Ok(()),
            _ => Err(Error::Pull(format!(
                "static delta list: {} passes the limit of {} bytes for the superblocks \
                 and the detached metadata that discovery keeps",
                what(),
                self.limit
            ))),
        }
    }

    /// Returns the file, and opens it if it is not open.
    async fn file(&mut self) -> Result<Arc<std::fs::File>> {
        if let Some(file) = &self.file {
            return Ok(Arc::clone(file));
        }
        let tmp = self.repo.open_tmp_dir().await?;
        let fd = ostrya_rt::unblock(move || open_rw_temp(tmp.as_fd())).await?;
        let file = Arc::new(std::fs::File::from(fd));
        self.file = Some(Arc::clone(&file));
        Ok(file)
    }

    /// Appends `bytes` on the blocking pool, and returns their range.
    ///
    /// `what` names the bytes in the error.
    ///
    /// # Errors
    ///
    /// - [`Error::Pull`] if the bytes would pass the limit of the file. The
    ///   call then opens no file and writes nothing.
    /// - [`Error::Io`] if the file cannot be opened or written.
    async fn append(
        &mut self,
        bytes: Vec<u8>,
        what: impl FnOnce() -> String,
    ) -> Result<Range<u64>> {
        self.check_room(bytes.len() as u64, what)?;
        let file = self.file().await?;
        let start = self.len;
        let end = start + bytes.len() as u64;
        ostrya_rt::unblock(move || file.write_all_at(&bytes, start)).await?;
        self.len = end;
        Ok(start..end)
    }

    /// Reads the bytes at `range` on the blocking pool.
    async fn read(&self, range: Range<u64>) -> Result<Vec<u8>> {
        let file = self
            .file
            .clone()
            .ok_or_else(|| Error::InvalidFormat("the record file holds no record".into()))?;
        ostrya_rt::unblock(move || {
            let len = usize::try_from(range.end - range.start)
                .map_err(|_| Error::InvalidFormat("a record is larger than memory".into()))?;
            let mut bytes = vec![0; len];
            file.read_exact_at(&mut bytes, range.start)?;
            Ok(bytes)
        })
        .await
    }
}

/// A superblock that discovery fetched and parsed, with its source and
/// target checked against the request, its signatures checked, and its
/// inline parts verified.
struct FetchedDelta {
    /// The request path prefix of the delta, `deltas/<fanout>/<rest>`.
    dir: String,
    /// The name of the delta in hex, `<to>` or `<from>-<to>`.
    name: String,
    /// The normal-form bytes of the target commit.
    commit_bytes: Vec<u8>,
    meta_entries: Vec<DeltaPart>,
    fallbacks: Vec<DeltaFallback>,
    /// The metadata dict, which carries the inline parts.
    metadata: Value,
    /// The position in `metadata` of each inline part, in part order.
    inline_index: Vec<Option<usize>>,
}

impl FetchedDelta {
    /// Copies the inline parts out of the metadata dict, and returns the job.
    ///
    /// If a part carries the composefs image, the call parses the target
    /// commit on the blocking pool and keeps its image key in the job.
    async fn into_job(self, repo: &Repo) -> Result<DeltaJob> {
        let (inline, inline_bodies) = take_inline_parts(
            repo,
            &self.metadata,
            &self.inline_index,
            &self.dir,
            &self.meta_entries,
        )
        .await?;
        let FetchedDelta {
            dir,
            name,
            commit_bytes,
            meta_entries,
            fallbacks,
            metadata,
            ..
        } = self;
        drop(metadata);
        let commit_bytes = Arc::new(commit_bytes);
        let image_key = if carries_image(&meta_entries) {
            let bytes = Arc::clone(&commit_bytes);
            ostrya_rt::unblock(move || image_key(&bytes)).await
        } else {
            None
        };
        Ok(DeltaJob {
            dir,
            name,
            commit_bytes,
            meta_entries,
            fallbacks,
            image_key,
            inline,
            inline_bodies,
        })
    }

    /// Returns the bytes of the target commit, and drops the rest of the
    /// parsed superblock.
    fn into_commit_bytes(self) -> Vec<u8> {
        self.commit_bytes
    }

    /// Returns the number of part files and the sum of their declared sizes.
    fn parts(&self) -> (u32, u64) {
        self.meta_entries
            .iter()
            .enumerate()
            .filter(|(part, _)| self.inline_index.get(*part).copied().flatten().is_none())
            .fold((0, 0), |(parts, bytes), (_, entry)| {
                (parts + 1, bytes.saturating_add(entry.size))
            })
    }

    /// Verifies each inline part in place against its meta-entry, with no
    /// copy.
    fn verify_inline_parts(&self) -> Result<()> {
        for (part, entry) in self.meta_entries.iter().enumerate() {
            if let Some((compression, body)) =
                inline_part_at(&self.metadata, &self.inline_index, part, || {
                    self.dir.clone()
                })?
            {
                verify_inline_part(compression, body, entry)?;
            }
        }
        Ok(())
    }
}

/// A superblock that the blocking pool parsed, before the check of its
/// signatures.
struct ParsedDelta {
    delta: FetchedDelta,
    /// The raw superblock bytes that the signatures cover.
    superblock_bytes: Vec<u8>,
    /// The signature array.
    signatures: Option<Value>,
    /// The result of the check of the inline parts. The pull reports it after
    /// the check of the signatures.
    inline: Result<()>,
}

impl ParsedDelta {
    /// Checks the signatures of the superblock if `verification` is set, as
    /// [`verify_fetched_delta`] states, then gives the result of the check of
    /// the inline parts. Returns the delta, with the raw bytes and the
    /// signature array dropped.
    async fn verify(self, verification: Option<&Verification>) -> Result<FetchedDelta> {
        let ParsedDelta {
            delta,
            superblock_bytes,
            signatures,
            inline,
        } = self;
        if let Some(verification) = verification {
            verify_fetched_delta(
                verification,
                &delta.name,
                &superblock_bytes,
                signatures.as_ref(),
            )
            .await?;
        }
        drop(superblock_bytes);
        inline?;
        Ok(delta)
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
/// command counts the same way. The discovery of a chain also counts the
/// `.commitmeta` of each commit of a chain, as [`check_step_commit`] states.
///
/// `edges` is the index of a list of static deltas. With a list, discovery
/// reads no summary and no delta index, and [`discover_chain`] plans and
/// fetches the chains. It also checks the commit of each step, a target
/// included, before the pull opens its transaction. `tips` holds the checks
/// of each requested ref, with the timestamp check that the caller resolved,
/// and the place of the refs, where discovery reads the current commit of a
/// ref. A local pull passes
/// [`TimestampBase::Off`](super::TimestampBase::Off). A
/// [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull ignores the list. A pull that
/// requires static deltas needs no summary for the list.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn discover(
    repo: &Repo,
    source: &DeltaSource<'_>,
    summary: Option<&Summary>,
    targets: &[(String, Checksum)],
    opts: &PullOptions,
    tips: TipChecks<'_>,
    edges: Option<Edges>,
    verification: &Verification,
    progress: &PullCounters,
) -> Result<DeltaPlan> {
    if opts.disable_static_deltas {
        return Ok(DeltaPlan::default());
    }
    if let Some(edges) = edges {
        if opts.flags.contains(PullFlags::COMMIT_ONLY) {
            return Ok(DeltaPlan::default());
        }
        return discover_chain(
            repo,
            source,
            targets,
            opts,
            tips,
            edges,
            verification,
            progress,
        )
        .await;
    }
    let mut jobs = HashMap::new();
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
        return Ok(DeltaPlan::default());
    }
    for (ref_name, to) in targets {
        if jobs.contains_key(to) || complete_here(repo, to).await? {
            continue;
        }
        let tip = repo
            .resolve_relpath_tip(tips.place.relpath(ref_name)?)
            .await?;
        let from = source_commit(repo, tip, to).await?;
        let scratch = scratch_allowed(tip, from, to);
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
    Ok(DeltaPlan {
        jobs,
        ..DeltaPlan::default()
    })
}

/// Plans the chains of static deltas to the targets over `edges`, and fetches
/// and verifies the superblock of each step.
///
/// The targets are the commits of `targets` that this repository does not
/// hold complete, each once, in the order of the refs, as [`chain_targets`]
/// states. The planner of the sibling module `chain` finds and merges the
/// chains.
///
/// Discovery fetches the steps of the plan in level order, and the steps to
/// the targets last. For each step it fetches the superblock, checks its
/// digest, its source and target, its signatures, and its inline parts, and
/// keeps a record. Then it drops the parsed superblock, and keeps only the
/// bytes of the commit for the check of the commit. For the commit of each
/// step it also fetches or reads the `.commitmeta`, as [`fetch_step`] and
/// [`check_step_commit`] state, and checks the commit, as
/// [`check_step_commit`] states. A commit gets one check, also if a later
/// plan makes it from another step. For a local source, discovery makes no
/// timestamp check, because a local pull has none.
///
/// If the source does not hold the superblock of a step, discovery excludes
/// that delta and plans again. It fetches only the steps that it did not
/// fetch before. Each pass excludes one delta, so the loop ends. The planner
/// limits the number of deltas that it plans again around. At the end
/// discovery drops each record that the last plan does not use. A target
/// with no chain gets no record, and the pull fetches its objects loose.
///
/// # Errors
///
/// - [`Error::Pull`] if the pull requires static deltas and a plan has no
///   chain to a target. A delta from scratch to the target that the scratch
///   rule refuses counts as a chain, and the pull fetches loose.
/// - [`Error::ChecksumMismatch`] if a superblock does not have its listed
///   digest.
/// - [`Error::Pull`] if a superblock produces another commit, or from
///   another commit, than its entry of the list.
/// - [`Error::Signature`] if the signatures of a superblock or of a commit
///   of a chain fail the policy of the pull.
/// - [`Error::Pull`] if a requested ref that names a commit of a chain fails
///   the ref-binding check or the timestamp check.
/// - [`Error::Pull`] if the superblocks and the `.commitmeta` files of a
///   remote would pass the limit of the record file, [`MAX_RECORD_FILE`].
///   The pull then does not fetch loose.
/// - [`Error::InvalidFormat`] if a superblock or an inline part is
///   malformed.
#[allow(clippy::too_many_arguments)]
async fn discover_chain(
    repo: &Repo,
    source: &DeltaSource<'_>,
    targets: &[(String, Checksum)],
    opts: &PullOptions,
    tips: TipChecks<'_>,
    edges: Edges,
    verification: &Verification,
    progress: &PullCounters,
) -> Result<DeltaPlan> {
    let (wanted, names) = chain_targets(repo, targets, tips.place).await?;
    if wanted.is_empty() {
        return Ok(DeltaPlan::default());
    }
    let target_commits: Vec<Checksum> = wanted.iter().map(|(target, _)| *target).collect();
    let (edges, complete) = complete_sources(repo, edges, &target_commits).await?;
    let (mut search, mut pass) = ostrya_rt::unblock(move || {
        let search = ChainSearch::new(edges, complete, wanted);
        let pass = Pass::new(&search);
        (search, pass)
    })
    .await;

    let mut store = match source {
        DeltaSource::Remote(_) => Some(RecordStore::new(repo)),
        DeltaSource::Local(_) => None,
    };
    // The requested refs of each target, in the order of the refs. Discovery
    // makes the checks of these refs when it checks the commit.
    let mut refs_of: HashMap<Checksum, Vec<&str>> = HashMap::new();
    for (name, target) in targets {
        refs_of.entry(*target).or_default().push(name.as_str());
    }
    let ctx = CheckCtx {
        repo,
        source,
        localcache: &opts.localcache_repos,
        verification,
        filter: &opts.detached_metadata_filter,
        progress,
        tips,
    };
    // The record of each fetched step, by list index.
    let mut records: HashMap<usize, StepRecord> = HashMap::new();
    // The check of each commit, by commit. A commit keeps its check when a
    // later plan makes it from another step.
    let mut checked: HashMap<Checksum, Checked> = HashMap::new();
    'plan: loop {
        if opts.require_static_deltas {
            for ((target, planned), name) in search.targets().zip(&names) {
                if !pass.plan.steps.contains_key(target) && *planned != Planned::Declined {
                    return Err(none_found_error(name, target));
                }
            }
        }
        for commit in std::mem::take(&mut pass.order) {
            let index = pass.plan.steps[&commit];
            // Discovery checked the commit of each step that it fetched.
            if records.contains_key(&index) {
                continue;
            }
            let check = !checked.contains_key(&commit);
            let delta = *search.edges().delta(index);
            let Some(step) = fetch_step(&ctx, &delta, check, store.as_mut()).await? else {
                (search, pass) = ostrya_rt::unblock(move || {
                    search.exclude(index);
                    let pass = Pass::new(&search);
                    (search, pass)
                })
                .await;
                continue 'plan;
            };
            records.insert(
                index,
                StepRecord {
                    delta,
                    parts: step.fetched.parts(),
                    superblock: step.kept,
                    detached: Detached::NotChecked,
                },
            );
            let FetchedStep {
                fetched, detached, ..
            } = step;
            // Only the commit bytes stay for the check. The rest of the parsed
            // superblock drops here.
            let commit_bytes = fetched.into_commit_bytes();
            if check {
                let refs = refs_of.get(&commit).map(Vec::as_slice).unwrap_or_default();
                let result =
                    check_step_commit(&ctx, &commit, commit_bytes, refs, detached, store.as_mut())
                        .await?;
                checked.insert(commit, result);
            }
        }
        break;
    }

    // A local source counts the `.commitmeta` of each intermediate commit of
    // the last plan alone, by the rule of the import of the pull.
    if let DeltaSource::Local(src) = source {
        for commit in pass.plan.levels.iter().flatten() {
            let size = match checked.get(commit).map(|check| &check.local) {
                Some(LocalRead::Size(size)) => Some(*size),
                Some(LocalRead::Absent) => None,
                Some(LocalRead::Nothing) | None => {
                    source_size(src, ObjectType::CommitMeta, commit).await?
                }
            };
            if let Some(size) = size {
                count_fetched(progress, ObjectType::CommitMeta, size);
            }
        }
    }

    let mut kept_records = HashMap::with_capacity(pass.plan.steps.len());
    for (commit, index) in &pass.plan.steps {
        let Some(mut record) = records.remove(index) else {
            continue;
        };
        if let Some(check) = checked.remove(commit) {
            record.detached = Detached::Checked {
                kept: check.kept,
                filtered: check.filtered,
            };
        }
        kept_records.insert(*commit, record);
    }
    Ok(DeltaPlan {
        jobs: HashMap::new(),
        records: kept_records,
        levels: pass.plan.levels,
        store,
    })
}

/// The plan of one pass of the discovery of a chain, with the order in which
/// discovery fetches its steps.
struct Pass {
    plan: ChainPlan,
    /// The commits of the plan in fetch order: the levels in order, then the
    /// targets that no step reads, in the order of the targets.
    order: Vec<Checksum>,
}

impl Pass {
    /// Merges the chains of `search`, and orders the steps of the result.
    fn new(search: &ChainSearch) -> Pass {
        let plan = search.merged();
        let intermediate: HashSet<Checksum> = plan.levels.iter().flatten().copied().collect();
        let order = plan
            .levels
            .iter()
            .flatten()
            .copied()
            .chain(
                search
                    .targets()
                    .map(|(target, _)| *target)
                    .filter(|target| {
                        plan.steps.contains_key(target) && !intermediate.contains(target)
                    }),
            )
            .collect();
        Pass { plan, order }
    }
}

/// Returns each commit of `targets` that this repository does not hold
/// complete, once, in the order of the refs, with its scratch rule. Also
/// returns the first ref that names each commit, for an error.
///
/// A step from scratch to a target is allowed if the scratch rule allows it
/// for one of the refs that name the target. The checks of the commits run on
/// the blocking pool in batches: one pass for the targets, and one for the
/// commits that the refs name here.
async fn chain_targets<'t>(
    repo: &Repo,
    targets: &'t [(String, Checksum)],
    place: RefPlace<'_>,
) -> Result<(Vec<(Checksum, bool)>, Vec<&'t str>)> {
    let mut unique: Vec<Checksum> = Vec::new();
    let mut seen: HashSet<Checksum> = HashSet::new();
    for (_, to) in targets {
        if seen.insert(*to) {
            unique.push(*to);
        }
    }
    let held: HashSet<Checksum> = check_complete(repo, &unique)
        .await?
        .into_iter()
        .filter_map(|(commit, complete)| complete.then_some(commit))
        .collect();
    let mut tips: Vec<(&str, Checksum, Option<Checksum>)> = Vec::new();
    for (ref_name, to) in targets {
        if held.contains(to) {
            continue;
        }
        let tip = repo.resolve_relpath_tip(place.relpath(ref_name)?).await?;
        tips.push((ref_name.as_str(), *to, tip));
    }
    // A tip can be the source commit only if it is not the target.
    let mut candidates: Vec<Checksum> = Vec::new();
    let mut seen: HashSet<Checksum> = HashSet::new();
    for (_, to, tip) in &tips {
        if let Some(tip) = tip
            && tip != to
            && seen.insert(*tip)
        {
            candidates.push(*tip);
        }
    }
    let complete: HashSet<Checksum> = check_complete(repo, &candidates)
        .await?
        .into_iter()
        .filter_map(|(commit, complete)| complete.then_some(commit))
        .collect();
    let mut wanted: Vec<(Checksum, bool)> = Vec::new();
    let mut names: Vec<&str> = Vec::new();
    let mut position: HashMap<Checksum, usize> = HashMap::new();
    for (name, to, tip) in tips {
        let from = tip.filter(|tip| *tip != to && complete.contains(tip));
        let scratch = scratch_allowed(tip, from, &to);
        match position.get(&to) {
            Some(&i) => wanted[i].1 |= scratch,
            None => {
                position.insert(to, wanted.len());
                wanted.push((to, scratch));
                names.push(name);
            }
        }
    }
    Ok((wanted, names))
}

/// What the check of the commit of each step reads, for one discovery.
struct CheckCtx<'a> {
    /// The repository that the pull writes into.
    repo: &'a Repo,
    source: &'a DeltaSource<'a>,
    /// The localcache repositories of the pull, in the order of the reads.
    localcache: &'a [Repo],
    verification: &'a Verification,
    /// The detached metadata filter of the pull. Discovery runs it over the
    /// `.commitmeta` of a commit that it checks from a remote, if the check of
    /// the signatures parses the `.commitmeta`.
    filter: &'a DetachedMetadataFilter,
    progress: &'a PullCounters,
    /// The checks of each requested ref that names a commit.
    tips: TipChecks<'a>,
}

/// A step whose superblock [`fetch_step`] fetched and verified.
struct FetchedStep {
    fetched: FetchedDelta,
    /// The range of the raw superblock in the record file.
    kept: Option<Range<u64>>,
    /// The `.commitmeta` of the commit of the step, if the fetch got it with
    /// the superblock. The inner `None` is a `.commitmeta` that no repository
    /// holds.
    detached: Option<Option<Vec<u8>>>,
}

/// Fetches and verifies the superblock of the step `delta`, as [`fetch_job`]
/// states, and returns `None` if the source does not hold it.
///
/// If `pair` is set and the source is a remote over a stream session, the
/// function can also get the `.commitmeta` of the commit of the step. If a
/// localcache repository holds the `.commitmeta`, the function sends the
/// request of the superblock alone and reads no `.commitmeta`. Else it sends
/// the request of the superblock and the request of the `.commitmeta` as one
/// pair, the superblock first, so the two cost one round trip. The reply of
/// the `.commitmeta` arrives while the function parses and verifies the
/// superblock. So the heap then holds one superblock, one `.commitmeta`, and
/// the parse of the superblock: up to [`MAX_SUPERBLOCK`] plus
/// [`MAX_METADATA_SIZE`] bytes of raw data.
///
/// A `.commitmeta` that the remote serves adds one to the metadata count,
/// also if the remote does not hold the superblock. A failure of the
/// superblock reports before a failure of the `.commitmeta`. If the remote
/// does not hold the superblock, the function drops the `.commitmeta`. If a
/// later plan makes the same commit from another delta, discovery requests
/// the `.commitmeta` again and counts it again. So for the same pull, the
/// metadata count over a stream session can be higher than over HTTP: one
/// more for each missing superblock whose commit has a `.commitmeta` on the
/// remote.
///
/// If the function gets no `.commitmeta`, [`check_step_commit`] reads it
/// after the superblock: from the first localcache repository that holds it,
/// else from the remote. This is so if `pair` is not set, for each other
/// source, and if a localcache repository holds the `.commitmeta`.
async fn fetch_step(
    ctx: &CheckCtx<'_>,
    delta: &AdvertisedDelta,
    pair: bool,
    store: Option<&mut RecordStore>,
) -> Result<Option<FetchedStep>> {
    let job = fetch_job(
        ctx.source,
        delta.from,
        delta.to,
        Some(delta.superblock),
        ctx.verification,
        ctx.progress,
        store,
    );
    let (job, detached) = match ctx.source {
        DeltaSource::Remote(remote) if pair && matches!(remote.transfer(), Transfer::Stream(_)) => {
            let name = ObjectName::new(delta.to, ObjectType::CommitMeta);
            match cached_source(ctx.localcache, name).await? {
                Some(_) => (job.await, None),
                None => {
                    let (job, detached) = futures_lite::future::zip(
                        job,
                        fetch_remote_detached(remote, ctx.progress, &delta.to),
                    )
                    .await;
                    (job, Some(detached))
                }
            }
        }
        _ => (job.await, None),
    };
    let job = job?;
    let detached = detached.transpose()?;
    Ok(job.map(|(fetched, kept)| FetchedStep {
        fetched,
        kept,
        detached,
    }))
}

/// Checks the commit `commit` of a step, and returns the check.
///
/// The check covers the signatures of the commit, and the ref-binding check
/// and the timestamp check of each ref of `refs`, in order. `refs` are the
/// requested refs that name the commit. They are empty for a commit that
/// is an intermediate commit alone. The checks of the refs run after the
/// check of the signatures, also if the policy checks no commit.
///
/// `commit_bytes` are the bytes of the commit that its superblock carries.
/// The parse of the superblock verified that they hash to `commit`. The
/// checks of the refs parse them on the blocking pool. Under
/// [`TimestampCheck::CurrentRef`](crate::pull::TimestampCheck::CurrentRef),
/// the timestamp check reads the commit of each ref on the blocking pool too.
/// The check reads the `.commitmeta` that the pull puts in place, as the
/// check of a fetched commit does.
///
/// - From a remote, `detached` is the `.commitmeta` that [`fetch_step`] got
///   with the superblock. If it is `None`, the `.commitmeta` comes from the
///   first localcache repository that holds it, else from the remote. A file
///   that the remote serves adds one to the metadata count. If the policy
///   checks commits and the pull has a filter, the check parses the bytes,
///   and the detached metadata filter of the pull reads that parse right
///   after the check, on the blocking pool. The record file keeps the result
///   of the filter. A filter that allows no property keeps no range. Else
///   the record file keeps the verified bytes, and the commit step runs the
///   filter over them. The result holds the range in the record file.
/// - From a local source, the `.commitmeta` comes from the source, else from
///   the first localcache repository that holds it. The reads and the parse
///   run in one call on the blocking pool. The record keeps no bytes. If the
///   policy checks no commit, discovery reads no `.commitmeta`. The result
///   holds the size of the file that the source holds. [`discover_chain`]
///   counts the file at its end, for each intermediate commit of the last
///   plan alone.
///
/// If no repository holds a `.commitmeta`, the check reads the detached
/// metadata of this repository.
///
/// # Errors
///
/// - [`Error::Signature`] if the signatures fail the policy of the pull.
/// - [`Error::Pull`] if the ref binding of the commit does not name a ref
///   of `refs`, or if the commit is older than the timestamp check allows.
/// - [`Error::Pull`] if the `.commitmeta` would pass the limit of the record
///   file.
async fn check_step_commit(
    ctx: &CheckCtx<'_>,
    commit: &Checksum,
    commit_bytes: Vec<u8>,
    refs: &[&str],
    detached: Option<Option<Vec<u8>>>,
    store: Option<&mut RecordStore>,
) -> Result<Checked> {
    let checked = match ctx.source {
        DeltaSource::Remote(remote) => {
            let detached = match detached {
                Some(detached) => detached,
                None => {
                    super::http::fetch_detached_metadata(
                        remote,
                        ctx.localcache,
                        ctx.progress,
                        commit,
                    )
                    .await?
                }
            };
            // If the check parses the `.commitmeta`, the filter reads that
            // parse right after the check, and the record file keeps its
            // result. Else the record file keeps the bytes of the source, and
            // the commit step filters them. A parse error of the filter then
            // comes only for a commit that the pull fetches.
            let checked = check_commit_signatures_filtered(
                ctx.repo,
                ctx.verification,
                ctx.filter,
                commit,
                &commit_bytes,
                detached,
            )
            .await?;
            let (detached, filtered) = match checked {
                Some(CheckedMeta::Filtered(kept)) => (kept, true),
                Some(CheckedMeta::Source(bytes)) => (Some(bytes), false),
                None => (None, false),
            };
            let kept = match (detached, store) {
                (Some(bytes), Some(store)) => Some(
                    store
                        .append(bytes, || format!("the .commitmeta of commit {commit}"))
                        .await?,
                ),
                _ => None,
            };
            Checked {
                kept,
                filtered,
                local: LocalRead::Nothing,
            }
        }
        DeltaSource::Local(_) if !ctx.verification.checks_commits() => Checked {
            kept: None,
            filtered: false,
            local: LocalRead::Nothing,
        },
        DeltaSource::Local(src) => {
            // The source comes first, then the localcache repositories, then
            // this repository. One call on the blocking pool reads and parses.
            let sources: Vec<Repo> = std::iter::once((*src).clone())
                .chain(ctx.localcache.iter().cloned())
                .collect();
            let read = check_local_commit_signatures(
                ctx.repo,
                ctx.verification,
                sources,
                commit,
                &commit_bytes,
            )
            .await?;
            let local = match read {
                Some((0, size)) => LocalRead::Size(size),
                _ => LocalRead::Absent,
            };
            Checked {
                kept: None,
                filtered: false,
                local,
            }
        }
    };
    if !refs.is_empty() {
        // The bytes can be as large as `MAX_METADATA_SIZE`, so the parse runs
        // on the blocking pool. The bytes drop there.
        let parsed = ostrya_rt::unblock(move || Commit::parse(&commit_bytes)).await?;
        check_tip_refs(ctx.repo, ctx.tips, commit, &parsed, refs).await?;
    }
    Ok(checked)
}

/// Reads the superblock of `record` again and parses it on the blocking
/// pool.
///
/// A record from a remote reads its range of `store`. These are the bytes
/// that discovery verified, so the parse checks no signature and no inline
/// part again. A record from a local source reads the superblock from the
/// source again and checks it against the listed digest. The same digest
/// gives the bytes that discovery verified.
async fn read_record(
    store: Option<&RecordStore>,
    source: &DeltaSource<'_>,
    record: &StepRecord,
) -> Result<FetchedDelta> {
    let AdvertisedDelta {
        from,
        to,
        superblock: digest,
    } = record.delta;
    let (bytes, digest) = match (&record.superblock, store, source) {
        (Some(range), Some(store), _) => (store.read(range.clone()).await?, None),
        (None, _, DeltaSource::Local(src)) => {
            let path = format!(
                "{}/{SUPERBLOCK_FILE}",
                delta_relative_dir(from.as_ref(), &to)
            );
            let bytes = read_local(src, &path, MAX_SUPERBLOCK)
                .await?
                .ok_or_else(|| {
                    Error::InvalidFormat(format!(
                        "static delta {}: the source repository holds no superblock",
                        delta_name(from.as_ref(), &to)
                    ))
                })?;
            (bytes, Some(digest))
        }
        _ => {
            return Err(Error::InvalidFormat(format!(
                "static delta {}: discovery kept no superblock",
                delta_name(from.as_ref(), &to)
            )));
        }
    };
    let (parsed, _) =
        ostrya_rt::unblock(move || parse_superblock(bytes, digest, None, from, to, false)).await?;
    parsed.verify(None).await
}

/// Returns `true` if this repository holds a commit and each object that it
/// references.
pub(super) async fn complete_here(repo: &Repo, commit: &Checksum) -> Result<bool> {
    let repo = repo.clone();
    let commit = *commit;
    ostrya_rt::unblock(move || complete_here_blocking(&repo, &commit)).await
}

/// Runs [`complete_here`] on the calling thread.
pub(super) fn complete_here_blocking(repo: &Repo, commit: &Checksum) -> Result<bool> {
    Ok(repo.has_object_blocking(ObjectType::Commit, commit)?
        && repo.commit_state_blocking(commit)? == CommitState::Normal)
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
pub(crate) async fn open_local(repo: &Repo, path: &str) -> Result<Option<(std::fs::File, u64)>> {
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
        let Some((file, len)) = open_local_blocking(repo_fd.as_fd(), &path)? else {
            return Ok(None);
        };
        read_capped(file, len, &path, cap).map(Some)
    })
    .await
}

/// Reads the whole file that [`open_local`] opened at `path`, or `None` if
/// `opened` is `None`.
///
/// The read runs on the blocking pool, under the cap rules of [`read_local`].
pub(crate) async fn read_opened(
    opened: Option<(std::fs::File, u64)>,
    path: &str,
    cap: u64,
) -> Result<Option<Vec<u8>>> {
    let Some((file, len)) = opened else {
        return Ok(None);
    };
    let path = path.to_owned();
    ostrya_rt::unblock(move || read_capped(file, len, &path, cap).map(Some)).await
}

/// Reads `file`, of length `len`, whole. If it is longer than `cap`, the
/// function reads `cap` bytes and one more, then refuses the file at `path`
/// with [`Error::InvalidFormat`].
fn read_capped(file: std::fs::File, len: u64, path: &str, cap: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let hint = len.min(cap) + 1;
    let mut bytes = Vec::with_capacity(usize::try_from(hint).unwrap_or(0));
    file.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(Error::InvalidFormat(format!(
            "{path} in the source repository exceeds the size ceiling of {cap} bytes"
        )));
    }
    Ok(bytes)
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
    for (candidate, name, value) in source_candidates(map, to) {
        if Some(candidate) != from && complete_here(repo, &candidate).await? {
            return Ok(Choice::Take {
                from: Some(candidate),
                digest: delta_digest(name, value)?,
            });
        }
    }
    Ok(match map_digest(map, &delta_name(None, to))? {
        Some(digest) if scratch => Choice::Take { from: None, digest },
        Some(_) => Choice::Declined,
        None => Choice::None,
    })
}

/// Returns the source commit, the name, and the value of each `<from>-<to>`
/// entry of `map`, in map order.
///
/// The scan skips each entry that is not a `{sv}`, each key for another
/// target, and each key that is not a delta name in lowercase hex. A key that
/// does not end in `-<to>` is skipped before the hex parse.
fn source_candidates<'a>(
    map: &'a Value,
    to: &Checksum,
) -> impl Iterator<Item = (Checksum, &'a str, &'a Value)> {
    let to = *to;
    let suffix = format!("-{}", to.to_hex());
    map.as_array()
        .unwrap_or_default()
        .iter()
        .filter_map(move |entry| {
            let [key, value] = entry.as_tuple()? else {
                return None;
            };
            let name = key.as_str()?;
            if !name.ends_with(&suffix) {
                return None;
            }
            match parse_delta_name(name)? {
                (Some(from), target) if target == to => Some((from, name, value)),
                _ => None,
            }
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
/// Step 2 skips each key that is not a delta name in lowercase hex. A digest
/// of the chosen delta that is not an `ay` of 32 bytes fails the pull with
/// [`Error::InvalidFormat`].
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
    // If the remote does not hold an advertised superblock, the advertisement
    // is stale. The pull then fetches the objects loose. If the pull requires
    // static deltas, it fails.
    let Some((fetched, _)) =
        fetch_job(source, from, to, digest, verification, progress, None).await?
    else {
        return none_found();
    };
    fetched.into_job(repo).await.map(Some)
}

/// Fetches the superblock of the delta from `from` to `to`, and verifies it.
///
/// Returns `None` if the source does not hold the superblock. The request
/// adds one to the metadata count in `progress`, whatever the source answers.
/// If `digest` is set, the SHA-256 of the superblock must be `digest`. The
/// superblock must produce `to` from `from`. Its signatures must pass the
/// policy of the pull, as [`verify_fetched_delta`] states. Each inline part
/// must pass its meta-entry.
///
/// If `keep` is set, the function appends the raw bytes to that record file
/// after the digest check, and returns their range with the parsed delta.
/// Before the digest check, it checks that the bytes keep the record file in
/// its limit. A superblock that would pass the limit fails before the
/// function opens the file or writes to it.
///
/// The digest check, the write to the record file, the parse, and the check
/// of the inline parts run in one call on the blocking pool. The check of the
/// signatures comes after it, and a failed inline part fails after the check
/// of the signatures.
///
/// # Errors
///
/// - [`Error::Pull`] if the superblock would pass the limit of the record
///   file of `keep`.
/// - [`Error::ChecksumMismatch`] if the superblock does not have `digest`.
/// - [`Error::Pull`] if the superblock produces another commit, or from
///   another commit.
/// - [`Error::Signature`] if the signatures fail the policy.
/// - [`Error::InvalidFormat`] or [`Error::Core`] if the superblock or an
///   inline part is malformed.
async fn fetch_job(
    source: &DeltaSource<'_>,
    from: Option<Checksum>,
    to: Checksum,
    digest: Option<Checksum>,
    verification: &Verification,
    progress: &PullCounters,
    mut keep: Option<&mut RecordStore>,
) -> Result<Option<(FetchedDelta, Option<Range<u64>>)>> {
    let path = format!(
        "{}/{SUPERBLOCK_FILE}",
        delta_relative_dir(from.as_ref(), &to)
    );
    let fetched = source.read(&path, MAX_SUPERBLOCK, progress).await?;
    progress.metadata_fetched();
    let Some(bytes) = fetched else {
        return Ok(None);
    };
    let sink = match keep.as_mut() {
        Some(store) => {
            store.check_room(bytes.len() as u64, || {
                format!(
                    "the superblock of static delta {}",
                    delta_name(from.as_ref(), &to)
                )
            })?;
            Some((store.file().await?, store.len))
        }
        None => None,
    };
    let (parsed, kept) =
        ostrya_rt::unblock(move || parse_superblock(bytes, digest, sink, from, to, true)).await?;
    if let (Some(store), Some(range)) = (keep, &kept) {
        store.len = range.end;
    }
    let fetched = parsed.verify(Some(verification)).await?;
    Ok(Some((fetched, kept)))
}

/// Checks and parses the superblock `bytes` of the delta from `from` to `to`
/// on the calling thread, and checks its source and target.
///
/// If `digest` is set, the SHA-256 of `bytes` must be `digest`. If `sink` is
/// set, the function then writes `bytes` to that file at that offset, before
/// the parse consumes them, and returns their range. If `check_inline` is
/// set, the result holds the check of each inline part against its
/// meta-entry.
fn parse_superblock(
    bytes: Vec<u8>,
    digest: Option<Checksum>,
    sink: Option<(Arc<std::fs::File>, u64)>,
    from: Option<Checksum>,
    to: Checksum,
    check_inline: bool,
) -> Result<(ParsedDelta, Option<Range<u64>>)> {
    if let Some(expected) = digest {
        let actual = Checksum::sha256(&bytes);
        if actual != expected {
            return Err(Error::ChecksumMismatch { expected, actual });
        }
    }
    let kept = match sink {
        Some((file, start)) => {
            file.write_all_at(&bytes, start)?;
            Some(start..start + bytes.len() as u64)
        }
        None => None,
    };
    let name = delta_name(from.as_ref(), &to);
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
    // The destructure lets the compiler prove where the raw bytes and the
    // signature array go. They go to verification alone. The metadata dict
    // goes to the inline parts.
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
    let delta = FetchedDelta {
        dir: delta_relative_dir(from.as_ref(), &to),
        name,
        commit_bytes,
        meta_entries,
        fallbacks,
        metadata,
        inline_index,
    };
    let inline = if check_inline {
        delta.verify_inline_parts()
    } else {
        Ok(())
    };
    Ok((
        ParsedDelta {
            delta,
            superblock_bytes,
            signatures,
            inline,
        },
        kept,
    ))
}

/// Copies the bodies of the inline parts into one [`Blob`].
///
/// The caller verified each inline part against its meta-entry. The function
/// checks again the size and the compression byte of each part, and does not
/// hash it again. It works in part order and copies the bodies out of the
/// metadata dict, so the caller can drop the dict. The heap threshold is 128
/// KiB. If the bodies total more, the blob is one anonymous temp file in
/// `tmp/` of the repository, mapped read-only. The job then keeps no copy of
/// the bodies on the heap.
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
        check_inline_part(compression, body, entry)?;
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
            let map = index_delta_map(&bytes)?.ok_or_else(|| {
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
    delta_digest(name, entry).map(Some)
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
        return apply_part(
            txn,
            payload.as_slice(),
            &entry.objects,
            &staging,
            checks,
            job.image_key,
        )
        .await;
    }
    let path = format!("{}/{index}", job.dir);
    let staging = txn.staging_fd().try_clone_to_owned()?;
    let blob = match source {
        DeltaSource::Remote(remote) => match remote.transfer() {
            Transfer::Http(fetcher) => fetch_part_blob(fetcher, &path, entry, &staging).await?,
            // The size of the part in the superblock caps the body.
            Transfer::Stream(stream) => {
                let body = stream.get(&path, entry.size).await?.ok_or_else(|| {
                    Error::InvalidFormat(format!(
                        "static delta {}: the remote holds no part {index}",
                        job.name
                    ))
                })?;
                decode_part_stream(body, entry, &staging)
                    .await
                    .map_err(session_error)?
            }
        },
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
    apply_part(
        txn,
        blob.as_slice(),
        &entry.objects,
        &staging,
        checks,
        job.image_key,
    )
    .await
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
    use crate::pull::TimestampBase;
    use ostrya_core::Type;

    fn checksum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    /// The digest lookup reads the `ay` in the variant, returns `None` for an
    /// absent delta, and refuses an entry of another type or of another
    /// length.
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
        for len in [31, 33] {
            crate::commit::append_dict_entry(
                &mut map,
                &format!("digest-of-{len}"),
                Value::variant(Type::parse("ay").unwrap(), Value::Bytes(vec![0x33; len])),
            )
            .unwrap();
        }

        assert_eq!(map_digest(&map, "delta-name").unwrap(), Some(digest));
        assert_eq!(map_digest(&map, "absent").unwrap(), None);
        assert!(matches!(
            map_digest(&map, "not-a-digest"),
            Err(Error::InvalidFormat(_))
        ));
        for name in ["digest-of-31", "digest-of-33"] {
            assert!(
                matches!(map_digest(&map, name), Err(Error::InvalidFormat(_))),
                "{name}"
            );
        }
    }

    /// The scan for `<from>-<to>` keys finds the lowercase key to `to` alone.
    /// It skips an uppercase source, another target, the from-scratch key,
    /// and a key that is not a delta name, and these keys do not stop it.
    #[test]
    fn source_candidates_finds_the_keys_to_the_target() {
        let (from, to, other) = (checksum(0xa1), checksum(0xf0), checksum(0xb2));
        let (from_hex, to_hex) = (from.to_hex(), to.to_hex());
        let found = delta_name(Some(&from), &to);
        let mut map = Value::Array(Vec::new());
        for name in [
            format!("{}-{to_hex}", from_hex.to_uppercase()),
            delta_name(Some(&from), &other),
            delta_name(None, &to),
            format!("zz-{to_hex}"),
            found.clone(),
        ] {
            crate::commit::append_dict_entry(
                &mut map,
                &name,
                Value::variant(
                    Type::parse("ay").unwrap(),
                    Value::Bytes(name.as_bytes().to_vec()),
                ),
            )
            .unwrap();
        }

        let candidates: Vec<_> = source_candidates(&map, &to).collect();
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        let (candidate, name, value) = candidates[0];
        assert_eq!((candidate, name), (from, found.as_str()));
        assert_eq!(
            value.as_variant().and_then(|(_, bytes)| bytes.as_bytes()),
            Some(found.as_bytes())
        );
    }

    /// The base64 of a 64-byte ed25519 secret key (seed, then public key).
    const SECRET_B64: &str =
        "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
    /// The matching 32-byte ed25519 public key.
    const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

    /// The verification of a pull that checks the commits against the
    /// ed25519 key [`PUBLIC_B64`].
    fn ed25519_verification() -> Verification {
        use crate::sign::{Ed25519Verifier, Verifier};
        let verifier = Ed25519Verifier::new(
            [ostrya_core::base64::decode(PUBLIC_B64).unwrap()],
            Vec::<Vec<u8>>::new(),
        )
        .unwrap();
        let keys = crate::verify::TrustedKeys::new(vec![
            std::sync::Arc::new(verifier) as Arc<dyn Verifier>
        ])
        .unwrap();
        Verification::from_trust(crate::verify::PullTrust::commits(keys))
    }

    fn unverified() -> Verification {
        Verification::from_trust(crate::verify::PullTrust::unverified())
    }

    /// Signs `commit` in `repo` with the key [`SECRET_B64`].
    async fn sign(repo: &Repo, commit: &Checksum) {
        let signer = crate::sign::Ed25519Signer::from_base64(SECRET_B64).unwrap();
        repo.sign_commit(commit, &signer).await.unwrap();
    }

    /// Writes a commit whose tree holds the file `f` with `content`, and
    /// returns it.
    async fn commit(repo: &Repo, parent: Option<Checksum>, content: &[u8]) -> Checksum {
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
            subject: None,
            body: None,
            timestamp: Some(1_700_000_000),
            metadata: None,
        };
        let commit = txn.write_commit(options, &root).await.unwrap();
        txn.commit().await.unwrap();
        commit
    }

    /// A source repository with the commits `A-B-C-D` and `A-X-Y`, and a
    /// repository that holds `A` complete under the ref `main`.
    struct Fixture {
        root: std::path::PathBuf,
        src: Repo,
        dst: Repo,
        a: Checksum,
        b: Checksum,
        c: Checksum,
        d: Checksum,
        x: Checksum,
        y: Checksum,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    impl Fixture {
        async fn new() -> Fixture {
            let root = std::env::temp_dir().join(format!(
                "ostrya-delta-chain-{}-{}",
                std::process::id(),
                crate::write::unique()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let create = || crate::CreateOptions::new(RepoMode::Archive);
            let src = Repo::create(&root.join("src"), create()).await.unwrap();
            let dst = Repo::create(&root.join("dst"), create()).await.unwrap();
            let a = commit(&src, None, b"a").await;
            let b = commit(&src, Some(a), b"b").await;
            let c = commit(&src, Some(b), b"c").await;
            let d = commit(&src, Some(c), b"d").await;
            let x = commit(&src, Some(a), b"x").await;
            let y = commit(&src, Some(x), b"y").await;
            src.set_ref_immediate("main", Some(&a)).await.unwrap();
            let opts = PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            };
            dst.pull_local(&src, opts).await.unwrap();
            Fixture {
                root,
                src,
                dst,
                a,
                b,
                c,
                d,
                x,
                y,
            }
        }

        /// Generates the delta from `from` to `to` in the source, and returns
        /// its entry of a list.
        async fn delta(&self, from: Option<Checksum>, to: Checksum) -> AdvertisedDelta {
            let options = crate::DeltaOptions {
                timestamp: Some(1_700_000_000),
                ..crate::DeltaOptions::default()
            };
            self.src
                .generate_static_delta(from.as_ref(), &to, &options)
                .await
                .unwrap();
            AdvertisedDelta {
                from,
                to,
                superblock: Checksum::sha256(&std::fs::read(self.superblock(from, to)).unwrap()),
            }
        }

        /// Returns the path of the superblock of a delta in the source.
        fn superblock(&self, from: Option<Checksum>, to: Checksum) -> std::path::PathBuf {
            self.src
                .path()
                .join(delta_relative_dir(from.as_ref(), &to))
                .join(SUPERBLOCK_FILE)
        }

        /// Runs the discovery of `list` for the targets `targets`.
        async fn discover(
            &self,
            list: Vec<AdvertisedDelta>,
            targets: &[(&str, Checksum)],
            opts: &PullOptions,
            verification: &Verification,
            counters: &PullCounters,
        ) -> Result<DeltaPlan> {
            let targets: Vec<(String, Checksum)> = targets
                .iter()
                .map(|(name, commit)| ((*name).to_owned(), *commit))
                .collect();
            discover(
                &self.dst,
                &DeltaSource::Local(&self.src),
                None,
                &targets,
                opts,
                TipChecks::new(opts.flags, TimestampBase::Off, RefPlace::Heads),
                Some(Edges::new(list)?),
                verification,
                counters,
            )
            .await
        }
    }

    fn required() -> PullOptions {
        PullOptions {
            require_static_deltas: true,
            ..PullOptions::default()
        }
    }

    /// Returns the source and the target of the record of each commit.
    fn record_steps(plan: &DeltaPlan) -> HashMap<Checksum, (Option<Checksum>, Checksum)> {
        plan.records
            .iter()
            .map(|(commit, record)| (*commit, (record.delta.from, record.delta.to)))
            .collect()
    }

    /// A chain of three steps gives three records and two levels, in order.
    /// It needs no summary, also if the pull requires static deltas. The
    /// parse of a level gives the job of each of its commits.
    #[test]
    fn a_chain_of_three_steps_gives_three_records_and_two_levels() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let list = vec![
                f.delta(Some(f.a), f.b).await,
                f.delta(Some(f.b), f.c).await,
                f.delta(Some(f.c), f.d).await,
            ];
            let counters = PullCounters::new(None);
            let plan = f
                .discover(
                    list,
                    &[("main", f.d)],
                    &required(),
                    &unverified(),
                    &counters,
                )
                .await
                .unwrap();
            assert!(plan.jobs.is_empty());
            assert_eq!(plan.levels, [vec![f.b], vec![f.c]]);
            assert_eq!(
                record_steps(&plan),
                HashMap::from([
                    (f.b, (Some(f.a), f.b)),
                    (f.c, (Some(f.b), f.c)),
                    (f.d, (Some(f.c), f.d)),
                ])
            );
            assert!(plan.store.is_none());
            for commit in [f.b, f.c, f.d] {
                assert!(matches!(
                    plan.records[&commit].detached,
                    Detached::Checked { kept: None, .. }
                ));
            }
            assert_eq!(counters.metadata(), 3);

            let source = DeltaSource::Local(&f.src);
            for level in &plan.levels {
                let jobs = plan.parse_level(&f.dst, &source, level).await.unwrap();
                assert_eq!(jobs.len(), 1);
                let (commit, job) = jobs.iter().next().unwrap();
                assert_eq!(Checksum::sha256(&job.commit_bytes), *commit);
                assert_eq!(job.fetched_parts(), plan.records[commit].parts);
            }
            // The second read of a superblock counts nothing.
            assert_eq!(counters.metadata(), 3);
            let jobs = plan
                .parse_level(&f.dst, &source, &[f.d, f.a])
                .await
                .unwrap();
            assert_eq!(jobs.keys().collect::<Vec<_>>(), [&f.d]);
        });
    }

    /// A missing superblock in the middle of a chain makes discovery plan
    /// again and take the second chain. The record of the step that it
    /// fetched before the miss is dropped.
    #[test]
    fn a_missing_superblock_makes_discovery_take_another_chain() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let list = vec![
                f.delta(Some(f.a), f.b).await,
                f.delta(Some(f.b), f.c).await,
                f.delta(Some(f.c), f.d).await,
                f.delta(Some(f.a), f.x).await,
                f.delta(Some(f.x), f.y).await,
                f.delta(Some(f.y), f.d).await,
            ];
            std::fs::remove_file(f.superblock(Some(f.b), f.c)).unwrap();
            let counters = PullCounters::new(None);
            let plan = f
                .discover(
                    list,
                    &[("main", f.d)],
                    &required(),
                    &unverified(),
                    &counters,
                )
                .await
                .unwrap();
            assert_eq!(plan.levels, [vec![f.x], vec![f.y]]);
            assert_eq!(
                record_steps(&plan),
                HashMap::from([
                    (f.x, (Some(f.a), f.x)),
                    (f.y, (Some(f.x), f.y)),
                    (f.d, (Some(f.y), f.d)),
                ])
            );
            assert_eq!(counters.metadata(), 5);
        });
    }

    /// A missing superblock in the middle of the only chain gives no chain.
    /// A pull that requires static deltas then fails.
    #[test]
    fn a_missing_superblock_with_no_other_chain_gives_no_chain() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let list = vec![
                f.delta(Some(f.a), f.b).await,
                f.delta(Some(f.b), f.c).await,
                f.delta(Some(f.c), f.d).await,
            ];
            std::fs::remove_file(f.superblock(Some(f.b), f.c)).unwrap();
            let counters = PullCounters::new(None);
            let plan = f
                .discover(
                    list.clone(),
                    &[("main", f.d)],
                    &PullOptions::default(),
                    &unverified(),
                    &counters,
                )
                .await
                .unwrap();
            assert!(plan.records.is_empty());
            assert!(plan.levels.is_empty());
            assert!(!plan.checked(&f.d));
            assert_eq!(counters.metadata(), 2);

            let err = f
                .discover(
                    list,
                    &[("main", f.d)],
                    &required(),
                    &unverified(),
                    &PullCounters::new(None),
                )
                .await
                .err()
                .unwrap();
            let Error::Pull(message) = err else {
                panic!("{err:?}");
            };
            assert_eq!(
                message,
                format!("Static deltas required, but none found for main to {}", f.d)
            );
        });
    }

    /// A wrong digest gives `ChecksumMismatch`. A superblock that produces
    /// another commit than its entry fails. The parse of a level checks the
    /// superblock of a local source again.
    #[test]
    fn a_superblock_that_does_not_match_the_list_fails() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let ab = f.delta(Some(f.a), f.b).await;
            let bc = f.delta(Some(f.b), f.c).await;
            let mut cd = f.delta(Some(f.c), f.d).await;
            let run = |list: Vec<AdvertisedDelta>| async {
                f.discover(
                    list,
                    &[("main", f.d)],
                    &PullOptions::default(),
                    &unverified(),
                    &PullCounters::new(None),
                )
                .await
            };

            let right = cd.superblock;
            cd.superblock = Checksum::from_bytes([0xee; 32]);
            let err = run(vec![ab, bc, cd]).await.err().unwrap();
            assert!(
                matches!(err, Error::ChecksumMismatch { expected, actual }
                    if expected == cd.superblock && actual == right),
                "{err:?}"
            );

            let ab_bytes = std::fs::read(f.superblock(Some(f.a), f.b)).unwrap();
            std::fs::write(f.superblock(Some(f.c), f.d), &ab_bytes).unwrap();
            cd.superblock = ab.superblock;
            let err = run(vec![ab, bc, cd]).await.err().unwrap();
            assert!(matches!(err, Error::Pull(_)), "{err:?}");

            // The parse of a level reads the superblock of the source again.
            let cd = f.delta(Some(f.c), f.d).await;
            let plan = run(vec![ab, bc, cd]).await.unwrap();
            let source = DeltaSource::Local(&f.src);
            std::fs::write(f.superblock(Some(f.b), f.c), &ab_bytes).unwrap();
            let err = plan
                .parse_level(&f.dst, &source, &plan.levels[1])
                .await
                .err()
                .unwrap();
            assert!(
                matches!(err, Error::ChecksumMismatch { expected, .. } if expected == bc.superblock),
                "{err:?}"
            );
            std::fs::remove_file(f.superblock(Some(f.b), f.c)).unwrap();
            let err = plan
                .parse_level(&f.dst, &source, &plan.levels[1])
                .await
                .err()
                .unwrap();
            assert!(matches!(err, Error::InvalidFormat(_)), "{err:?}");
        });
    }

    /// An intermediate commit with no valid signature fails discovery. With
    /// valid signatures, discovery counts the `.commitmeta` of each
    /// intermediate commit once.
    #[test]
    fn an_intermediate_commit_with_no_valid_signature_fails() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            sign(&f.src, &f.c).await;
            sign(&f.src, &f.d).await;
            let list = vec![
                f.delta(Some(f.a), f.b).await,
                f.delta(Some(f.b), f.c).await,
                f.delta(Some(f.c), f.d).await,
            ];
            let err = f
                .discover(
                    list.clone(),
                    &[("main", f.d)],
                    &PullOptions::default(),
                    &ed25519_verification(),
                    &PullCounters::new(None),
                )
                .await
                .err()
                .unwrap();
            assert!(matches!(err, Error::Signature(_)), "{err:?}");

            sign(&f.src, &f.b).await;
            let counters = PullCounters::new(None);
            let plan = f
                .discover(
                    list,
                    &[("main", f.d)],
                    &PullOptions::default(),
                    &ed25519_verification(),
                    &counters,
                )
                .await
                .unwrap();
            assert_eq!(plan.records.len(), 3);
            assert_eq!(counters.metadata(), 5);
        });
    }

    /// A target gets its check when discovery fetches its step. A later plan
    /// that makes the target an intermediate commit keeps that check. A
    /// target that fails its check fails discovery before the next superblock
    /// request.
    #[test]
    fn a_target_that_becomes_an_intermediate_commit_keeps_its_check() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            sign(&f.src, &f.d).await;
            let list = vec![
                f.delta(Some(f.a), f.c).await,
                f.delta(Some(f.a), f.d).await,
                f.delta(Some(f.c), f.d).await,
            ];
            std::fs::remove_file(f.superblock(Some(f.a), f.d)).unwrap();
            let targets = [("main", f.c), ("other", f.d)];
            let counters = PullCounters::new(None);
            let plan = f
                .discover(
                    list.clone(),
                    &targets,
                    &PullOptions::default(),
                    &unverified(),
                    &counters,
                )
                .await
                .unwrap();
            assert_eq!(plan.levels, [vec![f.c]]);
            for commit in [f.c, f.d] {
                assert!(plan.checked(&commit), "{commit}");
            }
            assert_eq!(counters.metadata(), 3);

            let counters = PullCounters::new(None);
            let err = f
                .discover(
                    list,
                    &targets,
                    &PullOptions::default(),
                    &ed25519_verification(),
                    &counters,
                )
                .await
                .err()
                .unwrap();
            assert!(matches!(err, Error::Signature(_)), "{err:?}");
            // The superblock of the step to `C` alone.
            assert_eq!(counters.metadata(), 1);
        });
    }

    /// Discovery checks the signatures of a target that has a chain. An
    /// unsigned target fails discovery. A signed target has a record that
    /// discovery checked, and a commit with no record is not checked.
    #[test]
    fn a_target_with_a_chain_is_checked_in_discovery() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            sign(&f.src, &f.b).await;
            sign(&f.src, &f.c).await;
            let list = vec![
                f.delta(Some(f.a), f.b).await,
                f.delta(Some(f.b), f.c).await,
                f.delta(Some(f.c), f.d).await,
            ];
            let err = f
                .discover(
                    list.clone(),
                    &[("main", f.d)],
                    &PullOptions::default(),
                    &ed25519_verification(),
                    &PullCounters::new(None),
                )
                .await
                .err()
                .unwrap();
            assert!(matches!(err, Error::Signature(_)), "{err:?}");

            sign(&f.src, &f.d).await;
            let plan = f
                .discover(
                    list,
                    &[("main", f.d)],
                    &PullOptions::default(),
                    &ed25519_verification(),
                    &PullCounters::new(None),
                )
                .await
                .unwrap();
            for commit in [f.b, f.c, f.d] {
                assert!(plan.checked(&commit), "{commit}");
            }
            assert!(!plan.checked(&f.a));
            assert!(matches!(
                plan.commit_check(&f.d).await.unwrap(),
                CommitCheck::Checked { detached: None, .. }
            ));
        });
    }

    /// A listed delta from scratch that the scratch rule refuses meets the
    /// requirement, and discovery keeps no record for it. With no delta to
    /// the target, a pull that requires static deltas fails.
    #[test]
    fn a_refused_delta_from_scratch_meets_the_requirement() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let list = vec![f.delta(None, f.d).await];
            let counters = PullCounters::new(None);
            let plan = f
                .discover(
                    list,
                    &[("main", f.d)],
                    &required(),
                    &unverified(),
                    &counters,
                )
                .await
                .unwrap();
            assert!(plan.records.is_empty());
            assert_eq!(counters.metadata(), 0);

            let err = f
                .discover(
                    Vec::new(),
                    &[("main", f.d)],
                    &required(),
                    &unverified(),
                    &PullCounters::new(None),
                )
                .await
                .err()
                .unwrap();
            assert!(matches!(err, Error::Pull(_)), "{err:?}");
        });
    }

    /// A commit-only pull ignores the list and sends no request.
    #[test]
    fn a_commit_only_pull_ignores_the_list() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let list = vec![f.delta(Some(f.a), f.d).await];
            let opts = PullOptions {
                flags: PullFlags::COMMIT_ONLY,
                ..required()
            };
            let counters = PullCounters::new(None);
            let plan = f
                .discover(list, &[("main", f.d)], &opts, &unverified(), &counters)
                .await
                .unwrap();
            assert!(plan.records.is_empty() && plan.jobs.is_empty());
            assert_eq!(counters.metadata(), 0);
        });
    }

    /// A superblock with the listed target and another source fails.
    #[test]
    fn a_superblock_from_another_source_fails() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let ax = f.delta(Some(f.a), f.x).await;
            let xy = f.delta(Some(f.x), f.y).await;
            f.delta(Some(f.c), f.d).await;
            let cd_bytes = std::fs::read(f.superblock(Some(f.c), f.d)).unwrap();
            let yd_path = f.superblock(Some(f.y), f.d);
            std::fs::create_dir_all(yd_path.parent().unwrap()).unwrap();
            std::fs::write(&yd_path, &cd_bytes).unwrap();
            let yd = AdvertisedDelta {
                from: Some(f.y),
                to: f.d,
                superblock: Checksum::sha256(&cd_bytes),
            };
            let err = f
                .discover(
                    vec![ax, xy, yd],
                    &[("main", f.d)],
                    &PullOptions::default(),
                    &unverified(),
                    &PullCounters::new(None),
                )
                .await
                .err()
                .unwrap();
            assert!(matches!(err, Error::Pull(_)), "{err:?}");
        });
    }

    /// An intermediate commit that a later plan makes a target alone keeps
    /// its check. Discovery does not read its `.commitmeta` again and does
    /// not count it.
    #[test]
    fn an_intermediate_commit_that_becomes_a_target_keeps_its_check() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            for commit in [f.c, f.x, f.d] {
                sign(&f.src, &commit).await;
            }
            let list = vec![
                f.delta(Some(f.a), f.c).await,
                f.delta(Some(f.c), f.d).await,
                f.delta(Some(f.a), f.x).await,
                f.delta(Some(f.x), f.d).await,
            ];
            std::fs::remove_file(f.superblock(Some(f.c), f.d)).unwrap();
            let counters = PullCounters::new(None);
            let plan = f
                .discover(
                    list,
                    &[("c", f.c), ("main", f.d)],
                    &PullOptions::default(),
                    &ed25519_verification(),
                    &counters,
                )
                .await
                .unwrap();
            assert_eq!(plan.levels, [vec![f.x]]);
            assert_eq!(
                record_steps(&plan),
                HashMap::from([
                    (f.c, (Some(f.a), f.c)),
                    (f.x, (Some(f.a), f.x)),
                    (f.d, (Some(f.x), f.d)),
                ])
            );
            for commit in [f.c, f.x, f.d] {
                assert!(matches!(
                    plan.records[&commit].detached,
                    Detached::Checked { kept: None, .. }
                ));
            }
            // Four superblock requests and the `.commitmeta` of `X`.
            assert_eq!(counters.metadata(), 5);
        });
    }

    /// A step from scratch to a target is allowed if the scratch rule allows
    /// it for one of the refs that name the target, in each order of the
    /// refs.
    #[test]
    fn one_ref_that_allows_a_step_from_scratch_is_sufficient() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let list = vec![f.delta(None, f.d).await];
            for targets in [
                [("main", f.d), ("other", f.d)],
                [("other", f.d), ("main", f.d)],
            ] {
                let plan = f
                    .discover(
                        list.clone(),
                        &targets,
                        &required(),
                        &unverified(),
                        &PullCounters::new(None),
                    )
                    .await
                    .unwrap();
                assert_eq!(record_steps(&plan), HashMap::from([(f.d, (None, f.d))]));
            }
        });
    }

    /// Two refs that name one target give one chain. A target that this
    /// repository holds complete gives no record and no request.
    #[test]
    fn a_target_is_planned_once_and_a_complete_target_not_at_all() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let list = vec![
                f.delta(Some(f.a), f.b).await,
                f.delta(Some(f.b), f.c).await,
                f.delta(Some(f.c), f.d).await,
            ];
            let counters = PullCounters::new(None);
            let plan = f
                .discover(
                    list.clone(),
                    &[("main", f.a), ("main", f.d), ("copy", f.d)],
                    &required(),
                    &unverified(),
                    &counters,
                )
                .await
                .unwrap();
            assert_eq!(plan.levels, [vec![f.b], vec![f.c]]);
            assert_eq!(plan.records.len(), 3);
            assert_eq!(counters.metadata(), 3);

            let counters = PullCounters::new(None);
            let plan = f
                .discover(
                    list,
                    &[("main", f.a)],
                    &required(),
                    &unverified(),
                    &counters,
                )
                .await
                .unwrap();
            assert!(plan.records.is_empty() && plan.levels.is_empty());
            assert_eq!(counters.metadata(), 0);
        });
    }

    /// A local source counts the `.commitmeta` of the intermediate commits of
    /// the last plan alone. An intermediate commit that a later plan drops is
    /// not counted, also if the check read its `.commitmeta`.
    #[test]
    fn a_dropped_intermediate_commit_is_not_counted() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            for commit in [f.b, f.x, f.y, f.d] {
                sign(&f.src, &commit).await;
            }
            let list = vec![
                f.delta(Some(f.a), f.b).await,
                f.delta(Some(f.b), f.c).await,
                f.delta(Some(f.c), f.d).await,
                f.delta(Some(f.a), f.x).await,
                f.delta(Some(f.x), f.y).await,
                f.delta(Some(f.y), f.d).await,
            ];
            std::fs::remove_file(f.superblock(Some(f.b), f.c)).unwrap();
            for verification in [unverified(), ed25519_verification()] {
                let counters = PullCounters::new(None);
                let plan = f
                    .discover(
                        list.clone(),
                        &[("main", f.d)],
                        &PullOptions::default(),
                        &verification,
                        &counters,
                    )
                    .await
                    .unwrap();
                assert_eq!(plan.levels, [vec![f.x], vec![f.y]]);
                // Five superblock requests, and the `.commitmeta` of `X` and
                // `Y`. The `.commitmeta` of `B` is not counted.
                assert_eq!(counters.metadata(), 7);
            }
        });
    }

    /// Discovery plans again around a limited number of missing superblocks.
    /// After the limit, a target whose chain holds a missing delta gets no
    /// chain, and a pull that requires static deltas fails.
    #[test]
    fn discovery_plans_again_around_a_limited_number_of_missing_deltas() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let ab = f.delta(Some(f.a), f.b).await;
            let bd = f.delta(Some(f.b), f.d).await;
            let list = |missing: usize| {
                let mut list = Vec::new();
                for i in 0..missing {
                    let mut bytes = [0x80; 32];
                    bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
                    let alternative = Checksum::from_bytes(bytes);
                    list.push(AdvertisedDelta {
                        from: Some(f.a),
                        to: alternative,
                        superblock: checksum(0x11),
                    });
                    list.push(AdvertisedDelta {
                        from: Some(alternative),
                        to: f.d,
                        superblock: checksum(0x11),
                    });
                }
                list.extend([ab, bd]);
                list
            };
            let limit = super::super::chain::MAX_EXCLUDED;

            let counters = PullCounters::new(None);
            let plan = f
                .discover(
                    list(limit),
                    &[("main", f.d)],
                    &required(),
                    &unverified(),
                    &counters,
                )
                .await
                .unwrap();
            assert_eq!(plan.levels, [vec![f.b]]);
            assert_eq!(plan.records.len(), 2);
            assert_eq!(counters.metadata(), limit as u32 + 2);

            let counters = PullCounters::new(None);
            let plan = f
                .discover(
                    list(limit + 1),
                    &[("main", f.d)],
                    &PullOptions::default(),
                    &unverified(),
                    &counters,
                )
                .await
                .unwrap();
            assert!(plan.records.is_empty() && plan.levels.is_empty());
            assert_eq!(counters.metadata(), limit as u32 + 1);

            let err = f
                .discover(
                    list(limit + 1),
                    &[("main", f.d)],
                    &required(),
                    &unverified(),
                    &PullCounters::new(None),
                )
                .await
                .err()
                .unwrap();
            assert!(matches!(err, Error::Pull(_)), "{err:?}");
        });
    }

    /// Returns the bytes that a server sends for the reply to `PullHello`
    /// and one found reply for each of `bodies`, in order.
    async fn served(bodies: &[&[u8]]) -> Vec<u8> {
        use crate::remote::proto::{
            FrameWriter, GetReply, Message, PULL_PROTOCOL_VERSION, PullHelloReply,
        };
        let mut writer = FrameWriter::new(futures_lite::io::Cursor::new(Vec::new()));
        writer
            .write_message(&Message::PullHelloReply(PullHelloReply {
                version: PULL_PROTOCOL_VERSION,
            }))
            .await
            .unwrap();
        for body in bodies {
            writer
                .write_message(&Message::GetReply(GetReply {
                    found: true,
                    len: Some(body.len() as u64),
                }))
                .await
                .unwrap();
            writer.write_object_data(body).await.unwrap();
            writer.end_object().await.unwrap();
        }
        writer.into_inner().into_inner()
    }

    /// Returns a remote source whose server answers with `bodies`, in order.
    async fn remote(bodies: &[&[u8]]) -> RemoteSource {
        let session = crate::remote::StreamSession::over_stream(
            futures_lite::io::Cursor::new(served(bodies).await),
            futures_lite::io::sink(),
            Default::default(),
        )
        .await
        .unwrap();
        RemoteSource::new(
            crate::remote::PullSession::Stream(session).into(),
            Vec::new(),
        )
    }

    /// From a remote, the record file keeps each superblock and the
    /// `.commitmeta` of each commit of a chain, the target included. A
    /// localcache repository that holds the `.commitmeta` comes first, and
    /// the remote does not serve it. The parse of a level reads the record
    /// file.
    #[test]
    fn a_remote_record_keeps_the_superblock_and_the_commitmeta() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            sign(&f.src, &f.b).await;
            sign(&f.src, &f.d).await;
            let list = vec![f.delta(Some(f.a), f.b).await, f.delta(Some(f.b), f.d).await];
            let ab = std::fs::read(f.superblock(Some(f.a), f.b)).unwrap();
            let bd = std::fs::read(f.superblock(Some(f.b), f.d)).unwrap();
            let meta = f
                .src
                .load_object_bytes(ObjectType::CommitMeta, &f.b)
                .await
                .unwrap();
            let meta_d = f
                .src
                .load_object_bytes(ObjectType::CommitMeta, &f.d)
                .await
                .unwrap();
            let targets = vec![("main".to_owned(), f.d)];
            for (localcache, bodies, metadata) in [
                (
                    Vec::new(),
                    vec![&ab[..], &meta[..], &bd[..], &meta_d[..]],
                    4,
                ),
                (vec![f.src.clone()], vec![&ab[..], &bd[..]], 2),
            ] {
                let source = remote(&bodies).await;
                let source = DeltaSource::Remote(&source);
                let opts = PullOptions {
                    localcache_repos: localcache,
                    ..PullOptions::default()
                };
                let counters = PullCounters::new(None);
                let mut plan = discover(
                    &f.dst,
                    &source,
                    None,
                    &targets,
                    &opts,
                    TipChecks::new(opts.flags, TimestampBase::Off, RefPlace::Heads),
                    Some(Edges::new(list.clone()).unwrap()),
                    &ed25519_verification(),
                    &counters,
                )
                .await
                .unwrap();
                assert_eq!(counters.metadata(), metadata);
                assert_eq!(plan.levels, [vec![f.b]]);
                let store = plan.store.as_ref().unwrap();
                let b = &plan.records[&f.b];
                let Detached::Checked {
                    kept: Some(kept), ..
                } = &b.detached
                else {
                    panic!("no kept .commitmeta");
                };
                assert_eq!(store.read(kept.clone()).await.unwrap(), meta);
                for (commit, bytes) in [(f.b, &ab), (f.d, &bd)] {
                    let range = plan.records[&commit].superblock.clone().unwrap();
                    assert_eq!(&store.read(range).await.unwrap(), bytes);
                }
                let jobs = plan.parse_level(&f.dst, &source, &[f.b]).await.unwrap();
                assert_eq!(Checksum::sha256(&jobs[&f.b].commit_bytes), f.b);
                let CommitCheck::Checked {
                    detached: Some(read),
                    ..
                } = plan.commit_check(&f.b).await.unwrap()
                else {
                    panic!("no checked .commitmeta");
                };
                assert_eq!(read, meta);
                let CommitCheck::Checked {
                    detached: Some(read),
                    ..
                } = plan.commit_check(&f.d).await.unwrap()
                else {
                    panic!("no checked .commitmeta of the target");
                };
                assert_eq!(read, meta_d);
                let jobs = plan.target_jobs(&f.dst, &source).await.unwrap();
                assert_eq!(jobs.keys().copied().collect::<Vec<_>>(), [f.d]);
                assert_eq!(Checksum::sha256(&jobs[&f.d].commit_bytes), f.d);
            }
        });
    }

    /// Returns the bytes that a server sends for one found reply for each of
    /// `bodies`, in order.
    async fn replies(bodies: &[&[u8]]) -> Vec<u8> {
        use crate::remote::proto::{FrameWriter, GetReply, Message};
        let mut writer = FrameWriter::new(futures_lite::io::Cursor::new(Vec::new()));
        for body in bodies {
            writer
                .write_message(&Message::GetReply(GetReply {
                    found: true,
                    len: Some(body.len() as u64),
                }))
                .await
                .unwrap();
            writer.write_object_data(body).await.unwrap();
            writer.end_object().await.unwrap();
        }
        writer.into_inner().into_inner()
    }

    /// The request bytes that the client of a gated session wrote, and the
    /// task that waits for more of them.
    #[derive(Default)]
    struct Requests {
        written: Vec<u8>,
        waker: Option<std::task::Waker>,
    }

    impl Requests {
        /// Returns `true` if the client wrote each path of `paths`.
        fn hold(&self, paths: &[String]) -> bool {
            paths.iter().all(|path| {
                self.written
                    .windows(path.len())
                    .any(|window| window == path.as_bytes())
            })
        }
    }

    /// The output of the client of a gated session. It keeps each byte and
    /// wakes the input.
    struct GatedOutput {
        requests: Arc<std::sync::Mutex<Requests>>,
    }

    impl futures_io::AsyncWrite for GatedOutput {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let mut requests = self.requests.lock().unwrap();
            requests.written.extend_from_slice(buf);
            if let Some(waker) = requests.waker.take() {
                waker.wake();
            }
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// The input of the client of a gated session. The server sends the
    /// bytes of each step of the script in order. It holds the bytes of a
    /// step until the client wrote each path of that step.
    struct GatedInput {
        requests: Arc<std::sync::Mutex<Requests>>,
        script: std::collections::VecDeque<(Vec<String>, Vec<u8>)>,
        /// The bytes of the current step, and the position of the next read.
        current: (Vec<u8>, usize),
    }

    impl futures_io::AsyncRead for GatedInput {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            loop {
                let (bytes, at) = &mut self.current;
                if *at < bytes.len() {
                    let n = buf.len().min(bytes.len() - *at);
                    buf[..n].copy_from_slice(&bytes[*at..*at + n]);
                    *at += n;
                    return std::task::Poll::Ready(Ok(n));
                }
                let Some((paths, _)) = self.script.front() else {
                    return std::task::Poll::Ready(Ok(0));
                };
                let requests = Arc::clone(&self.requests);
                let mut requests = requests.lock().unwrap();
                if !requests.hold(paths) {
                    requests.waker = Some(cx.waker().clone());
                    return std::task::Poll::Pending;
                }
                drop(requests);
                let (_, bytes) = self.script.pop_front().unwrap();
                self.current = (bytes, 0);
            }
        }
    }

    /// Returns a remote source whose server sends the bytes of each step of
    /// `script` in order, and the requests that its client writes. A step
    /// holds the paths that the client must write before the server sends
    /// its bytes.
    async fn gated_remote(
        script: Vec<(Vec<String>, Vec<u8>)>,
    ) -> (RemoteSource, Arc<std::sync::Mutex<Requests>>) {
        let requests = Arc::new(std::sync::Mutex::new(Requests::default()));
        let mut script: std::collections::VecDeque<_> = script.into();
        script.push_front((Vec::new(), served(&[]).await));
        let input = GatedInput {
            requests: Arc::clone(&requests),
            script,
            current: (Vec::new(), 0),
        };
        let output = GatedOutput {
            requests: Arc::clone(&requests),
        };
        let session = crate::remote::StreamSession::over_stream(input, output, Default::default())
            .await
            .unwrap();
        let source = RemoteSource::new(
            crate::remote::PullSession::Stream(session).into(),
            Vec::new(),
        );
        (source, requests)
    }

    /// Over a stream session, discovery sends the superblock request and the
    /// `.commitmeta` request of each step as one pair. The server of the test
    /// holds the reply to a superblock until the request of the `.commitmeta`
    /// arrives, so a discovery that sends them one after the other does not
    /// end. A localcache repository that holds the `.commitmeta` comes first,
    /// and discovery then sends the superblock request alone. The counts and
    /// the record file are as for a discovery with no pair.
    #[test]
    fn a_stream_discovery_sends_the_superblock_and_the_commitmeta_as_a_pair() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            sign(&f.src, &f.b).await;
            sign(&f.src, &f.d).await;
            let list = vec![f.delta(Some(f.a), f.b).await, f.delta(Some(f.b), f.d).await];
            let ab = std::fs::read(f.superblock(Some(f.a), f.b)).unwrap();
            let bd = std::fs::read(f.superblock(Some(f.b), f.d)).unwrap();
            let meta_b = f
                .src
                .load_object_bytes(ObjectType::CommitMeta, &f.b)
                .await
                .unwrap();
            let meta_d = f
                .src
                .load_object_bytes(ObjectType::CommitMeta, &f.d)
                .await
                .unwrap();
            let superblock = |from: Checksum, to: Checksum| {
                format!("{}/{SUPERBLOCK_FILE}", delta_relative_dir(Some(&from), &to))
            };
            let commitmeta = |commit: &Checksum| {
                format!(
                    "objects/{}",
                    ostrya_core::loose_path(commit, ObjectType::CommitMeta, RepoMode::Archive)
                )
            };
            let paired = vec![
                (
                    vec![superblock(f.a, f.b), commitmeta(&f.b)],
                    replies(&[&ab, &meta_b]).await,
                ),
                (
                    vec![superblock(f.b, f.d), commitmeta(&f.d)],
                    replies(&[&bd, &meta_d]).await,
                ),
            ];
            let cached = vec![
                (vec![superblock(f.a, f.b)], replies(&[&ab]).await),
                (vec![superblock(f.b, f.d)], replies(&[&bd]).await),
            ];
            let targets = vec![("main".to_owned(), f.d)];
            for (localcache, script, metadata) in
                [(Vec::new(), paired, 4), (vec![f.src.clone()], cached, 2)]
            {
                let (source, requests) = gated_remote(script).await;
                let source = DeltaSource::Remote(&source);
                let opts = PullOptions {
                    localcache_repos: localcache,
                    ..PullOptions::default()
                };
                let counters = PullCounters::new(None);
                let verification = ed25519_verification();
                let discovery = discover(
                    &f.dst,
                    &source,
                    None,
                    &targets,
                    &opts,
                    TipChecks::new(opts.flags, TimestampBase::Off, RefPlace::Heads),
                    Some(Edges::new(list.clone()).unwrap()),
                    &verification,
                    &counters,
                );
                let plan = futures_lite::future::or(discovery, async {
                    ostrya_rt::Timer::after(std::time::Duration::from_secs(10)).await;
                    panic!("discovery sent the requests of a step one after the other");
                })
                .await
                .unwrap();
                assert_eq!(counters.metadata(), metadata);
                let written = requests.lock().unwrap().written.clone();
                let position = |path: String| {
                    written
                        .windows(path.len())
                        .position(|window| window == path.as_bytes())
                };
                if opts.localcache_repos.is_empty() {
                    // The superblock request of a step comes first.
                    for (from, to) in [(f.a, f.b), (f.b, f.d)] {
                        assert!(position(superblock(from, to)) < position(commitmeta(&to)));
                    }
                } else {
                    assert_eq!(position(".commitmeta".to_owned()), None);
                }
                let store = plan.store.as_ref().unwrap();
                for (commit, meta) in [(f.b, &meta_b), (f.d, &meta_d)] {
                    let Detached::Checked {
                        kept: Some(kept), ..
                    } = &plan.records[&commit].detached
                    else {
                        panic!("no kept .commitmeta of {commit}");
                    };
                    assert_eq!(&store.read(kept.clone()).await.unwrap(), meta);
                }
                for (commit, bytes) in [(f.b, &ab), (f.d, &bd)] {
                    let range = plan.records[&commit].superblock.clone().unwrap();
                    assert_eq!(&store.read(range).await.unwrap(), bytes);
                }
            }
        });
    }

    /// Over a stream session, the remote does not hold the superblock of the
    /// first planned step, `a->d`, and serves the paired `.commitmeta` of `d`.
    /// Discovery drops that `.commitmeta`, plans again over `a->c` and `c->d`,
    /// and requests the `.commitmeta` of `d` again. The session stays usable,
    /// and the record of `d` keeps the `.commitmeta` of the second request.
    #[test]
    fn a_stream_pair_with_a_missing_superblock_plans_again() {
        ostrya_rt::block_on(async {
            use crate::remote::proto::{FrameWriter, GetReply, Message};
            let f = Fixture::new().await;
            sign(&f.src, &f.c).await;
            sign(&f.src, &f.d).await;
            let missing = AdvertisedDelta {
                from: Some(f.a),
                to: f.d,
                superblock: checksum(0x11),
            };
            let list = vec![
                missing,
                f.delta(Some(f.a), f.c).await,
                f.delta(Some(f.c), f.d).await,
            ];
            let ac = std::fs::read(f.superblock(Some(f.a), f.c)).unwrap();
            let cd = std::fs::read(f.superblock(Some(f.c), f.d)).unwrap();
            let meta_c = f
                .src
                .load_object_bytes(ObjectType::CommitMeta, &f.c)
                .await
                .unwrap();
            let meta_d = f
                .src
                .load_object_bytes(ObjectType::CommitMeta, &f.d)
                .await
                .unwrap();
            let superblock = |from: Checksum, to: Checksum| {
                format!("{}/{SUPERBLOCK_FILE}", delta_relative_dir(Some(&from), &to))
            };
            let commitmeta = |commit: &Checksum| {
                format!(
                    "objects/{}",
                    ostrya_core::loose_path(commit, ObjectType::CommitMeta, RepoMode::Archive)
                )
            };
            let mut not_found = FrameWriter::new(futures_lite::io::Cursor::new(Vec::new()));
            not_found
                .write_message(&Message::GetReply(GetReply {
                    found: false,
                    len: None,
                }))
                .await
                .unwrap();
            let mut first = not_found.into_inner().into_inner();
            first.extend(replies(&[&meta_d]).await);
            let script = vec![
                (vec![superblock(f.a, f.d), commitmeta(&f.d)], first),
                (
                    vec![superblock(f.a, f.c), commitmeta(&f.c)],
                    replies(&[&ac, &meta_c]).await,
                ),
                (vec![superblock(f.c, f.d)], replies(&[&cd, &meta_d]).await),
                (vec!["config".to_owned()], replies(&[b"after"]).await),
            ];
            let (source, requests) = gated_remote(script).await;
            let source = DeltaSource::Remote(&source);
            let counters = PullCounters::new(None);
            let targets = vec![("main".to_owned(), f.d)];
            let opts = PullOptions::default();
            let verification = ed25519_verification();
            let discovery = discover(
                &f.dst,
                &source,
                None,
                &targets,
                &opts,
                TipChecks::new(opts.flags, TimestampBase::Off, RefPlace::Heads),
                Some(Edges::new(list).unwrap()),
                &verification,
                &counters,
            );
            let plan = futures_lite::future::or(discovery, async {
                ostrya_rt::Timer::after(std::time::Duration::from_secs(10)).await;
                panic!("discovery sent the requests of a step one after the other");
            })
            .await
            .unwrap();
            // The superblock requests count three, and the `.commitmeta`
            // files that the remote serves count three: `d` twice and `c`
            // once. Over HTTP the count is 5, because the pull requests no
            // `.commitmeta` for the missing superblock.
            assert_eq!(counters.metadata(), 6);
            let written = String::from_utf8_lossy(&requests.lock().unwrap().written).into_owned();
            assert_eq!(written.matches(&commitmeta(&f.d)).count(), 2);
            assert_eq!(plan.levels, [vec![f.c]]);
            assert!(plan.checked(&f.c) && plan.checked(&f.d));
            let CommitCheck::Checked {
                detached: Some(read),
                ..
            } = plan.commit_check(&f.d).await.unwrap()
            else {
                panic!("no checked .commitmeta of the target");
            };
            assert_eq!(read, meta_d);
            let after = source
                .read("config", 1024, &PullCounters::new(None))
                .await
                .unwrap();
            assert_eq!(after.as_deref(), Some(&b"after"[..]));
        });
    }

    /// The record file keeps the raw superblock, and a record reads it back
    /// from there, also after the source drops the superblock.
    #[test]
    fn the_record_file_keeps_the_superblock() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let delta = f.delta(Some(f.a), f.b).await;
            let mut store = RecordStore::new(&f.dst);
            assert!(store.file.is_none());
            let range = store
                .append(b"padding".to_vec(), || "padding".to_owned())
                .await
                .unwrap();
            assert_eq!(range, 0..7);
            assert_eq!(store.read(range).await.unwrap(), b"padding");
            let source = DeltaSource::Local(&f.src);
            let (fetched, kept) = fetch_job(
                &source,
                delta.from,
                delta.to,
                Some(delta.superblock),
                &unverified(),
                &PullCounters::new(None),
                Some(&mut store),
            )
            .await
            .unwrap()
            .unwrap();
            let len = std::fs::metadata(f.superblock(delta.from, delta.to))
                .unwrap()
                .len();
            assert_eq!(kept, Some(7..7 + len));
            let record = StepRecord {
                delta,
                parts: fetched.parts(),
                superblock: kept,
                detached: Detached::NotChecked,
            };
            std::fs::remove_file(f.superblock(delta.from, delta.to)).unwrap();
            let read = read_record(Some(&store), &source, &record).await.unwrap();
            assert_eq!(read.commit_bytes, fetched.commit_bytes);
            assert_eq!(Checksum::sha256(&read.commit_bytes), f.b);
            assert_eq!(read.meta_entries.len(), fetched.meta_entries.len());
        });
    }

    /// The record file takes bytes up to its limit. One more byte fails with
    /// `Error::Pull`, which names the limit, and the file stays as it was.
    #[test]
    fn the_record_file_stops_at_its_limit() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let mut store = RecordStore {
                limit: 10,
                ..RecordStore::new(&f.dst)
            };
            let range = store
                .append(vec![0x5a; 10], || "ten bytes".to_owned())
                .await
                .unwrap();
            assert_eq!(range, 0..10);
            let err = store
                .append(vec![0x5a], || "one byte".to_owned())
                .await
                .err()
                .unwrap();
            let Error::Pull(message) = &err else {
                panic!("{err:?}");
            };
            assert!(message.contains("one byte"), "{message}");
            assert!(message.contains("10 bytes"), "{message}");
            assert_eq!(store.len, 10);
            let file = store.file.as_ref().unwrap();
            assert_eq!(file.metadata().unwrap().len(), 10);
            assert_eq!(store.read(0..10).await.unwrap(), [0x5a; 10]);
        });
    }

    /// A superblock that would pass the limit of the record file fails
    /// before the file opens. The request still counts.
    #[test]
    fn a_superblock_past_the_limit_fails_before_the_write() {
        ostrya_rt::block_on(async {
            let f = Fixture::new().await;
            let delta = f.delta(Some(f.a), f.b).await;
            let len = std::fs::metadata(f.superblock(delta.from, delta.to))
                .unwrap()
                .len();
            let mut store = RecordStore {
                limit: len - 1,
                ..RecordStore::new(&f.dst)
            };
            let counters = PullCounters::new(None);
            let err = fetch_job(
                &DeltaSource::Local(&f.src),
                delta.from,
                delta.to,
                Some(delta.superblock),
                &unverified(),
                &counters,
                Some(&mut store),
            )
            .await
            .err()
            .unwrap();
            let Error::Pull(message) = &err else {
                panic!("{err:?}");
            };
            assert!(
                message.contains(&delta_name(delta.from.as_ref(), &delta.to)),
                "{message}"
            );
            assert!(store.file.is_none());
            assert_eq!(store.len, 0);
            assert_eq!(counters.metadata(), 1);
        });
    }
}
