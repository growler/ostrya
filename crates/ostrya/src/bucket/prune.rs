//! The prune of a bucket repository.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use futures_lite::future::zip;
use ostrya_core::{Checksum, ObjectName, ObjectType, RepoMode};

use super::lock::{LockHolder, LockOperation, WriterLock};
use super::state::{BucketRefs, marker_key};
use super::{BucketRepo, ObjectListing, each_slot, invalid, object_key, release_on_error};
use crate::delta::parse_delta_dir;
use crate::deltagen::delta_name;
use crate::error::{Error, Result};
use crate::object::MAX_METADATA_SIZE;
use crate::prune::{PruneOptions, PruneStats, counted};
use crate::remote::s3::{Bucket, Upload, is_repository_key};
use crate::summary::{SUMMARY_READ_CAP, Summary};
use crate::traverse::{GcRoots, MetadataSource, ParentBound, walk_reachable_gc};

/// The most deletes or aborts that a phase sends after one check of the
/// lock.
const CHECK_INTERVAL: usize = 1000;

/// The size above which the walk hashes a metadata object on the blocking
/// pool: 1 MiB.
pub(super) const UNBLOCK_SIZE: usize = 1024 * 1024;

/// The options of [`BucketRepo::prune`] other than the [`PruneOptions`].
///
/// A caller sets the fields of [`default`](Default::default), because the
/// struct is `#[non_exhaustive]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BucketPruneOptions {
    /// Remove the writer lock of another writer before the run takes its
    /// own, as [`BucketRepo::lock`] states.
    pub break_lock: bool,
}

/// The result of [`BucketRepo::prune`].
///
/// With [`no_prune`](PruneOptions::no_prune), each list names what a run
/// without `no_prune` deletes or aborts, and the run changes nothing but the
/// probe key of the writer lock.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BucketPruneReport {
    /// The counts of the run, as the counts of
    /// [`Repo::prune`](crate::Repo::prune) state them.
    ///
    /// The sizes come from the listing of the objects. A delete of a key
    /// that holds no object counts too.
    /// [`deleted_refs`](PruneStats::deleted_refs) is always empty, because
    /// the run deletes no ref.
    pub stats: PruneStats,
    /// The name of each static delta whose keys the run deleted, sorted.
    ///
    /// The name is the hex of the target commit for a delta from scratch,
    /// and `FROM-TO` for other deltas.
    pub deleted_deltas: Vec<String>,
    /// Each commit whose partial-commit marker the run deleted, sorted.
    pub deleted_markers: Vec<Checksum>,
    /// Each incomplete multipart upload that the run aborted, sorted by key,
    /// then by upload id.
    pub aborted_uploads: Vec<Upload>,
    /// The holder of the lock that the break of the lock deleted, or `None`
    /// if the run deleted no lock.
    ///
    /// The holder is reported on success alone. A run that breaks the lock
    /// and then fails returns its error, and the holder of the deleted lock
    /// is not in it.
    pub broken_lock: Option<LockHolder>,
}

/// The objects that the walk of a prune reads: the objects that the listing
/// of the run holds.
///
/// The run holds the writer lock, so an object that the listing does not
/// hold is absent, and the source sends no request for it. A read takes at
/// most the size of the object in the listing. The source checks the
/// SHA-256 of each commit and dirtree that it reads against its name.
struct ListedObjects<'a> {
    repo: &'a BucketRepo,
    listing: &'a ObjectListing,
}

impl MetadataSource for ListedObjects<'_> {
    async fn load_metadata(&self, ty: ObjectType, checksum: Checksum) -> Result<Option<Vec<u8>>> {
        let name = ObjectName::new(checksum, ty);
        let Some(&listed) = self.listing.objects.get(&name) else {
            return Ok(None);
        };
        let key = object_key(&name);
        if listed > MAX_METADATA_SIZE {
            return Err(self.repo.malformed(format!(
                "the object {key} is larger than {MAX_METADATA_SIZE} bytes"
            )));
        }
        let bytes = match self.repo.bucket.get_strict(&key, listed).await {
            Ok(Some(object)) => object.bytes,
            Ok(None) => {
                return Err(self.repo.malformed(format!(
                    "the object {key} was in the listing and is gone at its read"
                )));
            }
            Err(crate::remote::Error::LimitExceeded(_)) => {
                return Err(self.repo.malformed(format!(
                    "the object {key} is larger than its size in the listing, {listed} bytes"
                )));
            }
            Err(e) => return Err(e.into()),
        };
        if !matches!(ty, ObjectType::Commit | ObjectType::DirTree) {
            return Ok(Some(bytes));
        }
        let hash = move || (Checksum::sha256(&bytes), bytes);
        let (actual, bytes) = if listed > UNBLOCK_SIZE as u64 {
            ostrya_rt::unblock(hash).await
        } else {
            hash()
        };
        if actual != checksum {
            return Err(self.repo.malformed(format!(
                "the object {key} has the checksum {actual}, which is not the checksum of its \
                 name; the prune deletes nothing until `ostrya remote fsck --delete` repairs \
                 the repository"
            )));
        }
        Ok(Some(bytes))
    }
}

/// The changes of one run, in the order of the run.
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    /// The key of each commit object to delete, each with the keys of its
    /// detached metadata and of its composefs image when these go too,
    /// sorted by commit.
    commits: Vec<Vec<String>>,
    /// Each detached metadata and each composefs image to delete whose
    /// commit object the listing does not hold, in the order of the keys.
    orphans: Vec<ObjectName>,
    /// Each other object to delete, in the order of the keys.
    content: Vec<ObjectName>,
    /// The superblock key of each static delta to delete, sorted.
    superblocks: Vec<Vec<String>>,
    /// The other keys of each static delta to delete, sorted.
    parts: Vec<Vec<String>>,
    /// The commits whose partial-commit markers go, sorted.
    markers: Vec<Checksum>,
    /// The name of each static delta to delete, sorted.
    deltas: Vec<String>,
    /// The counts of the run.
    stats: PruneStats,
}

impl BucketRepo {
    /// Deletes the objects of the bucket repository that no root reaches,
    /// with the static deltas and the partial-commit markers of the commits
    /// that are not in the bucket after the run, and aborts each incomplete
    /// multipart upload.
    ///
    /// The run keeps the objects that [`Repo::prune`](crate::Repo::prune)
    /// keeps with the same options in a local repository with the same
    /// objects and refs, and the commits that the summary names. A kept
    /// commit keeps its detached metadata and its composefs image. Unless the
    /// roots are on the refs alone, the run also deletes the detached
    /// metadata and the composefs image of a parent commit that the listing
    /// does not hold. `Repo::prune` keeps these when its bound reaches that
    /// parent. The run deletes no ref, writes no summary, and leaves the `summary`, the
    /// `summary.sig`, the `delta-indexes/`, and each `.tombstone-commit` as
    /// they are. The bucket repository module states the run under "The
    /// prune".
    ///
    /// # Options
    ///
    /// The run takes [`refs_only`](PruneOptions::refs_only),
    /// [`depth`](PruneOptions::depth),
    /// [`keep_younger_than`](PruneOptions::keep_younger_than), and
    /// [`no_prune`](PruneOptions::no_prune), as [`Repo::prune`](crate::Repo::prune)
    /// takes them. Each other option must keep its default value.
    ///
    /// # Roots
    ///
    /// The commit of each ref is a root under the bound of the run. The
    /// commit of each ref of the summary, field 0 and
    /// `ostree.summary.collection-map`, is a root that keeps no parent.
    /// Unless the roots are on the refs alone, each commit of the listing is
    /// a root too. In that case, each root keeps no parent, so the walk reads
    /// each commit of the listing once: each commit of the listing is a root
    /// of its own. With `refs_only` or `keep_younger_than`, the walk can read
    /// a commit again when it reaches the commit under a bound that goes
    /// further.
    ///
    /// The walk reads each commit and dirtree that it reaches with one `GET`,
    /// one at a time, and checks its SHA-256 against its name. It sends no
    /// request for an object that the listing does not hold, and reads such
    /// an object as absent. An absent commit or dirtree keeps its own name
    /// and nothing below it.
    ///
    /// # Steps
    ///
    /// 1. The refusal of the options, before any request.
    /// 2. The read of the `config`, by the strict rule of an absent key, and
    ///    then the take of the writer lock for [`LockOperation::Prune`] with
    ///    [`break_lock`](BucketPruneOptions::break_lock). A run with
    ///    `no_prune` takes the lock too.
    /// 3. At the same time: the refs, the listing of the objects, the list of
    ///    `deltas/`, the partial-commit markers, the list of the incomplete
    ///    multipart uploads, and the read of the `summary`.
    /// 4. The walk. With `no_prune`, the run then releases the lock and
    ///    returns the report.
    /// 5. The commits: each commit object, and then its detached metadata
    ///    and its composefs image, one slot for each commit. Then each
    ///    detached metadata and each composefs image whose commit object the
    ///    listing does not hold.
    /// 6. Each other object.
    /// 7. The superblock of each static delta whose target commit is not in
    ///    the bucket after the run, and then each other key of these
    ///    deltas. A delta directory with no superblock goes too. A key under
    ///    `deltas/` that fails [`is_repository_key`], and a directory whose
    ///    name does not decode as a delta, stay. Then the partial-commit
    ///    marker of each commit that is not in the bucket after the run.
    /// 8. The abort of each incomplete multipart upload.
    /// 9. The release of the lock.
    ///
    /// The run checks the lock before each of the steps 5 to 8 that has a
    /// change to make, and again after each 1000 deletes or aborts of a step.
    /// At most `max_outstanding` deletes or aborts run at a time, as
    /// [`new`](BucketRepo::new) states. Each delete is one `DELETE` of one
    /// key.
    ///
    /// A run that fails after its first delete leaves a bucket repository
    /// that a reader can use: each commit object in the bucket has the
    /// objects of its tree, because the commits go first. A later run
    /// deletes the rest.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if an option other than `refs_only`,
    ///   `depth`, `keep_younger_than`, and `no_prune` is not at its default
    ///   value. The message names the first such field, in the order of the
    ///   fields. The run then sends no request.
    /// - [`Error::Remote`] with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the bucket
    ///   repository has no `config`, or if its `config` sets
    ///   `[core] tombstone-commits` to `true` or sets
    ///   `[ex-ostrya] gc-root-metadata-keys`. The run then takes no lock.
    /// - [`Error::InvalidFormat`] if the `config` breaks a rule of a bucket
    ///   repository, if a key under `refs/` is no ref key, if a ref file is
    ///   malformed or is gone at its read, if the summary does not parse or
    ///   is larger than its cap, or if a commit or a dirtree that the walk
    ///   reads is larger than its cap or than its size in the listing, is
    ///   gone at its read, or does not have the checksum of its name. The run
    ///   then deletes nothing. Run `ostrya remote fsck --delete` to repair
    ///   an object whose checksum is wrong.
    /// - [`Error::Core`] if a commit or a dirtree that the walk reads does
    ///   not parse. The run then deletes nothing.
    /// - The errors of [`lock`](BucketRepo::lock). A lock of another writer
    ///   fails the run before it reads an object.
    /// - [`Error::BucketLockLost`] if a check of the lock or the release
    ///   fails. The run then sends no more deletes and releases no lock.
    /// - [`Error::Remote`] for an error of the bucket client. The run then
    ///   releases its lock and drops an error of that release. A failure
    ///   after the first delete leaves the deletes that completed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ostrya::PruneOptions;
    /// use ostrya::bucket::{BucketPruneOptions, BucketRepo};
    /// use ostrya::remote::s3::{Environment, S3Endpoint, Settings};
    /// # async fn run() -> ostrya::Result<()> {
    /// let endpoint =
    ///     S3Endpoint::resolve("s3://builds/exampleos", &Settings::default(), &Environment::Process)
    ///         .await?;
    /// let repo = BucketRepo::open(&endpoint).await?;
    /// let mut opts = PruneOptions::default();
    /// opts.refs_only = true;
    /// opts.depth = 0;
    /// let report = repo.prune(&opts, &BucketPruneOptions::default()).await?;
    /// println!(
    ///     "deleted {} of {} objects",
    ///     report.stats.pruned_objects, report.stats.total_objects
    /// );
    /// # Ok(()) }
    /// ```
    pub async fn prune(
        &self,
        opts: &PruneOptions,
        bucket_opts: &BucketPruneOptions,
    ) -> Result<BucketPruneReport> {
        refuse_options(opts)?;
        let Some(config) = self.read_config_strict().await? else {
            return Err(invalid(format!(
                "the bucket repository {} has no config; init it first",
                self.address()
            )));
        };
        if config.tombstone_commits()? {
            return Err(invalid(format!(
                "the config of the bucket repository {} sets [core] tombstone-commits to true, \
                 and the prune of a bucket repository writes no tombstone",
                self.address()
            )));
        }
        if config
            .keyfile()
            .get_value("ex-ostrya", "gc-root-metadata-keys")
            .is_some()
        {
            return Err(invalid(format!(
                "the config of the bucket repository {} sets [ex-ostrya] gc-root-metadata-keys, \
                 and the prune of a bucket repository reads no metadata key",
                self.address()
            )));
        }
        let own = config.collection_id();
        let lock = self
            .lock(LockOperation::Prune, bucket_opts.break_lock)
            .await?;
        let broken_lock = lock.broken().cloned();
        let (plan, uploads) = match self.prune_plan(opts, own).await {
            Ok(planned) => planned,
            Err(e) => return Err(release_on_error(lock, e).await),
        };
        if !opts.no_prune
            && let Err(e) = self.prune_apply(&plan, &uploads, &lock).await
        {
            return Err(release_on_error(lock, e).await);
        }
        lock.release().await?;
        Ok(BucketPruneReport {
            stats: plan.stats,
            deleted_deltas: plan.deltas,
            deleted_markers: plan.markers,
            aborted_uploads: uploads,
            broken_lock,
        })
    }

    /// Reads the state of the repository, walks it, and returns the plan of
    /// the run and the incomplete multipart uploads, sorted.
    async fn prune_plan(
        &self,
        opts: &PruneOptions,
        own: Option<&str>,
    ) -> Result<(Plan, Vec<Upload>)> {
        let (refs, (listing, (deltas, (partial, (uploads, summary))))) = zip(
            self.read_refs(own),
            zip(
                self.list_objects(),
                zip(
                    self.bucket.list("deltas/"),
                    zip(
                        self.partial_commits(),
                        zip(self.bucket.list_uploads(), self.summary_commits()),
                    ),
                ),
            ),
        )
        .await;
        let (refs, listing, deltas) = (refs?, listing?, deltas?);
        let (partial, mut uploads, summary) = (partial?, uploads?, summary?);
        uploads.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then_with(|| a.upload_id.cmp(&b.upload_id))
        });
        let keep = self.prune_walk(opts, &refs, &summary, &listing).await?;
        let deltas: Vec<&str> = deltas
            .objects
            .iter()
            .map(|listed| listed.key.as_str())
            .collect();
        Ok((plan(&listing, &keep, &deltas, &partial), uploads))
    }

    /// Returns the name of each object that the roots of the run reach.
    async fn prune_walk(
        &self,
        opts: &PruneOptions,
        refs: &BucketRefs,
        summary: &BTreeSet<Checksum>,
        listing: &ObjectListing,
    ) -> Result<HashSet<ObjectName>> {
        let targets: HashSet<Checksum> = refs
            .heads
            .values()
            .chain(refs.mirrors.values().flat_map(BTreeMap::values))
            .copied()
            .collect();
        let global = opts.global_bound();
        let mut roots: Vec<(Checksum, ParentBound)> = Vec::new();
        if opts.roots_on_refs_alone() {
            roots.extend(targets.iter().map(|commit| (*commit, global)));
            // The root of a ref target already keeps the commit and its
            // tree, so a second root for it at no parent only reads it again.
            roots.extend(
                summary
                    .iter()
                    .filter(|commit| !targets.contains(commit))
                    .map(|commit| (*commit, ParentBound::Depth(0))),
            );
        } else {
            // Each commit of the listing is a root, so a root that keeps no
            // parent keeps the same objects of the listing, and the walk
            // reads each commit once. The name of a parent commit that the
            // listing does not hold is then not kept, so the plan deletes
            // the detached metadata and the composefs image of that commit.
            roots.extend(
                targets
                    .iter()
                    .chain(summary)
                    .copied()
                    .chain(
                        listing
                            .objects
                            .keys()
                            .filter(|name| name.ty == ObjectType::Commit)
                            .map(|name| name.checksum),
                    )
                    .map(|commit| (commit, ParentBound::Depth(0))),
            );
        }
        let gc = GcRoots {
            metadata_keys: Vec::new(),
            traverse_parent: true,
            traverse_tree: true,
            weak_roots: Default::default(),
        };
        let source = ListedObjects {
            repo: self,
            listing,
        };
        walk_reachable_gc(&source, roots, global, &gc, &targets, None).await
    }

    /// Returns each commit that the `summary` of the repository names, in
    /// field 0 and in `ostree.summary.collection-map`, or an empty set if
    /// the key holds no object.
    ///
    /// The read takes the strict rule of an absent key, up to the read cap
    /// of a summary. The parse runs on the blocking pool.
    async fn summary_commits(&self) -> Result<BTreeSet<Checksum>> {
        let bytes = match self.bucket.get_strict("summary", SUMMARY_READ_CAP).await {
            Ok(Some(object)) => object.bytes,
            Ok(None) => return Ok(BTreeSet::new()),
            Err(crate::remote::Error::LimitExceeded(_)) => {
                return Err(self.malformed(format!(
                    "its summary is larger than {SUMMARY_READ_CAP} bytes"
                )));
            }
            Err(e) => return Err(e.into()),
        };
        let parsed = ostrya_rt::unblock(move || -> Result<BTreeSet<Checksum>> {
            let summary = Summary::parse(&bytes)?;
            let mut commits: BTreeSet<Checksum> =
                summary.refs.iter().map(|entry| entry.commit).collect();
            for (_, entries) in summary.collection_map()? {
                commits.extend(entries.iter().map(|entry| entry.commit));
            }
            Ok(commits)
        })
        .await;
        parsed.map_err(|e| self.malformed(format!("its summary does not parse: {e}")))
    }

    /// Sends the deletes and the aborts of `plan` and `uploads` under
    /// `lock`, in the order of the run.
    async fn prune_apply(
        &self,
        plan: &Plan,
        uploads: &[Upload],
        lock: &WriterLock<'_>,
    ) -> Result<()> {
        let bucket = &self.bucket;
        let one = |key: String| async move {
            bucket.delete(&key).await?;
            Ok(())
        };
        // The commits, with the sidecars of the absent commits.
        let mut sent = None;
        self.run_each(lock, &mut sent, &plan.commits, Vec::len, |keys| {
            delete_in_order(bucket, keys)
        })
        .await?;
        self.run_each(
            lock,
            &mut sent,
            &plan.orphans,
            |_| 1,
            |name| one(object_key(name)),
        )
        .await?;
        // The other objects.
        let mut sent = None;
        self.run_each(
            lock,
            &mut sent,
            &plan.content,
            |_| 1,
            |name| one(object_key(name)),
        )
        .await?;
        // The static deltas, each superblock first, and the markers.
        let mut sent = None;
        self.run_each(lock, &mut sent, &plan.superblocks, Vec::len, |keys| {
            delete_in_order(bucket, keys)
        })
        .await?;
        self.run_each(lock, &mut sent, &plan.parts, Vec::len, |keys| {
            delete_in_order(bucket, keys)
        })
        .await?;
        self.run_each(
            lock,
            &mut sent,
            &plan.markers,
            |_| 1,
            |commit| one(marker_key(commit)),
        )
        .await?;
        // The incomplete multipart uploads.
        let mut sent = None;
        self.run_each(
            lock,
            &mut sent,
            uploads,
            |_| 1,
            |upload| async move {
                bucket.abort_upload(&upload.key, &upload.upload_id).await?;
                Ok(())
            },
        )
        .await
    }

    /// Runs `op` on each item of `items`, at most `max_outstanding` at a
    /// time, and waits for each one before it returns.
    ///
    /// `sent` is the weight of the items of the step that ran since its last
    /// check of the lock, or `None` before its first check. The call checks
    /// the lock before the groups that [`groups`] gives, and updates `sent`.
    async fn run_each<'i, T, Fut>(
        &self,
        lock: &WriterLock<'_>,
        sent: &mut Option<usize>,
        items: &'i [T],
        weight: impl Fn(&T) -> usize,
        op: impl Fn(&'i T) -> Fut,
    ) -> Result<()>
    where
        Fut: Future<Output = Result<()>> + Send + 'i,
    {
        for (check, group) in groups(items, weight, sent) {
            if check {
                lock.check().await?;
            }
            each_slot(self.max_outstanding, group.iter().map(&op), |()| {}).await?;
        }
        Ok(())
    }
}

/// Refuses each option of `opts` that the prune of a bucket repository does
/// not take, in the order of the fields.
fn refuse_options(opts: &PruneOptions) -> Result<()> {
    let refused = [
        ("delete_commit", opts.delete_commit.is_some()),
        ("only_branch", !opts.only_branch.is_empty()),
        ("retain_branch_depth", !opts.retain_branch_depth.is_empty()),
        ("commit_only", opts.commit_only),
        ("static_deltas_only", opts.static_deltas_only),
        (
            "gc_root_metadata_keys",
            !opts.gc_root_metadata_keys.is_empty(),
        ),
        ("traverse_parent", !opts.traverse_parent),
        ("weak_ref_filter", opts.weak_ref_filter.is_set()),
    ];
    match refused.iter().find(|(_, set)| *set) {
        Some((field, _)) => Err(Error::InvalidInput(format!(
            "the prune of a bucket repository takes no option {field}; the option must keep its \
             default value"
        ))),
        None => Ok(()),
    }
}

/// Returns the plan of a run: the objects of `listing` that `keep` does not
/// hold, the static deltas of the keys `deltas` under `deltas/` and the
/// markers of `partial` whose commits are not in the bucket after the run,
/// and the counts.
fn plan(
    listing: &ObjectListing,
    keep: &HashSet<ObjectName>,
    deltas: &[&str],
    partial: &BTreeSet<Checksum>,
) -> Plan {
    let kept = |name: &ObjectName| {
        keep.contains(name)
            || (name.ty.is_commit_sidecar()
                && keep.contains(&ObjectName::new(name.checksum, ObjectType::Commit)))
    };
    // The objects of the listing that the run deletes.
    let doomed = |name: &ObjectName| {
        listing.objects.contains_key(name) && name.ty != ObjectType::TombstoneCommit && !kept(name)
    };
    let mut out = Plan {
        commits: Vec::new(),
        orphans: Vec::new(),
        content: Vec::new(),
        superblocks: Vec::new(),
        parts: Vec::new(),
        markers: Vec::new(),
        deltas: Vec::new(),
        stats: PruneStats {
            total_objects: listing
                .objects
                .keys()
                .filter(|name| counted(name.ty, false))
                .count(),
            pruned_objects: 0,
            freed_bytes: 0,
            deleted_refs: Vec::new(),
        },
    };
    let mut candidates: Vec<ObjectName> = Vec::new();
    for (name, size) in &listing.objects {
        if name.ty == ObjectType::TombstoneCommit || kept(name) {
            continue;
        }
        if counted(name.ty, false) {
            out.stats.pruned_objects += 1;
            out.stats.freed_bytes += size;
        }
        candidates.push(*name);
    }
    // The order of the checksum bytes, then of the extensions, is the order
    // of the keys, because the keys hold the checksums in lowercase hex.
    candidates.sort_unstable_by(|a, b| {
        a.checksum
            .as_bytes()
            .cmp(b.checksum.as_bytes())
            .then_with(|| {
                a.ty.extension(RepoMode::Archive)
                    .cmp(b.ty.extension(RepoMode::Archive))
            })
    });
    for name in &candidates {
        match name.ty {
            ObjectType::Commit => {
                let mut keys = vec![object_key(name)];
                for ty in [ObjectType::CommitMeta, ObjectType::ComposefsImage] {
                    let sidecar = ObjectName::new(name.checksum, ty);
                    if doomed(&sidecar) {
                        keys.push(object_key(&sidecar));
                    }
                }
                out.commits.push(keys);
            }
            ty if ty.is_commit_sidecar() => {
                let commit = ObjectName::new(name.checksum, ObjectType::Commit);
                if !listing.objects.contains_key(&commit) {
                    out.orphans.push(*name);
                }
            }
            _ => {}
        }
    }
    candidates.retain(|name| name.ty != ObjectType::Commit && !name.ty.is_commit_sidecar());
    out.content = candidates;
    // The commits that the bucket holds after the run.
    let present = |commit: &Checksum| {
        let name = ObjectName::new(*commit, ObjectType::Commit);
        listing.objects.contains_key(&name) && !doomed(&name)
    };
    out.markers = partial
        .iter()
        .filter(|commit| !present(commit))
        .copied()
        .collect();
    // The keys of each delta directory whose name decodes, by directory.
    let mut dirs: BTreeMap<(&str, &str), (String, Vec<&str>)> = BTreeMap::new();
    for &key in deltas {
        let mut parts = key.splitn(4, '/');
        let (Some("deltas"), Some(fanout), Some(leaf), Some(_)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let Ok((from, to)) = parse_delta_dir(fanout, leaf) else {
            continue;
        };
        if present(&to) || !is_repository_key(key) {
            continue;
        }
        dirs.entry((fanout, leaf))
            .or_insert_with(|| (delta_name(from.as_ref(), &to), Vec::new()))
            .1
            .push(key);
    }
    for ((fanout, leaf), (name, keys)) in dirs {
        let superblock = format!("deltas/{fanout}/{leaf}/superblock");
        for key in keys {
            if key == superblock {
                out.superblocks.push(vec![superblock.clone()]);
            } else {
                out.parts.push(vec![key.to_owned()]);
            }
        }
        out.deltas.push(name);
    }
    out.deltas.sort();
    out.superblocks.sort();
    out.parts.sort();
    out
}

/// Deletes `keys` in order.
async fn delete_in_order(bucket: &Bucket, keys: &[String]) -> Result<()> {
    for key in keys {
        bucket.delete(key).await?;
    }
    Ok(())
}

/// Splits `items` into groups in order, each with `true` if the lock is
/// checked before it.
///
/// `sent` is the weight of the items of the step that ran since its last
/// check of the lock, or `None` before its first check. The first item of a
/// step comes after a check. Each other item comes after a check if the
/// weight since the last check goes above [`CHECK_INTERVAL`] with it. So
/// after a check, a group holds items of at most `CHECK_INTERVAL` in all by
/// `weight`, or one item that weighs more. The call sets `sent` to the
/// weight since the last check after the last item.
fn groups<'i, T>(
    items: &'i [T],
    weight: impl Fn(&T) -> usize,
    sent: &mut Option<usize>,
) -> Vec<(bool, &'i [T])> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut check = false;
    for (at, item) in items.iter().enumerate() {
        let w = weight(item);
        let total = match *sent {
            Some(total) if total == 0 || total + w <= CHECK_INTERVAL => total,
            _ => {
                if at > start {
                    out.push((check, &items[start..at]));
                }
                start = at;
                check = true;
                0
            }
        };
        *sent = Some(total + w);
    }
    if start < items.len() {
        out.push((check, &items[start..]));
    }
    out
}

/// A compile-time check that the future of a prune is `Send`.
const _: fn() = || {
    fn assert_send<T: Send>(_: &T) {}
    let _ = |repo: &BucketRepo, opts: &PruneOptions, bucket: &BucketPruneOptions| {
        assert_send(&repo.prune(opts, bucket))
    };
};

#[cfg(test)]
mod tests {
    use super::*;

    fn csum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    fn name(byte: u8, ty: ObjectType) -> ObjectName {
        ObjectName::new(csum(byte), ty)
    }

    fn listing(names: &[(ObjectName, u64)]) -> ObjectListing {
        let mut listing = ObjectListing::default();
        listing.objects.extend(names.iter().copied());
        listing
    }

    #[test]
    fn a_doomed_commit_takes_its_sidecars_and_the_counts_leave_them_out() {
        let commit = name(1, ObjectType::Commit);
        let meta = name(1, ObjectType::CommitMeta);
        let image = name(1, ObjectType::ComposefsImage);
        let tombstone = name(1, ObjectType::TombstoneCommit);
        let orphan = name(2, ObjectType::CommitMeta);
        let tree = name(3, ObjectType::DirTree);
        let file = name(4, ObjectType::File);
        let kept = name(5, ObjectType::Commit);
        let kept_meta = name(5, ObjectType::CommitMeta);
        let listing = listing(&[
            (commit, 10),
            (meta, 20),
            (image, 30),
            (tombstone, 40),
            (orphan, 50),
            (tree, 60),
            (file, 70),
            (kept, 80),
            (kept_meta, 90),
        ]);
        let keep: HashSet<ObjectName> = [kept].into_iter().collect();
        let plan = plan(&listing, &keep, &[], &BTreeSet::new());
        assert_eq!(
            plan.commits,
            [vec![
                object_key(&commit),
                object_key(&meta),
                object_key(&image)
            ]]
        );
        assert_eq!(plan.orphans, [orphan]);
        assert_eq!(plan.content, [tree, file]);
        assert_eq!(plan.stats.total_objects, 4);
        assert_eq!(plan.stats.pruned_objects, 3);
        assert_eq!(plan.stats.freed_bytes, 10 + 60 + 70);
        assert!(plan.stats.deleted_refs.is_empty());
    }

    #[test]
    fn the_objects_to_delete_are_in_the_order_of_their_keys() {
        let types = [
            ObjectType::File,
            ObjectType::DirTree,
            ObjectType::DirMeta,
            ObjectType::PayloadLink,
            ObjectType::FileXattrs,
            ObjectType::FileXattrsLink,
        ];
        let mut names = Vec::new();
        for byte in [0x00, 0x0f, 0x10, 0x9a, 0xa0, 0xff] {
            for ty in types {
                names.push((name(byte, ty), 1));
            }
        }
        let plan = plan(&listing(&names), &HashSet::new(), &[], &BTreeSet::new());
        let keys: Vec<String> = plan.content.iter().map(object_key).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert_eq!(keys.len(), names.len());
    }

    #[test]
    fn the_deltas_and_the_markers_of_absent_commits_go() {
        let kept = csum(1);
        let doomed = csum(2);
        let absent = csum(3);
        let listing = listing(&[
            (ObjectName::new(kept, ObjectType::Commit), 1),
            (ObjectName::new(doomed, ObjectType::Commit), 1),
        ]);
        let keep: HashSet<ObjectName> = [ObjectName::new(kept, ObjectType::Commit)]
            .into_iter()
            .collect();
        let dir = |from: Option<&Checksum>, to: &Checksum| {
            let to = to.to_base64_modified();
            match from {
                Some(from) => {
                    let from = from.to_base64_modified();
                    format!("deltas/{}/{}-{to}", &from[..2], &from[2..])
                }
                None => format!("deltas/{}/{}", &to[..2], &to[2..]),
            }
        };
        let doomed_dir = dir(None, &doomed);
        let no_superblock = dir(Some(&kept), &absent);
        let kept_dir = dir(Some(&doomed), &kept);
        let deltas = [
            format!("{doomed_dir}/0"),
            format!("{doomed_dir}/superblock"),
            format!("{doomed_dir}/x/y"),
            format!("{no_superblock}/0"),
            format!("{kept_dir}/superblock"),
            "deltas/!!/bad/superblock".to_owned(),
            "deltas/short".to_owned(),
        ];
        let deltas: Vec<&str> = deltas.iter().map(String::as_str).collect();
        let partial: BTreeSet<Checksum> = [kept, doomed, absent].into_iter().collect();
        let plan = plan(&listing, &keep, &deltas, &partial);
        assert_eq!(plan.superblocks, [vec![format!("{doomed_dir}/superblock")]]);
        let mut parts = vec![
            vec![format!("{doomed_dir}/0")],
            vec![format!("{no_superblock}/0")],
        ];
        parts.sort();
        assert_eq!(plan.parts, parts);
        let mut names = vec![
            doomed.to_hex(),
            format!("{}-{}", kept.to_hex(), absent.to_hex()),
        ];
        names.sort();
        assert_eq!(plan.deltas, names);
        let mut markers = vec![doomed, absent];
        markers.sort();
        assert_eq!(plan.markers, markers);
    }

    #[test]
    fn a_group_holds_at_most_the_interval() {
        let items: Vec<usize> = vec![600, 400, 1, 2000, 3, 999, 1];
        let mut sent = None;
        let split = groups(&items, |w| *w, &mut sent);
        assert_eq!(
            split,
            [
                (true, &[600, 400][..]),
                (true, &[1][..]),
                (true, &[2000][..]),
                (true, &[3][..]),
                (true, &[999, 1][..])
            ]
        );
        assert_eq!(sent, Some(1000));
        let mut sent = None;
        assert!(groups(&[] as &[usize], |w| *w, &mut sent).is_empty());
        assert_eq!(sent, None);
        let ones = vec![1usize; 2500];
        let sizes: Vec<(bool, usize)> = groups(&ones, |_| 1, &mut sent)
            .iter()
            .map(|(check, group)| (*check, group.len()))
            .collect();
        assert_eq!(sizes, [(true, 1000), (true, 1000), (true, 500)]);
        assert_eq!(sent, Some(500));
    }

    #[test]
    fn the_next_list_of_a_step_carries_the_count_since_the_check() {
        let mut sent = Some(998);
        let split = groups(&[1usize, 1, 1, 5][..], |w| *w, &mut sent);
        assert_eq!(split, [(false, &[1, 1][..]), (true, &[1, 5][..])]);
        assert_eq!(sent, Some(6));
        // A list that fits after the last check gets no check.
        let split = groups(&[3usize][..], |w| *w, &mut sent);
        assert_eq!(split, [(false, &[3][..])]);
        assert_eq!(sent, Some(9));
        // An item that weighs more than the interval comes after a check.
        let split = groups(&[2000usize][..], |w| *w, &mut sent);
        assert_eq!(split, [(true, &[2000][..])]);
        assert_eq!(sent, Some(2000));
    }

    #[test]
    fn each_refused_option_is_named_in_field_order() {
        let mut opts = PruneOptions {
            refs_only: true,
            depth: 0,
            no_prune: true,
            keep_younger_than: Some(1),
            ..PruneOptions::default()
        };
        refuse_options(&opts).unwrap();
        opts.traverse_parent = false;
        opts.commit_only = true;
        match refuse_options(&opts) {
            Err(Error::InvalidInput(message)) => {
                assert!(message.contains("option commit_only;"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        opts.commit_only = false;
        match refuse_options(&opts) {
            Err(Error::InvalidInput(message)) => {
                assert!(message.contains("option traverse_parent;"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }
}
