//! Pull: importing refs and their objects from another repository.
//!
//! [`Repo::pull_local`] reads a local repository directly, described below;
//! [`Repo::pull`] fetches from an HTTP remote, described in
//! [`pull::http`](self::http). The two share the options, the flags, the
//! statistics, the ref-binding check, and the `.commitpartial` markers.
//!
//! [`Repo::pull_local`] copies a set of refs, the commits they name, and every
//! object those commits reach out of a source repository and into this one. The
//! objects are imported in one transaction, so a failure publishes none of them
//! and writes no ref. A commit's detached metadata is written as its objects are
//! imported, before the ref that names it, which is what a verifier reading the
//! signatures alongside the commit requires; a failed pull can therefore leave a
//! `.commitmeta` for a commit it did not publish, which prune sweeps.
//!
//! How an object is imported depends on how much of it the two repositories
//! store the same way.
//!
//! An imported object carries the filesystem metadata -- unix mode, ownership,
//! and xattrs -- a commit into this repository would have given it, and subject to
//! that it shares the source's bytes and its inode.
//!
//! An object with one shared representation is hardlinked into the transaction's
//! staging directory, which shares the source inode outright. Representation is
//! shared by every metadata object, which has one form in every mode; by every
//! content object between repositories of the same mode; and by a symlink object
//! between bare-user and bare-user-shared, which store one identically.
//!
//! A hardlink cannot separate the bytes from the ownership, so it is taken only
//! where the source inode's ownership is already what a write here produces. That
//! holds outright for a content object into a bare destination, whose uid, gid,
//! permission bits, and xattrs are all a function of the header its checksum
//! covers; two bare repositories therefore agree on such an inode byte for byte.
//! In every other mode ownership is a function of the writing process and the
//! staging directory, so the source inode's uid and gid are compared against the
//! pair an object freshly staged here takes. A pull between repositories owned
//! differently -- two group-shared repositories of differing groups, for one --
//! stops hardlinking, and its objects are written afresh with their bytes reflinked
//! where the filesystem supports it and copied where it does not.
//!
//! Ownership is all the source inode is read for. Its permission bits and its
//! xattrs are trusted to match the object's header rather than checked, and in
//! archive, bare-user, and bare-user-shared neither is covered by the object's
//! checksum, so a source whose inodes were rewritten out of band -- a copy that
//! dropped modes, a `chmod` over `objects/` -- carries that state into this
//! repository, as it does into a repository the tool pulls into. Attributes this
//! repository's environment assigns rather than its writer -- a default POSIX ACL
//! on its directories, a security label -- are not reapplied either: an object
//! written here inherits them and a linked one keeps the source's.
//!
//! A repository sealing its objects with fs-verity does not hardlink at all.
//! Verity is a per-inode property, so sealing a shared inode would seal the
//! source's copy too, and leaving it unsealed would break the destination's rule
//! that every object stored as a regular file is sealed. Such a destination copies
//! every object and seals each copy, which is a divergence from the tool: the tool
//! hardlinks into a `fsverity=yes` repository and leaves the imported objects
//! unsealed.
//!
//! A link refused, by either gate or by the filesystem -- the two repositories on
//! different filesystems, the source inode at its link limit, the kernel's
//! protected-hardlink rules, or [`FORCE_COPY`](PullFlags::FORCE_COPY) -- takes a
//! metadata object to a `FICLONE` reflink and then a byte copy of its bytes, with
//! the inode a metadata object written into this repository carries: 0644, no
//! xattrs, and the writing process's ownership. A content object goes to the
//! header path below, which is what gives an object the inode metadata a commit
//! into this repository would have written.
//!
//! A regular-file content object whose payload bytes the two modes share but
//! whose inode metadata they do not -- any pair within the bare family -- is
//! cloned: a `FICLONE`-then-copy move of the payload, with the destination's
//! inode policy applied afresh from the object's logical header. The header comes
//! from reading the object's metadata, not its payload.
//!
//! What remains is a content object crossing the archive boundary, whose stored
//! bytes are a framed, deflated form nothing else shares, and a symlink between
//! modes that store it differently. Those are read back into their logical form
//! (uid, gid, mode, xattrs, and payload) and written afresh through the ordinary
//! ingest path, which stores them the way the destination mode requires.
//!
//! A bare-user-only destination refuses a content object whose logical header is
//! not the one it stores. That mode records neither ownership nor xattrs and
//! reduces a regular file's permission bits to `perm & 0o755`, so a commit into it
//! names each object for the canonical header, while an import keeps the name the
//! object arrives under. A non-zero uid or gid, an xattr, and a regular-file mode
//! with bits outside `0755` are each rejected with [`Error::Pull`], since the
//! destination could hold such an object only under a name its stored form does
//! not hash to. This is a divergence from the tool, which hardlinks the object in
//! and leaves a repository its own fsck reports corrupt.
//!
//! Free space: the transaction's `min-free-space` budget is charged for the
//! blocks an import allocates. A hardlinked object allocates none and a reflinked
//! payload shares the source extents, so a pull whose objects the destination
//! shares with the source runs on a filesystem with no room for a second copy of
//! them; a byte-copied or re-ingested object is charged its full stored size.
//!
//! Source order: the source repository first, then each of
//! [`PullOptions::localcache_repos`] in turn. An object is taken from the first
//! source holding it, and the walk that decides what to import resolves each
//! commit and dirtree through the same order, so a subtree the source has lost is
//! enumerated from the cache that still holds it. An object no source holds is
//! named by the walk and fails the pull when the import reaches it, so a
//! published commit is complete.
//!
//! The commits of one pull are walked as one tree: a dirtree descended into for
//! one commit is not descended into again for another, so a deep pull of a chain
//! of near-identical trees reads each dirtree once. Each commit's plan therefore
//! carries the objects the commits ahead of it did not.
//!
//! Commit state: each commit being pulled gets a zero-length
//! `state/<commit>.commitpartial` marker before the commit object is stored,
//! removed once its objects are published. An interrupted pull therefore leaves the
//! commit marked partial, and a [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull
//! leaves the marker in place, since the commit's content was never fetched.
//! Both match the markers the `ostree` tool leaves behind. A marker already
//! present is left as it stands rather than rewritten, so the one-byte state
//! fsck writes survives a pull over the commit it marked.
//!
//! Marker durability: no marker is fsynced and neither is `state/`, which is
//! what the tool does. Every marker of a pull is written before
//! `Transaction::commit`, so the `syncfs` that opens publication makes it durable
//! ahead of the first object rename; a staged object enters `objects/` in that
//! rename, so no object a pull stages is reachable before the marker guarding it
//! is durable. A local pull writes all of its markers before the first import,
//! and an HTTP pull writes each commit's marker in the step that fetched that
//! commit. The removal is the pull's last operation and no barrier
//! follows it, so a crash immediately after a successful pull can leave a marker
//! on a commit that is complete. That direction costs availability rather than
//! integrity: checkout refuses the commit until the next pull of it, or a prune
//! of it, clears the marker.
//!
//! Trust: by default an object is imported without its checksum being checked,
//! which is what makes the link and clone paths possible.
//! [`UNTRUSTED`](PullFlags::UNTRUSTED) fails the pull on a mismatch between an
//! imported object and its name. An object that is re-ingested is hashed as it
//! streams and compared there whatever the flags say, so a corrupt source is
//! rejected on that path with or without the flag; every other path moves bytes
//! without hashing them, and the flag adds their one read. An untrusted pull
//! therefore reads each object exactly once.

use std::collections::{HashMap, HashSet};

use futures_lite::AsyncReadExt;
use ostrya_core::{Checksum, Commit, ContentHasher, DirTree, ObjectName, ObjectType, RepoMode};
use rustix::fs::{AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::file::FileKind;
use crate::repo::Repo;
use crate::transaction::Transaction;
use crate::traverse::reaches_at_least;
use crate::write::FileMeta;

mod delta;
mod drive;
pub mod http;

/// The chunk size for streaming a content object's payload.
const READ_CHUNK: usize = 128 * 1024;

/// Flags controlling a pull.
///
/// A bitset over the individual flag constants. Combine with `|` and test with
/// [`contains`](PullFlags::contains).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PullFlags(u32);

impl PullFlags {
    /// No flags set.
    pub const NONE: PullFlags = PullFlags(0);
    /// Verify every imported object's checksum against its name, failing the
    /// pull on a mismatch. Off by default, matching the tool: a local source is
    /// trusted and its objects are linked without being read.
    pub const UNTRUSTED: PullFlags = PullFlags(1 << 0);
    /// Import only the commit objects, leaving each commit's
    /// `.commitpartial` marker in place. The trees are not walked.
    pub const COMMIT_ONLY: PullFlags = PullFlags(1 << 1);
    /// Reject a regular-file content object whose logical mode has bits outside
    /// `0775` -- world-writable, setuid, setgid, or sticky. A bare-user-only
    /// destination applies a stricter rule of its own, described in the module
    /// documentation, whether or not this flag is set.
    pub const BAREUSERONLY_FILES: PullFlags = PullFlags(1 << 2);
    /// Skip the `ostree.ref-binding` check that a pulled commit names the ref it
    /// is being pulled under.
    pub const DISABLE_VERIFY_BINDINGS: PullFlags = PullFlags(1 << 3);
    /// Copy every object instead of hardlinking it, which is what an import from
    /// a source on another filesystem does on its own. A content object is copied
    /// through its header, so it lands with this repository's own inode policy.
    pub const FORCE_COPY: PullFlags = PullFlags(1 << 4);
    /// [`Repo::pull`] only. Write the pulled refs as local refs under
    /// `refs/heads/`, take every ref the remote's summary lists when
    /// [`refs`](PullOptions::refs) is empty, and copy the remote's `summary` and
    /// `summary.sig` bytes to this repository when the pull took every such ref.
    ///
    /// [`Repo::pull_local`] ignores this flag. It writes the pulled refs under
    /// the prefix [`remote`](PullOptions::remote) names, as local refs when that
    /// is `None`, and an empty [`refs`](PullOptions::refs) list takes every ref
    /// the source holds under `refs/heads`.
    pub const MIRROR: PullFlags = PullFlags(1 << 5);

    /// The empty flag set.
    pub const fn empty() -> PullFlags {
        PullFlags(0)
    }

    /// Whether every bit in `other` is set in `self`.
    pub const fn contains(self, other: PullFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// The raw bits.
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

/// What a fetched tip's timestamp is required to be no older than.
///
/// A pull that would move a ref backwards in time is refused, which is what
/// keeps a downgrade from arriving as an ordinary update. The comparison is
/// strict: an equal timestamp passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TimestampCheck {
    /// No check.
    #[default]
    Off,
    /// Compare against the commit the ref currently names in this repository.
    /// A ref this repository does not hold passes.
    CurrentRef,
    /// Compare against a given commit, which this repository must hold.
    Rev(Checksum),
}

/// What to pull and how.
///
/// The defaults are what [`Repo::pull_local`] does; the fields an HTTP pull adds
/// each default to the behavior a local pull has.
#[derive(Debug, Clone, Default)]
pub struct PullOptions {
    /// The ref names to pull. An empty list pulls every ref the source holds
    /// under `refs/heads`; over HTTP it resolves through the remote's summary
    /// under [`MIRROR`](PullFlags::MIRROR) and through the remote's configured
    /// `branches` otherwise.
    pub refs: Vec<String>,
    /// The remote name the pulled refs are written under
    /// (`refs/remotes/<remote>/<ref>`). `None` writes them as local refs under
    /// `refs/heads/` for a local pull, and under the remote's own name for an
    /// HTTP pull.
    pub remote: Option<String>,
    /// The flag set.
    pub flags: PullFlags,
    /// How many parents of each pulled commit to follow: `0` for the named
    /// commit alone, `-1` for the whole ancestry the source holds. Each ref's
    /// chain is followed to this depth on its own, so the commits a pull collects
    /// do not depend on the order the refs are listed.
    pub depth: i32,
    /// Extra local repositories consulted for an object the source does not
    /// hold, in order.
    pub localcache_repos: Vec<Repo>,
    /// The base URL an HTTP pull fetches from, overriding the remote's
    /// configured `url`. `None` uses the configuration.
    pub url: Option<String>,
    /// Extra headers an HTTP pull sends with every request.
    pub http_headers: Vec<(String, String)>,
    /// How many fetches an HTTP pull keeps in flight. `None` is 8.
    pub max_outstanding_fetches: Option<usize>,
    /// How many times an HTTP pull repeats a round of mirrors after a retryable
    /// failure. `None` is 5.
    pub n_network_retries: Option<u32>,
    /// What a fetched tip's timestamp is required to be no older than.
    pub timestamp_check: TimestampCheck,
    /// Fetch every object loose, ignoring any static delta the remote
    /// advertises. This wins over
    /// [`require_static_deltas`](PullOptions::require_static_deltas): a pull that
    /// asks for no delta looks for none and so finds nothing to require.
    pub disable_static_deltas: bool,
    /// Refuse a remote that advertises no static delta at all, which is a remote
    /// serving neither a delta index nor a summary carrying
    /// `ostree.static-deltas`. A remote that advertises deltas but none for the
    /// commit being pulled passes, and that pull fetches its objects loose. A
    /// commit this repository already holds complete is not looked for at all, so
    /// a pull with nothing to fetch is not refused.
    pub require_static_deltas: bool,
}

/// What a pull imported.
///
/// The counters cover the objects this pull staged, so an object the destination
/// already held is excluded from all three, and a
/// [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) pull, whose plan is the commit objects
/// alone, reports those and no content at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PullStats {
    /// Metadata objects imported. An object the destination already held does
    /// not count.
    pub metadata_imported: u32,
    /// Content objects imported. An object the destination already held does
    /// not count.
    pub content_imported: u32,
    /// The total on-disk size of the imported content objects, counted whether
    /// their bytes were written, shared by reflink, or shared by hardlink. This
    /// is the storage those objects occupy, not the space the pull consumed.
    pub content_bytes_written: u64,
}

impl Repo {
    /// Pull refs and their objects from another local repository.
    ///
    /// Every requested ref is resolved in `src`, its commit chain followed to
    /// [`depth`](PullOptions::depth) parents, and every object those commits
    /// reach imported into this repository. The refs are written last, after the
    /// objects are published, so no ref in this repository ever names a commit
    /// whose objects are not yet durable.
    ///
    /// A ref the source does not hold fails the pull with
    /// [`Error::RefNotFound`] before anything is imported. A parent commit the
    /// source does not hold ends that chain without error, so a source with
    /// truncated history pulls what it has.
    pub async fn pull_local(&self, src: &Repo, opts: PullOptions) -> Result<PullStats> {
        let targets = resolve_targets(src, &opts).await?;
        let flags = opts.flags;
        let verify_bindings = !flags.contains(PullFlags::DISABLE_VERIFY_BINDINGS);

        // The commit chains, in the order the refs were given, each commit once.
        let mut commits: Vec<Checksum> = Vec::new();
        let mut seen: HashMap<Checksum, i32> = HashMap::new();
        for (ref_name, tip) in &targets {
            let commit = load_commit(src, tip).await?;
            if verify_bindings {
                check_ref_binding(tip, &commit, ref_name)?;
            }
            collect_chain(src, *tip, commit, opts.depth, &mut commits, &mut seen).await?;
        }

        let txn = self.transaction().await?;

        // Mark each commit partial before its objects are imported, skipping one
        // this repository already holds intact: a pull that fails leaves its
        // markers behind, and a commit that was already complete must not be
        // demoted by an unrelated failure.
        let mut marked: Vec<Checksum> = Vec::new();
        for commit in &commits {
            if !self.has_object(ObjectType::Commit, commit).await?
                || self.commit_state(commit).await? == crate::read::CommitState::Partial
            {
                self.write_partial_marker(commit).await?;
                marked.push(*commit);
            }
        }

        let sources: Vec<&Repo> = std::iter::once(src)
            .chain(opts.localcache_repos.iter())
            .collect();

        let mut plan = PlanState::default();
        // The read buffer an untrusted verification streams through, reused
        // across every object of the pull and sized on its first use, so a pull
        // that verifies nothing allocates nothing.
        let mut verify_buf: Vec<u8> = Vec::new();
        for commit in &commits {
            for name in plan_commit(&sources, *commit, flags, &mut plan).await? {
                self.import_object(&txn, &sources, name, flags, &mut verify_buf)
                    .await?;
            }
            self.import_detached_metadata(&sources, commit).await?;
        }
        for (ref_name, tip) in &targets {
            txn.set_ref(&refspec(opts.remote.as_deref(), ref_name), Some(tip));
        }
        let stats = txn.commit().await?;

        // The content a marker guarded is published; a commit-only pull keeps
        // its markers, since the trees were never walked.
        if !flags.contains(PullFlags::COMMIT_ONLY) {
            for commit in &marked {
                self.remove_partial_marker(commit).await?;
            }
        }

        Ok(PullStats {
            metadata_imported: stats.metadata_written,
            content_imported: stats.content_written,
            content_bytes_written: stats.content_bytes_written,
        })
    }

    /// Import one object from the first source repository holding it.
    ///
    /// `verify_buf` is the buffer an untrusted verification streams the object's
    /// payload through, carried across the import loop so the pull holds one.
    async fn import_object(
        &self,
        txn: &Transaction,
        sources: &[&Repo],
        name: ObjectName,
        flags: PullFlags,
        verify_buf: &mut Vec<u8>,
    ) -> Result<()> {
        if txn.is_staged(&name.checksum, name.ty)
            || self.has_object(name.ty, &name.checksum).await?
        {
            return Ok(());
        }
        for src in sources {
            if src.has_object(name.ty, &name.checksum).await? {
                return self.import_from(txn, src, name, flags, verify_buf).await;
            }
        }
        Err(Error::ObjectNotFound {
            checksum: name.checksum,
            ty: name.ty,
        })
    }

    /// Import one object known to be present in `src`.
    async fn import_from(
        &self,
        txn: &Transaction,
        src: &Repo,
        name: ObjectName,
        flags: PullFlags,
        verify_buf: &mut Vec<u8>,
    ) -> Result<()> {
        if name.ty != ObjectType::File {
            // A metadata object is a plain file of its serialized bytes in every
            // mode, so the two repositories always store it identically.
            if flags.contains(PullFlags::UNTRUSTED) {
                verify_metadata(src, name).await?;
            }
            link_import(txn, src, name, flags).await?;
            return Ok(());
        }

        let same_mode = src.mode() == self.mode();
        let checks = ModeChecks::new(flags, self.mode());
        let untrusted = flags.contains(PullFlags::UNTRUSTED);

        // The mode checks read the object's logical form and run before the
        // object is imported by any path. An untrusted verification reads the same
        // form and is deferred to the path the import takes: the link and the
        // clone move bytes without hashing them and are verified here, while a
        // re-ingest hashes the object as it writes it and compares the result
        // against its name itself, so verifying ahead of that would read the
        // payload twice.
        let loaded = if checks.any() || untrusted {
            let file = src.load_file(&name.checksum).await?;
            if checks.any() {
                checks.check(&name.checksum, &file.meta())?;
            }
            Some(file)
        } else {
            None
        };

        // Two repositories of one mode store a content object identically, inode
        // included, so it is imported by sharing the source inode.
        if same_mode && link_import(txn, src, name, flags).await? {
            if untrusted && let Some(file) = &loaded {
                verify_content(&name.checksum, file, verify_buf).await?;
            }
            return Ok(());
        }

        // The object's logical form: the header the clone applies the
        // destination's inode policy from, and the payload a re-ingest streams.
        // A refused link arrives here too, which costs it one metadata read.
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
                // A symlink's identity is its header alone, which
                // `write_symlink` hashes and compares against the name it is
                // given, so this path checks the object whatever the flags say.
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

    /// Copy a commit's detached metadata from the first source holding it. The
    /// stored bytes are copied verbatim; a source with no `.commitmeta` leaves
    /// the destination's alone.
    async fn import_detached_metadata(&self, sources: &[&Repo], commit: &Checksum) -> Result<()> {
        for src in sources {
            match src.load_object_bytes(ObjectType::CommitMeta, commit).await {
                Ok(bytes) => return self.write_commit_detached_bytes(commit, bytes).await,
                Err(Error::ObjectNotFound { .. }) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Write a commit's zero-length `state/<commit>.commitpartial` marker, the
    /// marker a pull leaves while the commit's objects are in flight.
    ///
    /// A marker already present is left as it stands, so the one-byte state fsck
    /// writes survives a pull over the commit it marked. The tool does the same:
    /// its `pull-local` opens an existing marker read-only and creates one with
    /// `O_EXCL`.
    ///
    /// The marker is not fsynced and neither is `state/`. Every marker of a pull
    /// is written before `Transaction::commit`, so the `syncfs` that opens
    /// publication makes it durable ahead of the first object rename. A staged
    /// object enters `objects/` in that rename, so no object a pull stages is
    /// reachable before the marker guarding it is durable. A local pull writes all
    /// of its markers before the first import, and an HTTP pull writes each
    /// commit's marker in the step that fetched that commit.
    async fn write_partial_marker(&self, commit: &Checksum) -> Result<()> {
        let path = partial_path(commit);
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            match rustix::fs::openat(
                repo.repo_fd(),
                path.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o644),
            ) {
                Ok(_) | Err(rustix::io::Errno::EXIST) => Ok(()),
                Err(e) => Err(Error::from(e)),
            }
        })
        .await
    }

    /// Remove a commit's `.commitpartial` marker, treating an absent one as
    /// success.
    ///
    /// This is the last operation of a pull and no barrier follows it, matching
    /// the tool. A crash before the unlink reaches the disk therefore leaves the
    /// marker on a commit that is complete, which the next pull of that commit or
    /// a prune of it clears.
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
}

/// The `state/` path of a commit's partial marker, relative to the repository
/// directory.
pub(crate) fn partial_path(commit: &Checksum) -> String {
    format!("state/{}.commitpartial", commit.to_hex())
}

/// The refspec a pulled ref is written under: `remote:ref` when a remote name
/// is given, the bare ref name otherwise.
fn refspec(remote: Option<&str>, ref_name: &str) -> String {
    match remote {
        Some(remote) => format!("{remote}:{ref_name}"),
        None => ref_name.to_owned(),
    }
}

/// Resolve the refs to pull against the source: the requested names, or every
/// ref under the source's `refs/heads` when none were named.
async fn resolve_targets(src: &Repo, opts: &PullOptions) -> Result<Vec<(String, Checksum)>> {
    if opts.refs.is_empty() {
        return src.list_refs(None).await;
    }
    let mut out = Vec::with_capacity(opts.refs.len());
    for name in &opts.refs {
        let checksum = src
            .resolve_rev(name, false)
            .await?
            .ok_or_else(|| Error::RefNotFound(name.clone()))?;
        out.push((name.clone(), checksum));
    }
    Ok(out)
}

/// Follow a commit's parents in the source, appending each commit not already
/// collected. `depth` is the number of parents to follow, `-1` for all of them.
/// A parent the source does not hold ends the chain.
///
/// `seen` records the number of parents each commit still had to follow when it
/// was reached, so a chain that arrives at a commit with more parents left than a
/// previous one had is walked on from rather than stopped at, and the commits a
/// pull collects do not depend on the order the refs were given. A commit is
/// appended the first time it is reached and not again.
async fn collect_chain(
    src: &Repo,
    tip: Checksum,
    tip_commit: Commit,
    depth: i32,
    out: &mut Vec<Checksum>,
    seen: &mut HashMap<Checksum, i32>,
) -> Result<()> {
    let mut current = Some((tip, tip_commit));
    let mut remaining = depth;
    while let Some((checksum, commit)) = current {
        if let Some(&prev) = seen.get(&checksum)
            && reaches_at_least(prev, remaining)
        {
            return Ok(());
        }
        if seen.insert(checksum, remaining).is_none() {
            out.push(checksum);
        }
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

/// What a pull's plans have covered so far: the dirtrees descended into and the
/// object names an earlier commit's plan carried. Held across the commit loop so
/// the chain's trees are walked as one.
#[derive(Default)]
struct PlanState {
    dirtrees: HashSet<Checksum>,
    emitted: HashSet<ObjectName>,
}

impl PlanState {
    /// Add a name to the plan being built unless an earlier plan carried it.
    fn push(&mut self, name: ObjectName, out: &mut Vec<ObjectName>) {
        if self.emitted.insert(name) {
            out.push(name);
        }
    }
}

/// The objects one commit contributes, in import order: its tree's metadata and
/// content first, the commit object last, so a partially imported transaction
/// never holds a commit ahead of what it references. Under
/// [`COMMIT_ONLY`](PullFlags::COMMIT_ONLY) the tree is not walked and the commit
/// object is the whole plan.
///
/// The commit and every dirtree under it are read from the first source holding
/// them, so a subtree the source has lost is enumerated from a localcache
/// repository that still holds it. A dirtree no source holds contributes its own
/// name and nothing beneath it, which fails the pull once the import reaches that
/// name.
///
/// `state` carries what the commits ahead of this one covered, so a dirtree
/// shared along the chain is descended into once and the objects under it appear
/// in a single commit's plan.
async fn plan_commit(
    sources: &[&Repo],
    commit: Checksum,
    flags: PullFlags,
    state: &mut PlanState,
) -> Result<Vec<ObjectName>> {
    let commit_name = ObjectName::new(commit, ObjectType::Commit);
    if flags.contains(PullFlags::COMMIT_ONLY) {
        return Ok(vec![commit_name]);
    }
    // This commit's own tree; the chain walk supplies the parents.
    let parsed = load_commit_from(sources, &commit).await?;
    let mut names: Vec<ObjectName> = Vec::new();
    state.push(
        ObjectName::new(parsed.root_dirmeta, ObjectType::DirMeta),
        &mut names,
    );
    let mut stack = vec![parsed.root_dirtree];
    while let Some(checksum) = stack.pop() {
        if !state.dirtrees.insert(checksum) {
            continue;
        }
        state.push(ObjectName::new(checksum, ObjectType::DirTree), &mut names);
        let Some(dirtree) = load_dirtree_from(sources, &checksum).await? else {
            continue;
        };
        for (_, file) in dirtree.files {
            state.push(ObjectName::new(file, ObjectType::File), &mut names);
        }
        for (_, subtree, submeta) in dirtree.dirs {
            state.push(ObjectName::new(submeta, ObjectType::DirMeta), &mut names);
            stack.push(subtree);
        }
    }
    // `Checksum` orders by its raw bytes, which reproduces the ASCII order of
    // the hex names, so the key needs no formatting.
    names.sort_by_key(|name| (name.ty.as_u32(), name.checksum));
    names.push(commit_name);
    Ok(names)
}

/// Load and parse a commit from a repository.
async fn load_commit(repo: &Repo, checksum: &Checksum) -> Result<Commit> {
    let bytes = repo.load_object_bytes(ObjectType::Commit, checksum).await?;
    Ok(Commit::parse(&bytes)?)
}

/// Load a commit, treating an absent object as `None`.
async fn try_load_commit(repo: &Repo, checksum: &Checksum) -> Result<Option<Commit>> {
    match load_commit(repo, checksum).await {
        Ok(commit) => Ok(Some(commit)),
        Err(Error::ObjectNotFound { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Load a commit from the first source holding it.
async fn load_commit_from(sources: &[&Repo], checksum: &Checksum) -> Result<Commit> {
    for src in sources {
        if let Some(commit) = try_load_commit(src, checksum).await? {
            return Ok(commit);
        }
    }
    Err(Error::ObjectNotFound {
        checksum: *checksum,
        ty: ObjectType::Commit,
    })
}

/// Load a dirtree from the first source holding it, `None` when none does.
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

/// Check that a commit's `ostree.ref-binding` names the ref it is being pulled
/// under. A commit carrying no binding key at all predates the convention and
/// passes; one carrying a binding list that omits the ref fails.
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

/// Import an object the two repositories store identically, inode included, by
/// hardlinking it into the transaction's staging directory.
///
/// Returns whether the object is staged. `false` is a content object whose link
/// was refused -- the destination sealing its objects with fs-verity, the two
/// repositories on different filesystems, the source inode at its link limit, the
/// kernel's protected-hardlink rules, or
/// [`FORCE_COPY`](PullFlags::FORCE_COPY) -- which the caller imports through the
/// object's header instead. A metadata object, which has no header, is copied
/// when its link is refused and so is always staged.
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

/// Whether the two modes store a regular file's payload bytes identically. The
/// bare family stores the raw payload, so any two of its modes qualify; archive
/// stores a framed, deflated form that shares bytes with nothing else.
fn payload_shared(src: RepoMode, dest: RepoMode) -> bool {
    !src.is_archive() && !dest.is_archive()
}

/// Whether the two modes store a symlink object identically, inode included.
/// bare-user and bare-user-shared both store one as a 0644 regular file holding
/// the target plus a NUL, with the logical metadata in `user.ostreemeta`, so the
/// object is shareable between them.
fn symlink_shared(src: RepoMode, dest: RepoMode) -> bool {
    matches!(
        (src, dest),
        (RepoMode::BareUser, RepoMode::BareUserShared)
            | (RepoMode::BareUserShared, RepoMode::BareUser)
    )
}

/// The mode checks a content object is held to before it is written.
///
/// Two rules apply to a content object arriving from anywhere:
/// [`BAREUSERONLY_FILES`](PullFlags::BAREUSERONLY_FILES) bounds a regular file's
/// logical mode, and a `bare-user-only` destination takes only an object whose
/// logical form is the one it stores. Both read the logical metadata alone, so
/// one value carries them and every path an object reaches the object store by
/// makes the same checks: a local import, a fetched loose object, and the objects
/// a static delta's parts produce.
#[derive(Clone, Copy)]
pub(crate) struct ModeChecks {
    /// [`BAREUSERONLY_FILES`](PullFlags::BAREUSERONLY_FILES) was requested.
    bareuseronly_files: bool,
    /// The destination is `bare-user-only`.
    canonical: bool,
}

impl ModeChecks {
    /// The checks an import under `flags` into a repository of mode `dest` makes.
    /// A path with no pull flags of its own -- offline static-delta application --
    /// passes [`PullFlags::empty()`], which leaves the destination's own rule.
    pub(crate) fn new(flags: PullFlags, dest: RepoMode) -> ModeChecks {
        ModeChecks {
            bareuseronly_files: flags.contains(PullFlags::BAREUSERONLY_FILES),
            canonical: dest == RepoMode::BareUserOnly,
        }
    }

    /// Whether any check applies. A path that would otherwise not read an
    /// object's logical metadata reads it only when this holds.
    pub(crate) fn any(&self) -> bool {
        self.bareuseronly_files || self.canonical
    }

    /// Refuse a content object whose logical metadata fails a check that
    /// applies. Called before the object's bytes are written, so a refused
    /// object leaves nothing behind.
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

/// Reject a content object whose logical metadata is not what a
/// `bare-user-only` destination stores.
///
/// That mode records neither ownership nor xattrs and reduces a regular file's
/// permission bits to `perm & 0o755`, so a write into it canonicalizes the header
/// and names the object for the result. An import keeps the name the object
/// arrives under, which it can do only where that name already covers the
/// canonical header; anything else would land under a name its stored form does
/// not hash to. A symlink's mode is fixed by the object model and is exempt.
fn check_canonical(checksum: &Checksum, meta: &FileMeta) -> Result<()> {
    let extra = if meta.is_symlink() {
        0
    } else {
        // S_IFREG plus the permission bits the mode keeps.
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

/// Reject a regular-file content object whose logical mode has bits outside
/// `0775`. Symlinks carry a fixed mode and are exempt.
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

/// Verify a metadata object's serialized bytes hash to its name.
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

/// Verify a content object: its framed header followed by its streamed payload
/// must hash to its name.
///
/// `buf` is the caller's read buffer, grown to [`READ_CHUNK`] on its first use
/// and reused for every object after it.
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

/// The pull options and the timestamp check move freely across tasks and
/// threads.
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
