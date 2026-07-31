//! HTTP pull: importing refs and their objects from a remote over HTTP.
//!
//! [`Repo::pull`] fetches a set of refs, the commits they name, and every object
//! those commits reach from a remote named in this repository's config, into one
//! transaction. What the transaction publishes, when the refs are written, and
//! what the `.commitpartial` markers mean is the local pull's contract
//! unchanged; what this module adds is where the objects come from and how many
//! are fetched at once.
//!
//! What a pull asks the remote for, in the order it first asks: `summary.sig`,
//! `summary`, `config`, then the objects. A remote with no summary answers 404
//! and each requested ref is resolved through `refs/heads/<ref>` instead.
//!
//! The remote is an archive repository. A content object is requested as
//! `objects/<..>.filez` whatever the remote stores on its own disk, since that
//! is the one form of a content object an HTTP client can read: the framed,
//! deflated payload behind its header. `config` is fetched to establish that
//! before the first object is requested, so a non-archive remote is refused with
//! [`Error::Unsupported`] naming its mode rather than surfacing as a 404 on the
//! first content object. A remote serving no `config` is treated as archive.
//!
//! Concurrency. A pull holds up to
//! [`max_outstanding_fetches`](PullOptions::max_outstanding_fetches) steps in
//! flight, each a future that fetches one object and stores it. The plan those
//! slots are refilled from holds three classes, drained in this order and
//! carrying the matching fetch priority:
//!
//! - the commits: the requested tips, and their parents under
//!   [`depth`](PullOptions::depth);
//! - the scan: the dirtree and dirmeta objects the walk is blocked on;
//! - the content: the file objects, which nothing waits on.
//!
//! That drain order is what orders a pull's requests. The fetcher admits as many
//! requests at once as the pull has slots, and a slot has one fetch outstanding
//! at a time, so the admission gate a priority is weighed at never queues inside
//! one pull. The priority a class carries decides the order where a [`Fetcher`]
//! is shared by more callers than it admits.
//!
//! The plan is owned by the loop, so it needs no lock. Nothing is spawned: the
//! step futures borrow the repository, the transaction, and the fetcher, so a
//! failure returns from the loop and drops every step still in flight, closing
//! their connections and releasing their fetcher permits. The transaction reaps
//! its staging directory and no ref is written.
//!
//! A commit object is fetched before the objects it references, since its tree
//! is unknown until it arrives, and staged where it arrives: the write path
//! hashes the bytes there and compares the result against the name they were
//! requested by, so a commit stored under the wrong name fails the pull before
//! its tree is asked for, and nothing is held in memory past the step. A reader
//! is covered against a commit whose tree is not yet complete by the commit's
//! `.commitpartial` marker, which is written when the commit is fetched and
//! removed after the transaction publishes. An object several commits reach is
//! fetched once, and the step that fetches a commit makes the ref-binding and
//! timestamp checks of every requested ref naming it, so two refs at one commit
//! are both checked. A commit this repository already holds complete has no
//! object of its tree queued, since what it references is present; its parent is
//! followed all the same, so a pull extends the history a shallower pull left.
//!
//! A commit's `.commitmeta` is requested ahead of the commit object and written
//! once that object is here, which keeps the detached metadata ahead of the ref
//! that names its commit and leaves none behind for a parent the remote answers
//! 404 for. The file is outside the transaction, so a pull that fails after a
//! commit object landed leaves the copy it wrote, which prune sweeps.
//!
//! Above one slot the request order is not fixed: which queued object a freed
//! slot takes depends on which step finished. What is fixed is the set of
//! requests and the class order between them.
//!
//! Writing is throttled separately. A content step takes one of three write
//! permits once the response head has arrived and holds it for the whole body:
//! the archive header read, the payload streaming into the object store, and the
//! read that settles the end of the stream. A fast remote therefore cannot put
//! more concurrent writers on the destination filesystem than that. The permit is
//! taken before the body is read, which keeps a step waiting for one off the
//! fetcher's progress clock: that clock measures silence since a read wanted
//! bytes, and no read has yet wanted any. The header arrives inside the first
//! frame in the ordinary case, so what the permit spans beside the payload is
//! that frame and the byte that ends the stream. A body waiting for a permit
//! holds what it has received unread, and over HTTP/2 that is flow-control
//! credit: the fetcher gives a connection one stream window for every request it
//! admits, so the credit a parked body holds is its own and the metadata stream a
//! scan is blocked on receives over a window of its own.
//!
//! What a step holds in memory follows the object class it fetches. A content
//! object streams into the object store through its slot's 128 KiB read buffer
//! and buffers its header alone, which `MAX_FILE_HEADER_SIZE` caps at 1 MiB; the
//! read buffer belongs to the slot rather than to the object, so the objects a
//! slot stores share it whether they come from the remote or from a localcache
//! repository. What each in-flight object does allocate for itself is the 16 KiB
//! the decoder reads its compressed input through. A metadata object -- a commit,
//! a dirtree, a dirmeta, or a `.commitmeta` -- is read whole under the format's
//! 128 MiB metadata cap, one buffer per step sized from the length the remote
//! declares, so the metadata a pull holds is that cap times the slot count.
//!
//! Verification. Every fetched object is stored under the name it was requested
//! by, and the write path hashes what it stores and compares the result against
//! that name, so a corrupt or substituted object fails the pull with
//! [`Error::ChecksumMismatch`] and publishes nothing. There is no flag to skip
//! it: the write path cannot store an object without naming it, which is why an
//! HTTP pull ignores [`UNTRUSTED`](PullFlags::UNTRUSTED) -- it verifies either
//! way.
//!
//! The mode checks are the local pull's, made over the header a content object
//! arrives with: [`BAREUSERONLY_FILES`](PullFlags::BAREUSERONLY_FILES) rejects a
//! regular file whose mode has bits outside `0775`, and a bare-user-only
//! destination rejects one whose header is not the canonical form it stores.
//!
//! That header also declares what the payload decompresses to, which bounds the
//! stream on both sides. A payload that outgrows the declaration is refused with
//! [`Error::InvalidFormat`], so what a corrupt or expanding stream can write
//! before the checksum comparison at the end of the payload is what the object
//! declared. A payload that takes more off the connection than a compressed form
//! of that declaration occupies is refused the same way, which bounds the time and
//! the bandwidth a stream of empty DEFLATE blocks would otherwise take.
//!
//! After the payload, a content step reads its response to the end. One byte
//! settles it, since nothing follows an object's final DEFLATE block. That read
//! returns the connection to the pool, so a pull reuses one connection per slot
//! rather than opening one per object; at one slot that is one connection for the
//! whole pull, and at the default eight it is up to eight, since HTTP/1.1 carries
//! one request at a time. Bytes after the payload are refused with
//! [`Error::InvalidFormat`], and a symlink's stored form is held to the same
//! rule.
//!
//! Sources. A [`localcache_repos`](PullOptions::localcache_repos) repository is
//! consulted before the network, per object, through the local pull's import
//! path with its checksum verified.

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use async_compression::futures::bufread::DeflateDecoder;
use futures_io::AsyncRead;
use futures_lite::{AsyncReadExt, AsyncWriteExt};
use ostrya_core::{
    Checksum, Commit, DirTree, FileHeader, ObjectName, ObjectType, RepoMode, loose_path,
};

use crate::config::RepoConfig;
use crate::error::{Error, Result};
use crate::fetch::gate::Gate;
use crate::fetch::{
    Body, ClientIdentity, FetchRequest, Fetched, Fetcher, FetcherOptions, Priority, TlsOptions,
    TrustRoots,
};
use crate::inflate::BufSource;
use crate::object::{MAX_FILE_HEADER_SIZE, MAX_METADATA_SIZE};
use crate::read::CommitState;
use crate::repo::Repo;
use crate::summary::{SUMMARY_FILE, Summary};
use crate::transaction::Transaction;
use crate::traverse::reaches_at_least;
use crate::write::FileMeta;

use super::drive::Slots;
use super::{
    PullFlags, PullOptions, PullStats, READ_CHUNK, TimestampCheck, check_bareuseronly,
    check_canonical, check_ref_binding, refspec,
};

/// How many fetches are in flight when the caller names no limit.
const DEFAULT_OUTSTANDING: usize = 8;
/// How many times a round of mirrors is repeated when the caller names no count.
const DEFAULT_RETRIES: u32 = 5;
/// How many fetched content objects stream into the object store at once.
const WRITE_THROTTLE: usize = 3;

/// The cap on the repository-root files a pull fetches (`summary`,
/// `summary.sig`, `config`), matching the cap the local summary reader applies.
const MAX_ROOT_FILE: u64 = 64 * 1024 * 1024;
/// The cap on a fetched `refs/heads/<ref>` file, which holds 64 hex characters
/// and a newline.
const MAX_REF_FILE: u64 = 1024;

/// The summary signature file name at the repository root.
const SUMMARY_SIG_FILE: &str = "summary.sig";
/// The repository config file name at the repository root.
const CONFIG_FILE: &str = "config";

impl Repo {
    /// Pull refs and their objects from an HTTP remote.
    ///
    /// `remote` names a `[remote "<name>"]` section of this repository's config,
    /// which supplies the base URL and the TLS material;
    /// [`url`](PullOptions::url) overrides the URL, which lets a caller pull from
    /// a remote the config does not describe.
    ///
    /// Every requested ref is resolved against the remote's summary and then
    /// against `refs/heads/<ref>`; a ref neither yields fails with
    /// [`Error::RefNotFound`] before anything is fetched. An empty
    /// [`refs`](PullOptions::refs) list takes every ref the summary lists under
    /// [`MIRROR`](PullFlags::MIRROR), and the remote's configured `branches`
    /// otherwise; neither being available fails with [`Error::Pull`].
    ///
    /// The refs are written after the objects are published, under
    /// `refs/remotes/<remote>/<ref>` -- or under
    /// [`PullOptions::remote`](PullOptions::remote) when that names a different
    /// prefix, and as local refs under [`MIRROR`](PullFlags::MIRROR). A mirror
    /// pull that took every ref the summary lists also copies the remote's
    /// summary bytes to this repository's `summary`, and its `summary.sig` bytes
    /// where the remote holds them.
    pub async fn pull(&self, remote: &str, opts: PullOptions) -> Result<PullStats> {
        let fetcher = self.remote_fetcher(remote, &opts).await?;
        let (summary_bytes, signature) = fetch_summary(&fetcher).await?;
        let summary = match summary_bytes.as_deref() {
            Some(bytes) => Some(Summary::parse(bytes)?),
            None => None,
        };
        check_remote_mode(&fetcher).await?;
        let targets = self
            .remote_targets(remote, &opts, summary.as_ref(), &fetcher)
            .await?;

        let mirror = opts.flags.contains(PullFlags::MIRROR);
        let prefix = if mirror {
            None
        } else {
            Some(opts.remote.as_deref().unwrap_or(remote))
        };

        let txn = self.transaction().await?;
        let marked = self.drive(&txn, &fetcher, &opts, prefix, &targets).await?;
        for (name, tip) in &targets {
            txn.set_ref(&refspec(prefix, name), Some(tip));
        }
        let stats = txn.commit().await?;

        // The content a marker guarded is published; a commit-only pull keeps
        // its markers, since the trees were never fetched.
        if !opts.flags.contains(PullFlags::COMMIT_ONLY) {
            for commit in &marked {
                self.remove_partial_marker(commit).await?;
            }
        }

        // A mirror pull of every ref holds the whole of what the remote
        // publishes, so the remote's summary describes this repository too and
        // is copied verbatim. A mirror pull of named refs holds part of it and
        // writes no summary.
        if mirror
            && opts.refs.is_empty()
            && let Some(bytes) = summary_bytes
        {
            let fsync = self.config().fsync()?;
            self.write_root_file(SUMMARY_FILE, bytes, fsync).await?;
            // The signature covers those bytes, so it is copied with them: a
            // client pulling from this repository with `gpg-verify-summary=true`
            // reads the pair. A remote holding no `summary.sig` leaves this
            // repository's own file as it stands, which is what the tool does.
            if let Some(sig) = signature {
                self.write_root_file(SUMMARY_SIG_FILE, sig, fsync).await?;
            }
        }

        Ok(PullStats {
            metadata_imported: stats.metadata_written,
            content_imported: stats.content_written,
            content_bytes_written: stats.content_bytes_written,
        })
    }

    /// The remote's `summary` and `summary.sig` bytes, an absent one as `None`.
    ///
    /// The remote is reached the way [`pull`](Repo::pull) reaches it: its
    /// configured URL and TLS material, with no override.
    pub async fn remote_fetch_summary(
        &self,
        remote: &str,
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        let fetcher = self.remote_fetcher(remote, &PullOptions::default()).await?;
        fetch_summary(&fetcher).await
    }

    /// Build the fetcher for one remote from its config section and `opts`.
    async fn remote_fetcher(&self, remote: &str, opts: &PullOptions) -> Result<Fetcher> {
        let section = self.config().remote(remote);
        let url = match &opts.url {
            Some(url) => url.clone(),
            None => {
                let section = section
                    .as_ref()
                    .ok_or_else(|| Error::Pull(format!("no remote '{remote}' is configured")))?;
                section
                    .url()?
                    .ok_or_else(|| Error::Pull(format!("remote '{remote}' has no url")))?
            }
        };
        let tls = match &section {
            Some(section) => remote_tls(remote, section).await?,
            None => TlsOptions::default(),
        };
        Fetcher::new(FetcherOptions {
            headers: opts.http_headers.clone(),
            tls,
            max_retries: opts.n_network_retries.unwrap_or(DEFAULT_RETRIES),
            max_outstanding: opts.max_outstanding_fetches.unwrap_or(DEFAULT_OUTSTANDING),
            ..FetcherOptions::new(url)
        })
        .await
    }

    /// Resolve what to pull: the requested refs, the remote's summary refs under
    /// [`MIRROR`](PullFlags::MIRROR), or the remote's configured `branches`.
    async fn remote_targets(
        &self,
        remote: &str,
        opts: &PullOptions,
        summary: Option<&Summary>,
        fetcher: &Fetcher,
    ) -> Result<Vec<(String, Checksum)>> {
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
            // A summary name becomes a ref this pull writes, so it is held to
            // the ref store's rule here, before the first object is requested,
            // rather than when the transaction resolves it at publication.
            for (name, _) in &summary.refs {
                crate::refs::check_ref_path(name)?;
            }
            return Ok(summary.refs.clone());
        } else {
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
            // The name reaches the wire as a request path, so it is held to the
            // rule the ref store holds it to: a traversal component would ask
            // the server for a resource the ref does not name.
            crate::refs::check_ref_path(&name)?;
            let checksum = match summary.and_then(|summary| summary.lookup(&name)) {
                Some(checksum) => checksum,
                None => fetch_remote_ref(fetcher, &name)
                    .await?
                    .ok_or_else(|| Error::RefNotFound(name.clone()))?,
            };
            out.push((name, checksum));
        }
        Ok(out)
    }

    /// Run the plan to completion, returning the commits whose `.commitpartial`
    /// marker this pull wrote and has to clear.
    async fn drive(
        &self,
        txn: &Transaction,
        fetcher: &Fetcher,
        opts: &PullOptions,
        ref_prefix: Option<&str>,
        targets: &[(String, Checksum)],
    ) -> Result<Vec<Checksum>> {
        // The refs each requested tip is the tip of. The binding and timestamp
        // checks are per ref, and the plan fetches one commit once however many
        // refs name it, so the step that fetches a commit runs the checks of every
        // ref in its entry here.
        let mut tips: HashMap<Checksum, Vec<String>> = HashMap::new();
        for (name, tip) in targets {
            tips.entry(*tip).or_default().push(name.clone());
        }
        let ctx = StepCtx {
            txn,
            fetcher,
            writes: Arc::new(Gate::new(WRITE_THROTTLE)),
            sources: &opts.localcache_repos,
            flags: opts.flags,
            ref_prefix,
            timestamp_check: &opts.timestamp_check,
            tips: &tips,
        };
        let mut plan = Plan::default();
        for (_, tip) in targets {
            plan.push_commit(CommitItem {
                checksum: *tip,
                depth: opts.depth,
                optional: false,
            });
        }

        let mut marked = Vec::new();
        let mut slots = Slots::new(opts.max_outstanding_fetches.unwrap_or(DEFAULT_OUTSTANDING));
        // The read buffers a content object passes through, whichever source it
        // comes from: a localcache import verifies its payload through one, and a
        // fetched payload streams into the object store through one. A step takes
        // a buffer where it starts and hands it back with its outcome, so a pull
        // holds one buffer per slot however many objects it stores. A step that
        // fails takes its buffer with it, which ends the pull anyway.
        let mut buffers: Vec<Vec<u8>> = Vec::new();
        loop {
            while slots.has_room()
                && let Some(item) = plan.next()
            {
                let buffer = buffers.pop().unwrap_or_default();
                slots.push(self.step(&ctx, item, buffer));
            }
            let Some(outcome) = slots.next_ready().await else {
                break;
            };
            let (step, buffer) = outcome?;
            buffers.push(buffer);
            plan.apply(step, &mut marked);
        }
        Ok(marked)
    }

    /// Run one unit of work: fetch an object and store it.
    ///
    /// `read_buf` is the slot's read buffer, returned with the outcome for the
    /// next step in that slot to reuse. A content object reads through it: the
    /// payload of one fetched from the remote, and the verification of one taken
    /// from a localcache repository.
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
            Item::Object(name) => self.fetch_metadata(ctx, name, &mut read_buf).await?,
        };
        Ok((step, read_buf))
    }

    /// Fetch one commit: its detached metadata, then the object itself, then the
    /// checks each requested ref naming it is subject to. The detached metadata is
    /// written once the commit object is here.
    async fn fetch_commit(
        &self,
        ctx: &StepCtx<'_>,
        item: CommitItem,
        read_buf: &mut Vec<u8>,
    ) -> Result<Step> {
        let checksum = item.checksum;
        let name = ObjectName::new(checksum, ObjectType::Commit);

        // Detached metadata travels with its commit and is fetched ahead of it,
        // the order the tool was observed to request the pair in. The bytes are
        // held until the commit object is here, so a commit the remote does not
        // hold leaves none behind.
        let detached = self.fetch_detached_metadata(ctx, &checksum).await?;

        let present = self.has_object(ObjectType::Commit, &checksum).await?;
        let complete = present && self.commit_state(&checksum).await? == CommitState::Normal;
        // Whether the commit object still has to be staged. A commit this
        // repository holds, and one a localcache repository supplied, are both
        // already accounted for.
        let mut stage = false;
        let bytes = if present {
            self.load_object_bytes(ObjectType::Commit, &checksum)
                .await?
        } else if let Some(src) = cached_source(ctx.sources, name).await? {
            self.import_from(
                ctx.txn,
                src,
                name,
                ctx.flags | PullFlags::UNTRUSTED,
                read_buf,
            )
            .await?;
            src.load_object_bytes(ObjectType::Commit, &checksum).await?
        } else {
            let path = object_path(&checksum, ObjectType::Commit);
            match fetch_whole(ctx.fetcher, &path, Priority::High, MAX_METADATA_SIZE).await {
                Ok(bytes) => {
                    stage = true;
                    bytes
                }
                // A parent the remote does not hold ends that chain, the way a
                // source with truncated history does for a local pull. Its
                // detached metadata is dropped: this repository holds no commit
                // for it to belong to.
                Err(Error::HttpStatus { status: 404, .. }) if item.optional => {
                    return Ok(Step::Done);
                }
                Err(e) => return Err(object_not_found(e, name)),
            }
        };

        let commit = Commit::parse(&bytes)?;
        // Every requested ref naming this commit is checked here. The plan fetches
        // one commit once, so a second ref at the same commit has no step of its
        // own to be checked in.
        for ref_name in ctx.tips.get(&checksum).into_iter().flatten() {
            if !ctx.flags.contains(PullFlags::DISABLE_VERIFY_BINDINGS) {
                check_ref_binding(&checksum, &commit, ref_name)?;
            }
            self.check_timestamp(ctx, ref_name, &checksum, &commit)
                .await?;
        }

        // A commit this repository already holds intact is not marked partial: a
        // pull that fails elsewhere must not demote it.
        if !complete {
            self.write_partial_marker(&checksum).await?;
        }
        // The commit is staged where it arrived, behind its own marker and ahead
        // of its tree. The write path hashes the bytes and compares the result
        // against the name they were requested by, so a commit stored under the
        // wrong name fails here rather than after its tree has been fetched, and
        // nothing is held past the step. What covers a reader against a commit
        // whose tree is not yet complete is the marker, cleared once the
        // transaction has published.
        if stage {
            ctx.txn
                .write_metadata(ObjectType::Commit, Some(&checksum), &bytes)
                .await?;
        }
        // The commit object is here, so its detached metadata is written now,
        // ahead of the ref that names it, which is what a verifier reading the
        // signatures alongside the commit requires. A commit this repository
        // already holds has the remote's copy written over its own, which is
        // what re-reading a mutable file on every pull is for.
        if let Some(meta) = detached {
            self.write_commit_detached_bytes(&checksum, meta).await?;
        }
        // A commit already complete here needs no object of its tree: what it
        // references is present. Its parent is a separate question, since the
        // depth an earlier pull ran at may be shallower than this one's, so the
        // chain walks on and the parent's own step decides what it needs.
        let tree = if complete || ctx.flags.contains(PullFlags::COMMIT_ONLY) {
            Vec::new()
        } else {
            vec![
                ObjectName::new(commit.root_dirmeta, ObjectType::DirMeta),
                ObjectName::new(commit.root_dirtree, ObjectType::DirTree),
            ]
        };
        Ok(Step::Commit(CommitOutcome {
            checksum,
            tree,
            parent: commit.parent,
            marked: !complete,
        }))
    }

    /// Read a commit's `.commitmeta` from the first localcache source holding it
    /// and from the remote otherwise, returning the bytes for the caller to write
    /// once the commit object is here. A 404 is the commit carrying none, which
    /// leaves this repository's copy as it stands.
    async fn fetch_detached_metadata(
        &self,
        ctx: &StepCtx<'_>,
        commit: &Checksum,
    ) -> Result<Option<Vec<u8>>> {
        for src in ctx.sources {
            match src.load_object_bytes(ObjectType::CommitMeta, commit).await {
                Ok(bytes) => return Ok(Some(bytes)),
                Err(Error::ObjectNotFound { .. }) => continue,
                Err(e) => return Err(e),
            }
        }
        let path = object_path(commit, ObjectType::CommitMeta);
        fetch_optional(ctx.fetcher, &path, Priority::High, MAX_METADATA_SIZE).await
    }

    /// Fetch one dirtree or dirmeta object and store it. A dirtree also reports
    /// what it references, which is what the scan walks on from.
    async fn fetch_metadata(
        &self,
        ctx: &StepCtx<'_>,
        name: ObjectName,
        read_buf: &mut Vec<u8>,
    ) -> Result<Step> {
        // An object already here is not fetched again. A dirtree is still read:
        // what it references may be missing, and the walk is what finds that
        // out.
        if ctx.txn.is_staged(&name.checksum, name.ty)
            || self.has_object(name.ty, &name.checksum).await?
        {
            // An object this transaction staged lives in the staging directory
            // until the transaction publishes, so the read checks the staged set
            // before `objects/`.
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
        let bytes = fetch_whole(ctx.fetcher, &path, Priority::High, MAX_METADATA_SIZE)
            .await
            .map_err(|e| object_not_found(e, name))?;
        // The write path hashes the bytes and compares the result against the
        // name they were requested by, so a substituted object fails here.
        ctx.txn
            .write_metadata(name.ty, Some(&name.checksum), &bytes)
            .await?;
        match name.ty {
            ObjectType::DirTree => Ok(Step::DirTree(children_of(&DirTree::parse(&bytes)?))),
            _ => Ok(Step::Done),
        }
    }

    /// The step a stored metadata object produces: a dirtree reports what it
    /// references, and anything else is a leaf, so `load` is called only for a
    /// dirtree.
    async fn walked<F>(&self, name: ObjectName, load: impl FnOnce() -> F) -> Result<Step>
    where
        F: Future<Output = Result<DirTree>>,
    {
        if name.ty != ObjectType::DirTree {
            return Ok(Step::Done);
        }
        Ok(Step::DirTree(children_of(&load().await?)))
    }

    /// Fetch one content object and store it.
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
        // A content object is requested as `.filez` whatever the remote stores
        // on its own disk: the framed, deflated form is the one an HTTP client
        // can read.
        let path = object_path(&name.checksum, ObjectType::File);
        let body = match ctx
            .fetcher
            .fetch(FetchRequest {
                path: &path,
                priority: Priority::Low,
                validators: None,
                max_size: None,
            })
            .await
        {
            Ok(Fetched::Body(body)) => body,
            Ok(Fetched::NotModified) => {
                return Err(Error::Fetch(format!(
                    "{path}: the remote answered 304 to an unconditional request"
                )));
            }
            Err(e) => return Err(object_not_found(e, name)),
        };
        // The write permit is taken before the body is read: a step waiting for
        // one has not yet asked the connection for bytes, so the fetcher's
        // progress window is not running against it. It covers the whole body --
        // the header read and the end-of-stream read along with the payload --
        // and is released where the step returns.
        let _permit = ctx.writes.acquire(Priority::Normal).await;
        self.store_content(ctx, &name.checksum, body, read_buf)
            .await?;
        Ok(Step::Done)
    }

    /// Store one fetched content object under the name it was requested by.
    ///
    /// The payload streams through `read_buf`, the slot's buffer, so the objects
    /// a slot stores share one allocation.
    async fn store_content(
        &self,
        ctx: &StepCtx<'_>,
        expected: &Checksum,
        body: Body,
        read_buf: &mut Vec<u8>,
    ) -> Result<()> {
        let (header, declared, mut body) = read_archive_header(body).await?;
        // The same mode checks a local pull makes, over the header the object
        // arrives with rather than the one a source repository stored.
        if ctx.flags.contains(PullFlags::BAREUSERONLY_FILES) {
            check_bareuseronly(expected, &header)?;
        }
        if self.mode() == RepoMode::BareUserOnly {
            check_canonical(expected, &header)?;
        }
        let symlink = header.is_symlink();
        let FileHeader {
            uid,
            gid,
            mode,
            symlink_target,
            xattrs,
        } = header;
        let meta = FileMeta {
            uid,
            gid,
            mode,
            xattrs,
        };
        if symlink {
            check_stream_end(expected, "symlink header", &mut body).await?;
            ctx.txn
                .write_symlink(&symlink_target, &meta, Some(expected))
                .await?;
            return Ok(());
        }
        let mut writer = ctx.txn.content_writer(Some(expected), &meta).await?;
        // The declared size bounds both sides of the payload: what it may
        // decompress to, and what may come off the connection to produce that.
        let source = BoundedInput::new(body, *expected, compressed_bound(declared));
        let mut payload = DeflateDecoder::new(BufSource::new(source));
        copy_bounded(&mut payload, &mut writer, read_buf, expected, declared)
            .await
            .map_err(payload_refusal)?;
        writer.finish().await?;
        // The decoder stops at the DEFLATE end-of-stream marker and asks its
        // input for nothing more, so the response has to be read to its end
        // here: that read is what returns the connection to the pool for the
        // next object.
        check_stream_end(expected, "deflated payload", payload.into_inner())
            .await
            .map_err(payload_refusal)?;
        Ok(())
    }

    /// Refuse a fetched tip that is older than what it is checked against.
    async fn check_timestamp(
        &self,
        ctx: &StepCtx<'_>,
        ref_name: &str,
        tip: &Checksum,
        fetched: &Commit,
    ) -> Result<()> {
        let against = match ctx.timestamp_check {
            TimestampCheck::Off => return Ok(()),
            TimestampCheck::CurrentRef => {
                let current = self
                    .resolve_rev(&refspec(ctx.ref_prefix, ref_name), true)
                    .await?;
                // A ref this repository does not hold yet has nothing to be
                // older than.
                let Some(current) = current else {
                    return Ok(());
                };
                current
            }
            TimestampCheck::Rev(rev) => *rev,
        };
        let bytes = self.load_object_bytes(ObjectType::Commit, &against).await?;
        let current = Commit::parse(&bytes)?;
        if fetched.timestamp >= current.timestamp {
            return Ok(());
        }
        Err(Error::Pull(format!(
            "commit {tip} (timestamp {}) is chronologically older than \
             {against} (timestamp {})",
            fetched.timestamp, current.timestamp
        )))
    }
}

/// What every step of one pull shares.
struct StepCtx<'a> {
    txn: &'a Transaction,
    fetcher: &'a Fetcher,
    /// The write throttle: how many fetched content objects stream into the
    /// object store at once.
    writes: Arc<Gate>,
    /// Repositories consulted for an object before the network, in order.
    sources: &'a [Repo],
    flags: PullFlags,
    /// The prefix the pulled refs are written under, which the timestamp check
    /// resolves the ref's current tip through. `None` is a local ref.
    ref_prefix: Option<&'a str>,
    timestamp_check: &'a TimestampCheck,
    /// The requested refs each tip commit is the tip of, which the binding and
    /// timestamp checks are made against. A commit with no entry is a parent
    /// reached under `depth`, which no ref names.
    tips: &'a HashMap<Checksum, Vec<String>>,
}

/// One commit to fetch.
struct CommitItem {
    checksum: Checksum,
    /// How many more parents to follow from here, `-1` for all of them.
    depth: i32,
    /// Whether a remote that does not hold this commit ends the chain rather
    /// than failing the pull, which is what a parent under `depth` does.
    optional: bool,
}

/// One unit of work a slot runs.
enum Item {
    Commit(CommitItem),
    Object(ObjectName),
}

/// What one step produced.
enum Step {
    /// A commit object arrived, or was already here.
    Commit(CommitOutcome),
    /// A dirtree is stored; these are the objects it references.
    DirTree(Vec<ObjectName>),
    /// Nothing follows: a dirmeta or content object is stored, or a parent the
    /// remote does not hold ended its chain.
    Done,
}

/// What a commit contributes to the plan.
struct CommitOutcome {
    checksum: Checksum,
    /// The commit's root dirmeta and dirtree, empty when its tree is not walked.
    tree: Vec<ObjectName>,
    /// The parent to follow under `depth`.
    parent: Option<Checksum>,
    /// Whether this pull wrote the commit's `.commitpartial` marker.
    marked: bool,
}

/// What the pull still has to do, and what it has done.
///
/// The loop owns this, so nothing here is shared or locked.
#[derive(Default)]
struct Plan {
    /// The commits, drained first and fetched at high priority.
    commits: VecDeque<CommitItem>,
    /// The dirtree and dirmeta objects the walk is blocked on, drained second
    /// and fetched at high priority.
    scan: VecDeque<ObjectName>,
    /// The content objects, drained last and fetched at low priority.
    content: VecDeque<ObjectName>,
    /// The objects this pull has queued, so an object several commits reach is
    /// fetched once.
    queued: HashSet<ObjectName>,
    /// The remaining depth each commit was reached at, which is what decides
    /// whether a chain arriving at it again walks on from it.
    seen: HashMap<Checksum, i32>,
    /// The parent each fetched commit named, so a chain reaching it again with
    /// further to go resumes without refetching it.
    parents: HashMap<Checksum, Option<Checksum>>,
}

impl Plan {
    /// Queue a commit unless it has already been reached at least this deep.
    ///
    /// A commit reached again with further to go is not fetched again: the walk
    /// resumes at the parent it named. A commit still in flight has not named
    /// one yet, and its own outcome follows the parent to the depth recorded
    /// here.
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

    /// Queue an object this pull has not queued already.
    fn push_object(&mut self, name: ObjectName) {
        if !self.queued.insert(name) {
            return;
        }
        match name.ty {
            ObjectType::File => self.content.push_back(name),
            _ => self.scan.push_back(name),
        }
    }

    /// The next unit of work: the commits, then the scan, then the content.
    fn next(&mut self) -> Option<Item> {
        if let Some(commit) = self.commits.pop_front() {
            return Some(Item::Commit(commit));
        }
        if let Some(name) = self.scan.pop_front() {
            return Some(Item::Object(name));
        }
        self.content.pop_front().map(Item::Object)
    }

    /// Fold one step's outcome back into the plan.
    fn apply(&mut self, step: Step, marked: &mut Vec<Checksum>) {
        match step {
            Step::Commit(outcome) => self.apply_commit(outcome, marked),
            Step::DirTree(children) => {
                for child in children {
                    self.push_object(child);
                }
            }
            Step::Done => {}
        }
    }

    /// Record a commit and queue what it needs.
    fn apply_commit(&mut self, outcome: CommitOutcome, marked: &mut Vec<Checksum>) {
        if outcome.marked {
            marked.push(outcome.checksum);
        }
        self.parents.insert(outcome.checksum, outcome.parent);
        for name in outcome.tree {
            self.push_object(name);
        }
        // The depth comes from the plan and not from the item: a later chain may
        // have reached this commit with further to go while it was in flight.
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

/// One parent followed: a finite depth counts down, and `-1` stays `-1`.
fn one_less(depth: i32) -> i32 {
    if depth > 0 { depth - 1 } else { depth }
}

/// The objects a dirtree references: its files, and the dirmeta and dirtree of
/// each subdirectory.
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

/// The request path of a loose object. The remote is an archive repository, so a
/// content object is named `.filez` there whatever this repository stores.
fn object_path(checksum: &Checksum, ty: ObjectType) -> String {
    format!("objects/{}", loose_path(checksum, ty, RepoMode::Archive))
}

/// The first localcache repository holding `name`.
async fn cached_source(sources: &[Repo], name: ObjectName) -> Result<Option<&Repo>> {
    for src in sources {
        if src.has_object(name.ty, &name.checksum).await? {
            return Ok(Some(src));
        }
    }
    Ok(None)
}

/// Report a 404 for an object as the object being absent; anything else stands.
fn object_not_found(error: Error, name: ObjectName) -> Error {
    match error {
        Error::HttpStatus { status: 404, .. } => Error::ObjectNotFound {
            checksum: name.checksum,
            ty: name.ty,
        },
        other => other,
    }
}

/// The remote's summary and its signature, an absent one as `None`.
///
/// The signature is fetched first, which is the order the tool asks in: it
/// covers the summary that follows, and asking the other way round would pair a
/// summary with the signature of one the remote had already replaced.
async fn fetch_summary(fetcher: &Fetcher) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let signature =
        fetch_optional(fetcher, SUMMARY_SIG_FILE, Priority::High, MAX_ROOT_FILE).await?;
    let summary = fetch_optional(fetcher, SUMMARY_FILE, Priority::High, MAX_ROOT_FILE).await?;
    Ok((summary, signature))
}

/// Refuse a remote whose `[core] mode` is not archive.
async fn check_remote_mode(fetcher: &Fetcher) -> Result<()> {
    let Some(bytes) = fetch_optional(fetcher, CONFIG_FILE, Priority::High, MAX_ROOT_FILE).await?
    else {
        // A remote that serves no config is taken at its word as an archive,
        // which is what the `.filez` objects it serves say it is.
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

/// The commit a remote's `refs/heads/<name>` names, or `None` when the remote
/// serves no such ref.
async fn fetch_remote_ref(fetcher: &Fetcher, name: &str) -> Result<Option<Checksum>> {
    let path = ref_request_path(name);
    let Some(bytes) = fetch_optional(fetcher, &path, Priority::High, MAX_REF_FILE).await? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::InvalidFormat(format!("the remote ref {name} is not valid utf-8")))?;
    Ok(Some(Checksum::from_hex(text.trim())?))
}

/// The request path of a remote ref: `refs/heads/` and the percent-encoded name.
///
/// A request path reaches the wire as written, so the name is encoded where it
/// is built. Everything outside the unreserved set of RFC 3986 -- the ASCII
/// letters and digits, `-`, `.`, `_`, and `~` -- is encoded, `/` excepted, which
/// separates the name's components as it does the path's. A name carrying `?`,
/// `#`, or `%` therefore names the ref rather than a query, a fragment, or an
/// escape the server decodes into a different name.
fn ref_request_path(name: &str) -> String {
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

/// Fetch a path whole, or `None` when the remote answers 404.
async fn fetch_optional(
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

/// Fetch a path whole, under a size cap.
///
/// The fetcher refuses a declared `Content-Length` above the cap before the body
/// is read and stops a body that passes the cap as the bytes arrive. One buffer
/// belongs to each fetch in flight, so the cap a caller names bounds the memory
/// of one step: [`MAX_METADATA_SIZE`] for a metadata object,
/// [`MAX_ROOT_FILE`] for a repository-root file, [`MAX_REF_FILE`] for a
/// `refs/heads/<ref>` file.
///
/// The buffer is sized from the declared length, which the fetcher has already
/// held to the cap, so the body lands in one allocation of its own size and the
/// resident peak is what the cap states. The one spare byte is where the final
/// read finds the end of the stream: a buffer filled to its capacity is grown
/// before that read, which would double it. A remote declaring no length grows
/// its buffer as it reads, under the same cap.
async fn fetch_whole(
    fetcher: &Fetcher,
    path: &str,
    priority: Priority,
    max_size: u64,
) -> Result<Vec<u8>> {
    let fetched = fetcher
        .fetch(FetchRequest {
            path,
            priority,
            validators: None,
            max_size: Some(max_size),
        })
        .await?;
    let Fetched::Body(mut body) = fetched else {
        return Err(Error::Fetch(format!(
            "{path}: the remote answered 304 to an unconditional request"
        )));
    };
    let declared = body.content_length().unwrap_or(0).min(max_size);
    let mut out = Vec::with_capacity(usize::try_from(declared).unwrap_or(0).saturating_add(1));
    body.read_to_end(&mut out).await?;
    Ok(out)
}

/// Read the archive framing off the front of a content object's stream: a
/// four-byte big-endian header length, four zero bytes, then the header itself.
/// What remains of the stream is the raw-DEFLATE payload.
///
/// The size the header declares for that payload is returned with it, and bounds
/// what the payload is allowed to decompress to.
///
/// The remote states the header length and supplies the bytes behind it, so a
/// length above [`MAX_FILE_HEADER_SIZE`] is refused before the buffer for it is
/// allocated. That bound holds for each fetch in flight, since one header is
/// read per content object.
async fn read_archive_header<R: AsyncRead + Unpin>(mut stream: R) -> Result<(FileHeader, u64, R)> {
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
    Ok((header, uncompressed, stream))
}

/// Stream a content object's payload into `writer`, stopping if it outgrows the
/// size its header declared.
///
/// A correct object decompresses to exactly `declared`, so a stream that passes
/// it is corrupt or built to expand, and either way there is nothing to be gained
/// from reading the rest of it. The declared size is not covered by the object's
/// checksum, which is compared at the end of the payload: this bounds what has to
/// be written before that comparison is reached. Each read is clamped to what is
/// left plus the byte that settles it, so at most one byte past the declaration
/// is stored before the refusal.
///
/// `buf` is the slot's read buffer, grown to [`READ_CHUNK`] on its first use and
/// reused by every object that slot stores after it.
///
/// The compressed side of the same declaration is bounded by [`BoundedInput`],
/// under the decoder.
async fn copy_bounded<R, W>(
    mut reader: R,
    writer: &mut W,
    buf: &mut Vec<u8>,
    expected: &Checksum,
    declared: u64,
) -> Result<()>
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
            return Ok(());
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

/// How many bytes a payload declaring `declared` uncompressed bytes may take off
/// the connection.
///
/// A stored block is the form a DEFLATE compressor falls back to for data it
/// cannot shrink: five bytes of framing per 65535 bytes of input, which is one
/// part in thirteen thousand. A part in a thousand covers that with room to spare.
/// The fixed 64 KiB covers a small object, whose framing outweighs its content.
/// A stream past this bound is not a compressed form of what the header declares,
/// whatever it decompresses to.
fn compressed_bound(declared: u64) -> u64 {
    declared
        .saturating_add(declared / 1024)
        .saturating_add(64 * 1024)
}

/// A content object's compressed stream, bounded against the size its header
/// declares.
///
/// [`copy_bounded`] bounds what the payload decompresses to. That says nothing
/// about how many compressed bytes produce it: an empty non-final DEFLATE block is
/// five bytes that decompress to nothing, so a stream of them decompresses to
/// nothing for as long as the remote sends it, and memory and disk stay bounded
/// while time and bandwidth do not. The decoder does not return to its caller
/// while its input keeps yielding bytes, so the bound on that input belongs in the
/// read the decoder itself makes, which is this one.
///
/// The refusal travels as an [`Error::InvalidFormat`] inside the `io::Error` the
/// decoder passes up, which [`payload_refusal`] takes back out: the bound comes
/// from the object's own declaration, so the refusal names the object as the
/// decompressed-size refusal does.
struct BoundedInput<R> {
    inner: R,
    /// The object the bound is stated for.
    checksum: Checksum,
    bound: u64,
    /// What has been taken from `inner`, which passes the bound by at most the one
    /// read that trips it.
    taken: u64,
}

impl<R> BoundedInput<R> {
    fn new(inner: R, checksum: Checksum, bound: u64) -> BoundedInput<R> {
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

/// Take back the refusal a bounded read reported.
///
/// The decoder returns its input's failure as its own, so a bound [`BoundedInput`]
/// enforced arrives here inside an `io::Error`. Unwrapping it puts that refusal on
/// the footing of one [`copy_bounded`] raises itself. Any other failure stands as
/// it is.
fn payload_refusal(error: Error) -> Error {
    match error {
        Error::Io(io) => io.downcast::<Error>().unwrap_or_else(Error::Io),
        other => other,
    }
}

/// Establish that a content object's stream ends after `after`, and reach that
/// end.
///
/// One byte settles it. The framing that selects the caller's check arrives from
/// the remote, so the bytes a remote sends instead of an end of stream are of a
/// length that remote chose; reading them out would hold all of them. An object
/// that ends where it should reaches the end of its response in this read, which
/// returns the connection to the pool for the next object.
///
/// The payload's stream is the decoder's input buffer, which hands back
/// read-ahead the decoder left before it asks the body for more. A correct
/// object leaves none: nothing follows its final DEFLATE block.
async fn check_stream_end<R: AsyncRead + Unpin>(
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

/// Read the trust anchors and the client identity a remote's TLS keys name.
async fn remote_tls(remote: &str, section: &crate::config::Remote<'_>) -> Result<TlsOptions> {
    if section.tls_permissive()? {
        return Err(Error::Unsupported(format!(
            "remote '{remote}' sets tls-permissive: the fetcher has no way to skip \
             certificate verification, and verifying anyway would misreport the \
             configuration"
        )));
    }
    let roots = match section.tls_ca_path()? {
        Some(path) => TrustRoots::Pem(read_pem(&path).await?),
        None => TrustRoots::System,
    };
    let client_identity = match (
        section.tls_client_cert_path()?,
        section.tls_client_key_path()?,
    ) {
        (Some(cert), Some(key)) => Some(ClientIdentity {
            cert_chain_pem: read_pem(&cert).await?,
            key_pem: read_pem(&key).await?,
        }),
        (None, None) => None,
        _ => {
            return Err(Error::Pull(format!(
                "remote '{remote}': a client certificate needs both \
                 tls-client-cert-path and tls-client-key-path"
            )));
        }
    };
    Ok(TlsOptions {
        roots,
        client_identity,
    })
}

/// Read a PEM file named by the config.
async fn read_pem(path: &str) -> Result<Vec<u8>> {
    let path = path.to_owned();
    ostrya_rt::unblock(move || std::fs::read(&path).map_err(Error::from)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_compression::futures::bufread::DeflateEncoder;
    use futures_lite::io::Cursor;
    use ostrya_core::Xattrs;
    use ostrya_rt::block_on;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// The archive stored form of a content object: the framed header, then the
    /// payload the caller supplies.
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

    /// The header comes off the front of the stream and the payload is what is
    /// left, which is what the decoder is handed.
    #[test]
    fn the_header_is_read_off_the_front_and_the_payload_is_left() {
        block_on(async {
            let stored = framed(&regular_header(), 4, b"payload bytes");
            let (header, declared, mut rest) =
                read_archive_header(Cursor::new(stored)).await.unwrap();
            assert_eq!(header, regular_header());
            assert_eq!(declared, 4);
            let mut payload = Vec::new();
            rest.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, b"payload bytes");
        });
    }

    /// A symlink's header names its target, and its stored form carries no
    /// payload at all.
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
            let (parsed, _declared, mut rest) =
                read_archive_header(Cursor::new(stored)).await.unwrap();
            assert!(parsed.is_symlink());
            assert_eq!(parsed.symlink_target, "hello.txt");
            let mut payload = Vec::new();
            rest.read_to_end(&mut payload).await.unwrap();
            assert!(payload.is_empty());
        });
    }

    /// The four bytes after the length are padding and must be zero: anything
    /// else is not the framing this reader is looking at.
    #[test]
    fn nonzero_framing_padding_is_rejected() {
        block_on(async {
            let mut stored = framed(&regular_header(), 0, b"");
            stored[5] = 1;
            let err = read_archive_header(Cursor::new(stored)).await.unwrap_err();
            assert!(err.to_string().contains("padding"), "{err}");
        });
    }

    /// A stream that ends inside the framing is a truncated object, not an empty
    /// one.
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

    /// A stream that never ends. Past a small budget it fails, so a check that
    /// reads for an end fails this test rather than running until the process
    /// runs out of memory.
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

    /// A symlink whose stored form carries a payload is refused, and the refusal
    /// reads one byte of it: the length the remote chose to send is not held.
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

    /// The decoder stops at the end of the DEFLATE stream without reading what
    /// follows it, so the end-of-stream check runs over the decoder's input
    /// buffer: a payload that ends the stream ends the check, and trailing bytes
    /// the decoder never consumed are refused.
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

    /// A payload that decompresses past the size its header declares is refused,
    /// and the refusal reads one byte past the declaration rather than the rest
    /// of a stream that never ends.
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

    /// A stream of empty non-final DEFLATE blocks: five bytes that decompress to
    /// nothing, repeated. Past a budget well above the bound under test it fails,
    /// so a compressed stream nothing bounds fails this test rather than running
    /// until the process runs out of memory.
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

    /// A payload that decompresses to nothing for as long as it is sent is refused
    /// against the bound its declared size sets, since the decompressed bound never
    /// trips against it. The refusal reaches the caller as the refusal it is, and
    /// what the stream delivered is the bound plus the one read that tripped it.
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

    /// The bound refuses no object of the size it is stated for: data a compressor
    /// cannot shrink is the worst case, and its compressed form sits inside the
    /// bound its uncompressed size sets.
    #[test]
    fn the_compressed_bound_holds_incompressible_data() {
        block_on(async {
            // A linear congruential sequence, which deflate cannot shrink.
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

    /// The declaration is a ceiling, not an equality: a payload that reaches it
    /// is stored whole, and a shorter one is left to the checksum comparison.
    #[test]
    fn a_payload_within_its_declared_size_is_stored() {
        block_on(async {
            // One buffer serves both objects, the way a slot's does.
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
            // The buffer the first object grew is the one the second read
            // through, and it is the slot's read chunk.
            assert_eq!(buf.len(), READ_CHUNK);
        });
    }

    /// A declared header length past the header cap is refused before the buffer
    /// for it is allocated, so a remote directs at most that cap for each fetch
    /// in flight. The first byte past the cap is refused, as is the largest
    /// length the four-byte field holds.
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

    /// A ref name reaches the wire encoded: its `/` separators stand, and every
    /// character that would name something else does not.
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

    /// The outcome of a commit that was fetched and holds `tree`.
    fn fetched(checksum: Checksum, tree: Vec<ObjectName>, parent: Option<Checksum>) -> Step {
        Step::Commit(CommitOutcome {
            checksum,
            tree,
            parent,
            marked: true,
        })
    }

    /// Drain the plan by applying a stored outcome for each queued object, whose
    /// dirtrees reference nothing further.
    fn drain(plan: &mut Plan, marked: &mut Vec<Checksum>) {
        while let Some(item) = plan.next() {
            let step = match item {
                Item::Object(name) if name.ty == ObjectType::DirTree => Step::DirTree(Vec::new()),
                Item::Object(_) => Step::Done,
                Item::Commit(_) => panic!("the test queues no further commits"),
            };
            plan.apply(step, marked);
        }
    }

    /// A commit queues the objects it references, and reports that this pull
    /// marked it partial.
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

    /// An object several commits reach is queued once, whether the others reach
    /// it while it is still queued or after it was fetched.
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

    /// A commit reached again with further to go is not fetched again: the walk
    /// resumes at the parent it named.
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

    /// The drain order is the fetch order the pull relies on: the commits, then
    /// the objects the scan is blocked on, then the content.
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
            });
        }
        assert_eq!(drained, [csum(5), csum(2), csum(3), csum(4)]);
    }
}
