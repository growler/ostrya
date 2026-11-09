//! The export of collection refs onto removable media, and the import from
//! them.
//!
//! [`Repo::export_media`] copies the commits of collection refs onto a
//! mounted volume, into the repository `MOUNT/.ostree/repo`. A client that
//! has no network finds the repository on the volume and pulls from it. The
//! layout is the layout that `ostree create-usb` writes, and
//! `ostree find-remotes --pull` reads it.
//!
//! [`Repo::import_media`] finds the one media repository on the mounted
//! volumes, and pulls collection refs from it into the client repository,
//! under the trust of the remote of each collection.
//!
//! [`MediaExportOptions`] holds the options of the export, and
//! [`MediaExportReport`] gives the repository and the commit of each ref.
//! [`MediaImportOptions`] holds the options of the import, and
//! [`MediaImportReport`] gives the written, the unchanged, and the refused
//! refs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use ostrya_core::{Checksum, Ref, RefSelector, RepoMode, Value, is_valid_collection_id};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::config::{RepoConfig, valid_remote_name};
use crate::error::{Error, Result};
use crate::pull::{PullVerify, TimestampCheck, check_collection_binding, check_ref_binding};
use crate::refs::is_ref_path;
use crate::related::RelatedRule;
use crate::repo::{CreateOptions, Repo};
use crate::summary::{
    COLLECTION_ID_KEY, Summary, SummaryOptions, SummaryRef, collection_map_refs, parse_ref_list,
};
use crate::verify::PullTrust;

mod find;
mod mountinfo;

use find::{FoundMedia, MediaChoice};

/// The path of the media repository under the mount directory.
const MEDIA_REPO: &str = ".ostree/repo";

/// The directory of the media repository under the mount directory.
const MEDIA_DIR: &str = ".ostree";

/// The options of [`Repo::export_media`].
#[derive(Debug, Clone, Default)]
pub struct MediaExportOptions {
    /// The commit that the one ref of the export gets, in place of the
    /// commit of the ref in the source.
    ///
    /// The source must hold the commit. The ref need not exist in the
    /// source. The commit can be older than the commit of the ref on the
    /// media. The default is `None`: each ref gets the commit of the ref in
    /// the source.
    pub commit: Option<Checksum>,
}

/// The result of [`Repo::export_media`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaExportReport {
    /// The path of the media repository: `MOUNT/.ostree/repo`.
    pub repo: PathBuf,
    /// Each exported ref as a collection ref `@ID:NAME`, with its commit, in
    /// the order of the operands. An operand that occurs two times is in the
    /// list one time.
    pub refs: Vec<(Ref, Checksum)>,
}

/// The options of [`Repo::import_media`].
///
/// With no ref in [`refs`](MediaImportOptions::refs) and no collection in
/// [`collections`](MediaImportOptions::collections), the import takes each
/// ref on the media whose collection has a matched remote.
#[derive(Debug, Clone, Default)]
pub struct MediaImportOptions {
    /// The directory that the media finder probes in place of the mount
    /// table.
    ///
    /// The directory need not be a mount point. The default is `None`: the
    /// finder reads the mount table of the process.
    pub mount: Option<PathBuf>,
    /// The refs to import.
    ///
    /// `NAME` ([`Ref::Local`]) is the ref `@OWN:NAME`, where `OWN` is the
    /// `[core] collection-id` of the client repository. `@ID:NAME`
    /// ([`Ref::Collection`]) is the ref `NAME` of the collection `ID`.
    pub refs: Vec<Ref>,
    /// The collections to import each ref of, as the prefix `@ID:` does.
    pub collections: Vec<String>,
}

/// The result of [`Repo::import_media`].
///
/// Each list holds refs as collection refs `@ID:NAME`, also for the
/// `[core] collection-id` of the client repository, in the order of the
/// import.
#[derive(Debug)]
pub struct MediaImportReport {
    /// The path of the media repository.
    pub repo: PathBuf,
    /// Each ref that the import wrote, with its new commit.
    pub written: Vec<(Ref, Checksum)>,
    /// Each ref that held the commit of the media before the import, with
    /// that commit. The import did not pull it.
    pub unchanged: Vec<(Ref, Checksum)>,
    /// Each ref that the import refused, with the reason. The import did
    /// not change the ref.
    pub refused: Vec<(Ref, Error)>,
}

/// The reason why the media finder skipped a candidate repository that
/// exists.
///
/// [`Error::MediaNotFound`] holds each skipped candidate with its reason.
#[derive(Debug)]
#[non_exhaustive]
pub enum MediaSkip {
    /// The candidate is on another file system than the mount, or its path
    /// crosses a mount point.
    OtherFileSystem,
    /// The candidate is the client repository.
    Client,
    /// The finder cannot open the candidate, read its summary, or open its
    /// repository.
    Unreadable(Error),
    /// The summary of the candidate lists no collection ref, or the
    /// candidate has no summary.
    NoCollectionRef,
}

impl Repo {
    /// Copies the commits of the collection refs `refs` of this repository
    /// onto the volume that is mounted at `mount`.
    ///
    /// The media repository is `mount/.ostree/repo`. The call does not
    /// check that `mount` is a mount point.
    ///
    /// # Refs
    ///
    /// Each operand names one collection ref of this repository, the source:
    ///
    /// - `NAME` ([`Ref::Local`]) is the local ref `refs/heads/NAME`. It goes
    ///   onto the media as the ref `@OWN:NAME`, where `OWN` is the
    ///   `[core] collection-id` of the source.
    /// - `@ID:NAME` ([`Ref::Collection`]) is the collection ref of `ID`. The
    ///   call reads it as [`resolve_ref_tip`](Repo::resolve_ref_tip) does:
    ///   `refs/heads/NAME` when `ID` is the own id, and else
    ///   `refs/mirrors/ID/NAME`.
    ///
    /// The call reads the ref files alone. It does not read the `summary` of
    /// the source, and it does not read `refs/remotes/`. An operand that
    /// occurs two times is exported one time. The operands can name refs of
    /// more than one collection.
    ///
    /// The tip commit of each ref must have an `ostree.collection-binding`
    /// that states `ID`. If the `ostree.ref-binding` key is present, it must
    /// name `NAME`.
    ///
    /// # Media repository
    ///
    /// The call resolves each ref and checks each tip before it creates or
    /// changes a file. Then it creates `mount/.ostree` and the media
    /// repository in `archive` mode, if they do not exist. An existing
    /// repository keeps its mode and its `[core] collection-id`.
    ///
    /// The call makes one pull for each collection, in the order of the
    /// first operand of each collection. Each pull is a local pull at depth
    /// 0 with no signature check. It copies the `.commitmeta` of each
    /// commit, and the dependencies of field 2 of each commit as loose
    /// objects. It copies no static delta. It writes each ref to
    /// `refs/mirrors/ID/NAME`, or to `refs/heads/NAME` when `ID` is the
    /// `[core] collection-id` of the media repository. It moves a ref to an
    /// older commit with no error.
    ///
    /// Then the call sets `[core] indexed-deltas=true` in the `config` of the
    /// media repository, if the key does not hold `true`. Last, it writes
    /// the root summary of the media repository with
    /// [`root_summary_only`](SummaryOptions::root_summary_only): it removes
    /// an existing `summary.sig`, and it writes no `ostree-metadata` anchor
    /// commit.
    ///
    /// A failure after the checks, for example a full volume, can leave the
    /// media repository and objects on the volume. Each pull writes its refs
    /// when it completes, so a failure in the pull of a collection keeps the
    /// refs of the collections that the call pulled before it. The call then
    /// does not set `indexed-deltas` and writes no summary: the media
    /// repository keeps its old summary, or has none.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `refs` is empty, or if
    ///   [`commit`](MediaExportOptions::commit) is set and `refs` holds more
    ///   than one ref.
    /// - [`Error::InvalidRefspec`] if an operand is a remote ref, or fails
    ///   [`Ref::validate`].
    /// - [`Error::InvalidInput`] if an operand is a local ref and the source
    ///   has no `[core] collection-id`, or if two different operands name
    ///   one ref, for example `NAME` and `@OWN:NAME`.
    /// - [`Error::RefNotFound`] if the source does not hold a ref, with the
    ///   text `@ID:NAME`.
    /// - [`Error::ObjectNotFound`] if the source does not hold a tip commit,
    ///   for example the commit of [`commit`](MediaExportOptions::commit).
    /// - [`Error::Pull`] if a binding check of a tip fails.
    /// - [`Error::Io`] if `mount` does not exist or is not a directory. The
    ///   errors above and this error come before the call creates a file.
    /// - The errors of [`CreateOptions::create`], of
    ///   [`pull_local`](Repo::pull_local), of
    ///   [`write_config`](Repo::write_config), and of
    ///   [`regenerate_summary`](Repo::regenerate_summary).
    pub async fn export_media(
        &self,
        mount: &Path,
        refs: &[Ref],
        options: MediaExportOptions,
    ) -> Result<MediaExportReport> {
        if refs.is_empty() {
            return Err(Error::InvalidInput("a media export needs a ref".into()));
        }
        if options.commit.is_some() && refs.len() > 1 {
            return Err(Error::InvalidInput(
                "a media export with a commit takes one ref".into(),
            ));
        }
        let wanted = self.media_refs(refs)?;

        // Each ref resolves, and each tip passes its checks, before the
        // export creates a file.
        let mut tips = Vec::with_capacity(wanted.len());
        for &(id, name) in &wanted {
            let tip = match options.commit {
                Some(commit) => commit,
                None => {
                    // A name that reaches a directory of the ref tree, or a
                    // path under a ref file, is no ref of the source.
                    let target = Ref::collection(id, name);
                    match self.resolve_ref_tip(&target).await {
                        Ok(Some(tip)) => tip,
                        Ok(None) => return Err(Error::RefNotFound(target.to_string())),
                        Err(Error::Io(e))
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::IsADirectory
                                    | std::io::ErrorKind::NotADirectory
                            ) =>
                        {
                            return Err(Error::RefNotFound(target.to_string()));
                        }
                        Err(e) => return Err(e),
                    }
                }
            };
            let (commit, _) = self.load_commit(&tip).await?;
            check_ref_binding(&tip, &commit, name)?;
            check_collection_binding(&tip, &commit, id, false)?;
            tips.push(tip);
        }

        let dir = mount.to_owned();
        ostrya_rt::unblock(move || make_media_dir_blocking(&dir)).await?;
        let path = mount.join(MEDIA_REPO);
        let mut media = CreateOptions::new(RepoMode::Archive).create(&path).await?;

        // One pull for each collection, in the order of its first ref.
        let mut collections: Vec<(&str, Vec<(String, Checksum)>)> = Vec::new();
        for (&(id, name), tip) in wanted.iter().zip(&tips) {
            let slot = match collections.iter().position(|(other, _)| *other == id) {
                Some(slot) => slot,
                None => {
                    collections.push((id, Vec::new()));
                    collections.len() - 1
                }
            };
            collections[slot].1.push((name.to_owned(), *tip));
        }
        for (id, targets) in collections {
            media
                .pull_local_pinned(
                    self,
                    id,
                    targets,
                    PullTrust::unverified(),
                    TimestampCheck::Off,
                )
                .await?;
        }

        // The handle keeps the config that it read at the open, so the
        // summary reads the new key through a new handle.
        if !matches!(
            media.config().keyfile().get_bool("core", "indexed-deltas"),
            Ok(Some(true))
        ) {
            let mut keyfile = media.config().keyfile().clone();
            keyfile.set_value("core", "indexed-deltas", "true")?;
            media.write_config(&keyfile).await?;
            media = Repo::open(&path).await?;
        }
        media
            .regenerate_summary(&SummaryOptions {
                root_summary_only: true,
                ..SummaryOptions::default()
            })
            .await?;

        Ok(MediaExportReport {
            repo: path,
            refs: wanted
                .into_iter()
                .zip(tips)
                .map(|((id, name), tip)| (Ref::collection(id, name), tip))
                .collect(),
        })
    }

    /// Finds the one media repository on the mounted volumes, and pulls
    /// collection refs from it into this repository, the client.
    ///
    /// # Media repository
    ///
    /// The media finder reads the mount table of the process, or probes the
    /// directory [`mount`](MediaImportOptions::mount) alone. On each mount,
    /// it probes each entry of `.ostree/repos.d/`, then `.ostree/repo`,
    /// `ostree/repo`, and `var/lib/flatpak/repo`. The media repository of a
    /// mount is the first candidate whose summary lists a collection ref.
    /// The finder skips a candidate on another file system than the mount,
    /// the client repository, and a candidate that it cannot read. The
    /// import needs exactly one media repository.
    ///
    /// # Refs
    ///
    /// A ref `@ID:NAME` is on the media when the ref files of the media
    /// repository and its `summary` both list it. The summary lists the refs
    /// of `ID` in field 0 when it states the collection id `ID`, and else in
    /// the first entry of `ID` in `ostree.summary.collection-map`. The commit
    /// of the ref is the commit that the summary lists. The import reads no
    /// `summary.sig`.
    ///
    /// The import takes these refs, in this order:
    ///
    /// 1. Each ref of [`refs`](MediaImportOptions::refs), in order.
    /// 2. Each ref on the media of each collection of
    ///    [`collections`](MediaImportOptions::collections), in the order of
    ///    the collections, and in the byte order of the names in one
    ///    collection.
    ///
    /// A ref that the options name two times is imported one time. With no
    /// ref and no collection, the import takes each ref on the media whose
    /// collection has a matched remote, in the byte order of the collection
    /// ids and then of the names. It ignores each other collection.
    ///
    /// # Matched remote
    ///
    /// The matched remote of the collection `ID` is the first remote, in the
    /// byte order of the names, whose `collection-id` is `ID`. If no remote
    /// has that `collection-id`, it is the first remote whose
    /// `mirrored-collection-ids` holds `ID`. The import ignores a remote
    /// whose name or `collection-id` is not valid. It reads no summary of a
    /// remote.
    ///
    /// # Trust
    ///
    /// The import checks the commits of a collection with the trust of its
    /// matched remote, as [`PullTrust::from_remote`] reads it, with no check
    /// of the summary. If that trust checks no commit signature, the import
    /// checks the GPG signature of each commit with the keys of a pull from
    /// the remote with `gpg-verify=true`: the keyring of the remote, or the
    /// global trusted keyrings when the remote has no keyring of its own,
    /// and each keyring that `gpgkeypath` names. A build without the
    /// `verify-gpg` feature refuses each ref of such a remote that does not
    /// hold the commit of the media.
    ///
    /// # Pull
    ///
    /// The import does not pull a ref that holds the commit of the media.
    /// It makes one local pull from the media repository for each other ref,
    /// with its own transaction, as the pull of a local candidate of
    /// [`Repo::pull_collection`] does. The pull is at depth 0, and reads no
    /// static delta. It takes the `.commitmeta` and the dependencies of
    /// field 2 of the commit. The `ostree.collection-binding` of the commit
    /// must state `ID`, and the ref-binding check applies. The pull refuses
    /// a commit that is older than the commit of the ref in this repository,
    /// as [`TimestampCheck::CurrentRef`] states. It writes the ref to
    /// `refs/mirrors/ID/NAME`, or to `refs/heads/NAME` when `ID` is the
    /// `[core] collection-id` of this repository.
    ///
    /// A pull that fails refuses its ref, and the import continues with the
    /// next ref. [`MediaImportReport::refused`] holds the error.
    ///
    /// # Errors
    ///
    /// The import gives each error below before its first pull, and then
    /// changes no ref.
    ///
    /// - [`Error::InvalidRefspec`] if a ref of
    ///   [`refs`](MediaImportOptions::refs) is a remote ref or fails
    ///   [`Ref::validate`], or if a collection id of
    ///   [`collections`](MediaImportOptions::collections) is not valid. The
    ///   error of a collection id holds the text `@ID:`.
    /// - [`Error::InvalidInput`] if a ref is a local ref and this repository
    ///   has no `[core] collection-id`, or if two different refs name one
    ///   ref, for example `NAME` and `@OWN:NAME`.
    /// - [`Error::InvalidInput`] if a collection of the options has no
    ///   matched remote. The import gives this error before it reads the
    ///   media.
    /// - [`Error::Core`] if the `collection-id` of a remote holds a malformed
    ///   escape sequence, and the errors of
    ///   [`Remote::mirrored_collection_ids`](crate::config::Remote::mirrored_collection_ids).
    /// - The errors of
    ///   [`generate_composefs`](crate::config::RepoConfig::generate_composefs),
    ///   and [`Error::Core`] if `[ex-ostrya] keep-detached-related` of this
    ///   repository is not a boolean.
    /// - [`Error::Io`] if the finder cannot open
    ///   [`mount`](MediaImportOptions::mount), cannot read the mount table,
    ///   or cannot read the device and the inode of this repository.
    /// - [`Error::MediaNotFound`] if the finder finds no media repository.
    /// - [`Error::AmbiguousMedia`] if the finder finds more than one media
    ///   repository.
    /// - [`Error::Core`] or [`Error::InvalidFormat`] if the summary of the
    ///   media repository does not parse.
    /// - [`Error::RefNotFound`] if a ref of the options is not on the media,
    ///   with the text `@ID:NAME`, or if a collection of the options has no
    ///   ref on the media, with the text `@ID:`.
    /// - The errors of
    ///   [`list_collection_refs_in`](Repo::list_collection_refs_in) on the
    ///   media repository.
    /// - The errors of [`PullTrust::from_remote`] for a matched remote.
    pub async fn import_media(&self, options: MediaImportOptions) -> Result<MediaImportReport> {
        let named = self.media_refs(&options.refs)?;
        let mut prefixes: Vec<&str> = Vec::new();
        for id in &options.collections {
            if !is_valid_collection_id(id) {
                return Err(Error::InvalidRefspec(format!("@{id}:")));
            }
            if !prefixes.contains(&id.as_str()) {
                prefixes.push(id);
            }
        }
        // The commit of each transaction reads these keys again. These reads
        // fail a bad value before the scan of the media.
        self.config().generate_composefs()?;
        RelatedRule::of(self.config())?;

        // Each collection of the options, with its matched remote, before
        // the scan of the media.
        let remotes = served_collections(self.config())?;
        let mut collections: Vec<(&str, &str)> = Vec::new();
        for id in named
            .iter()
            .map(|&(id, _)| id)
            .chain(prefixes.iter().copied())
        {
            if collections.iter().any(|&(other, _)| other == id) {
                continue;
            }
            let Some(remote) = matched_remote(&remotes, id) else {
                return Err(Error::InvalidInput(format!(
                    "no remote matches the collection {id}: no remote has collection-id={id}, \
                     and no remote holds {id} in mirrored-collection-ids"
                )));
            };
            collections.push((id, remote));
        }
        let no_operand = named.is_empty() && prefixes.is_empty();
        if no_operand {
            // Each collection that a remote serves, in byte order.
            let mut ids: Vec<&str> = remotes
                .iter()
                .flat_map(|remote| {
                    remote
                        .collection_id
                        .as_deref()
                        .into_iter()
                        .chain(remote.mirrored.iter().map(String::as_str))
                })
                .collect();
            ids.sort_unstable();
            ids.dedup();
            collections = ids
                .into_iter()
                .filter_map(|id| Some((id, matched_remote(&remotes, id)?)))
                .collect();
        }

        let choice = match &options.mount {
            Some(dir) => find::find_media_in(self, dir).await?,
            None => find::find_media(self, mountinfo::read_table().await?).await?,
        };
        let FoundMedia {
            path,
            repo: media,
            summary,
        } = take_media(choice)?;
        let ids: Vec<String> = collections.iter().map(|&(id, _)| id.to_owned()).collect();
        let mut listed = ostrya_rt::unblock(move || summary_collections(&summary, &ids)).await?;
        if no_operand {
            collections.retain(|&(id, _)| listed.get(id).is_some_and(|refs| !refs.is_empty()));
        }

        // The refs of each collection on the media: the summary lists them,
        // and the media repository holds their ref files. For a collection
        // that only named refs select, the listing reads the files of these
        // names alone. A valid ref name holds no wildcard, so each name is a
        // literal pattern.
        let all = RefSelector::parse([])?;
        let mut on_media: HashMap<&str, BTreeMap<String, Checksum>> = HashMap::new();
        for &(id, _) in &collections {
            let only_named = !no_operand && !prefixes.contains(&id);
            let selector = if only_named {
                RefSelector::parse(
                    named
                        .iter()
                        .filter(|&&(other, _)| other == id)
                        .map(|&(_, name)| name),
                )?
            } else {
                all.clone()
            };
            let files: HashSet<String> = media
                .list_collection_refs_in(id, &selector)
                .await?
                .into_iter()
                .map(|(name, _)| name)
                .collect();
            let mut refs = listed.remove(id).unwrap_or_default();
            refs.retain(|name, _| files.contains(name));
            on_media.insert(id, refs);
        }
        drop(listed);

        let mut selected: Vec<(&str, String, Checksum)> = Vec::new();
        let seen: HashSet<(&str, &str)> = named.iter().copied().collect();
        for &(id, name) in &named {
            let Some(&commit) = on_media[id].get(name) else {
                return Err(Error::RefNotFound(Ref::collection(id, name).to_string()));
            };
            selected.push((id, name.to_owned(), commit));
        }
        for &id in &prefixes {
            let refs = on_media.remove(id).unwrap_or_default();
            if refs.is_empty() {
                return Err(Error::RefNotFound(format!("@{id}:")));
            }
            for (name, commit) in refs {
                if !seen.contains(&(id, name.as_str())) {
                    selected.push((id, name, commit));
                }
            }
        }
        if no_operand {
            for &(id, _) in &collections {
                for (name, commit) in on_media.remove(id).unwrap_or_default() {
                    selected.push((id, name, commit));
                }
            }
        }
        // Only the selected refs stay in memory during the pulls.
        drop(on_media);

        // The trust of each matched remote, one time, before the first pull.
        let remote_of: HashMap<&str, &str> = collections.iter().copied().collect();
        let mut trusts: HashMap<&str, Option<PullTrust>> = HashMap::new();
        for &(id, ..) in &selected {
            let remote = remote_of[id];
            if !trusts.contains_key(remote) {
                trusts.insert(remote, self.media_trust(remote).await?);
            }
        }

        let mut report = MediaImportReport {
            repo: path,
            written: Vec::new(),
            unchanged: Vec::new(),
            refused: Vec::new(),
        };
        for (id, name, commit) in selected {
            let target = Ref::collection(id, name.as_str());
            if matches!(self.resolve_ref_tip(&target).await, Ok(Some(tip)) if tip == commit) {
                report.unchanged.push((target, commit));
                continue;
            }
            let remote = remote_of[id];
            let Some(trust) = &trusts[remote] else {
                report.refused.push((target, no_gpg_engine(remote)));
                continue;
            };
            let targets = vec![(name, commit)];
            match self
                .pull_local_pinned(
                    &media,
                    id,
                    targets,
                    trust.clone(),
                    TimestampCheck::CurrentRef,
                )
                .await
            {
                Ok(_) => report.written.push((target, commit)),
                Err(e) => report.refused.push((target, e)),
            }
        }
        Ok(report)
    }

    /// Returns the trust of the import of the refs whose matched remote is
    /// `remote`, as [`import_media`](Repo::import_media) states, or `None`
    /// if the import needs a GPG check that this build cannot make.
    async fn media_trust(&self, remote: &str) -> Result<Option<PullTrust>> {
        // The summary of the media is unsigned, so the import checks no
        // summary.
        let verify = PullVerify {
            gpg_summary: Some(false),
            sign_summary: Some(false),
            ..PullVerify::default()
        };
        let trust = PullTrust::for_pull(self, remote, &verify, None).await?;
        if trust.checks_signatures() {
            return Ok(Some(trust));
        }
        #[cfg(feature = "verify-gpg")]
        {
            let verify = PullVerify {
                gpg: Some(true),
                ..verify
            };
            PullTrust::for_pull(self, remote, &verify, None)
                .await
                .map(Some)
        }
        #[cfg(not(feature = "verify-gpg"))]
        Ok(None)
    }

    /// Returns the collection id and the name of each ref of the operands
    /// `refs`, in order, as [`export_media`](Repo::export_media) states. An
    /// operand that occurs two times gives one entry.
    fn media_refs<'a>(&'a self, refs: &'a [Ref]) -> Result<Vec<(&'a str, &'a str)>> {
        let own = self.config().collection_id();
        let mut seen: HashMap<(&str, &str), &Ref> = HashMap::new();
        let mut wanted = Vec::with_capacity(refs.len());
        for r in refs {
            r.validate()?;
            let pair = match r {
                Ref::Local { name } => match own {
                    Some(id) => (id, name.as_str()),
                    None => {
                        return Err(Error::InvalidInput(format!(
                            "the ref {r} needs the collection id of the repository, and the \
                             repository has none"
                        )));
                    }
                },
                Ref::Collection { id, name } => (id.as_str(), name.as_str()),
                Ref::Remote { .. } => return Err(Error::InvalidRefspec(r.to_string())),
            };
            match seen.get(&pair) {
                Some(first) if *first == r => continue,
                Some(first) => {
                    return Err(Error::InvalidInput(format!(
                        "the refs {first} and {r} name one ref @{}:{}",
                        pair.0, pair.1
                    )));
                }
                None => {
                    seen.insert(pair, r);
                    wanted.push(pair);
                }
            }
        }
        Ok(wanted)
    }
}

/// Opens the directory `mount`, and creates the directory `.ostree` in it if
/// it does not exist, with the mode `0777` less the file-creation mask.
fn make_media_dir_blocking(mount: &Path) -> Result<()> {
    let fd = rustix::fs::open(
        mount,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    match rustix::fs::mkdirat(&fd, MEDIA_DIR, Mode::from_raw_mode(0o777)) {
        Ok(()) | Err(Errno::EXIST) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// The collections that one remote serves.
struct ServedCollections<'a> {
    /// The name of the remote.
    name: &'a str,
    /// The `collection-id` of the remote.
    collection_id: Option<String>,
    /// The `mirrored-collection-ids` of the remote.
    mirrored: Vec<String>,
}

/// Returns the collections of each remote of `config`, in the byte order of
/// the names. The list leaves out a remote whose name or `collection-id` is
/// not valid.
///
/// # Errors
///
/// - [`Error::Core`] if a `collection-id` holds a malformed escape sequence.
/// - The errors of
///   [`Remote::mirrored_collection_ids`](crate::config::Remote::mirrored_collection_ids).
fn served_collections(config: &RepoConfig) -> Result<Vec<ServedCollections<'_>>> {
    let mut names: Vec<&str> = config
        .remotes()
        .filter(|name| valid_remote_name(name))
        .collect();
    names.sort_unstable();
    names.dedup();
    let mut served = Vec::with_capacity(names.len());
    for name in names {
        let Some(remote) = config.remote(name) else {
            continue;
        };
        let collection_id = remote.collection_id()?;
        if collection_id
            .as_deref()
            .is_some_and(|id| !is_valid_collection_id(id))
        {
            continue;
        }
        served.push(ServedCollections {
            name,
            collection_id,
            mirrored: remote.mirrored_collection_ids()?,
        });
    }
    Ok(served)
}

/// Returns the matched remote of the collection `id` among `remotes`, as
/// [`Repo::import_media`] states, or `None` if no remote matches.
fn matched_remote<'a>(remotes: &[ServedCollections<'a>], id: &str) -> Option<&'a str> {
    remotes
        .iter()
        .find(|remote| remote.collection_id.as_deref() == Some(id))
        .or_else(|| {
            remotes
                .iter()
                .find(|remote| remote.mirrored.iter().any(|other| other == id))
        })
        .map(|remote| remote.name)
}

/// Applies the rule of one media repository to the result `choice` of the
/// media finder.
fn take_media(choice: MediaChoice) -> Result<FoundMedia> {
    match choice {
        MediaChoice::One(found) => Ok(found),
        MediaChoice::None(skipped) => Err(Error::MediaNotFound { skipped }),
        MediaChoice::Many(paths) => Err(Error::AmbiguousMedia { paths }),
    }
}

/// Returns the refs that the media summary `bytes` lists for each
/// collection of `ids`, with their commits.
///
/// If the summary states the collection id `S`, field 0 holds the refs of
/// `S`, and the call ignores an entry of `S` in the collection map. The
/// refs of each other collection come from the collection map. If the map
/// holds a collection id two times, the first entry counts. The first entry
/// of a name counts. The call leaves out a name that fails the ref-name
/// rule, and a collection id that is not valid. It parses the refs of the
/// collections of `ids` alone.
///
/// # Errors
///
/// - [`Error::Core`] or [`Error::InvalidFormat`] if the bytes do not parse,
///   or if the collection map is malformed.
fn summary_collections(
    bytes: &[u8],
    ids: &[String],
) -> Result<BTreeMap<String, BTreeMap<String, Checksum>>> {
    let metadata = Summary::parse_metadata(bytes)?;
    let own = metadata
        .dict_get(COLLECTION_ID_KEY)
        .and_then(Value::as_variant)
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned);
    let mut listed = BTreeMap::new();
    for id in ids {
        if Some(id) != own.as_ref() {
            add_listed(&mut listed, id, collection_map_refs(&metadata, id)?);
        }
    }
    drop(metadata);
    if let Some(id) = own.filter(|id| ids.contains(id)) {
        add_listed(&mut listed, &id, parse_ref_list(bytes)?);
    }
    Ok(listed)
}

/// Adds the refs `refs` of the collection `id` to `listed`, as
/// [`summary_collections`] states.
fn add_listed(
    listed: &mut BTreeMap<String, BTreeMap<String, Checksum>>,
    id: &str,
    refs: Vec<SummaryRef>,
) {
    if !is_valid_collection_id(id) {
        return;
    }
    let names = listed.entry(id.to_owned()).or_default();
    for entry in refs {
        if is_ref_path(&entry.name) {
            names.entry(entry.name).or_insert(entry.commit);
        }
    }
}

/// Returns the refusal of a ref whose matched remote `remote` checks no
/// commit signature, in a build with no GPG engine.
fn no_gpg_engine(remote: &str) -> Error {
    Error::Unsupported(format!(
        "remote '{remote}' checks no commit signature, so the media import checks the GPG \
         signature of the commit with the keyrings of the remote, and this build has no GPG \
         engine; build with the verify-gpg feature, or turn on sign-verify or a trust group \
         for the remote"
    ))
}

/// The options, the reports, and the futures of an export and an import
/// move across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MediaExportOptions>();
    assert_send_sync::<MediaExportReport>();
    assert_send_sync::<MediaImportOptions>();
    assert_send_sync::<MediaImportReport>();
    assert_send_sync::<MediaSkip>();
    fn assert_send<T: Send>(_: &T) {}
    let _ = |repo: &Repo, mount: &Path, refs: &[Ref]| {
        assert_send(&repo.export_media(mount, refs, MediaExportOptions::default()))
    };
    let _ = |repo: &Repo| assert_send(&repo.import_media(MediaImportOptions::default()));
};

#[cfg(test)]
mod tests {
    use super::*;

    /// No media repository gives each skipped candidate, and more than one
    /// gives the path of each.
    #[test]
    fn the_finder_result_maps_to_the_media_errors() {
        let skipped = vec![(PathBuf::from("/mnt/a/.ostree/repo"), MediaSkip::Client)];
        let err = take_media(MediaChoice::None(skipped)).err().unwrap();
        assert!(
            matches!(&err, Error::MediaNotFound { skipped }
                if matches!(skipped.as_slice(), [(path, MediaSkip::Client)]
                    if path == Path::new("/mnt/a/.ostree/repo"))),
            "{err:?}"
        );
        let paths = vec![
            PathBuf::from("/mnt/b/ostree/repo"),
            PathBuf::from("/mnt/a/.ostree/repo"),
        ];
        let err = take_media(MediaChoice::Many(paths.clone())).err().unwrap();
        assert!(
            matches!(&err, Error::AmbiguousMedia { paths: got } if *got == paths),
            "{err:?}"
        );
        assert!(err.to_string().contains("/mnt/b/ostree/repo"), "{err}");
    }

    /// The summary parse reads the first collection-map entry of an id, and
    /// parses no collection that the caller does not ask for.
    #[test]
    fn the_summary_parse_reads_the_first_map_entry_of_an_id() {
        use ostrya_core::{Type, to_bytes};
        let entry = |name: &str, byte: u8| {
            Value::Tuple(vec![
                Value::Str(name.to_owned()),
                Value::Tuple(vec![
                    Value::U64(0),
                    Value::Bytes(vec![byte; 32]),
                    Value::Array(Vec::new()),
                ]),
            ])
        };
        let collection = |id: &str, refs: Vec<Value>| {
            Value::Tuple(vec![Value::Str(id.to_owned()), Value::Array(refs)])
        };
        let map = Value::Array(vec![
            collection("org.x", vec![entry("a", 1)]),
            collection("org.x", vec![entry("b", 2)]),
            collection("org.y", vec![entry("c", 3)]),
        ]);
        let metadata = Value::Array(vec![Value::Tuple(vec![
            Value::Str("ostree.summary.collection-map".to_owned()),
            Value::variant(Type::parse("a{sa(s(taya{sv}))}").unwrap(), map),
        ])]);
        let summary = Value::Tuple(vec![Value::Array(Vec::new()), metadata]);
        let bytes = to_bytes(&Type::parse("(a(s(taya{sv}))a{sv})").unwrap(), &summary).unwrap();

        let listed = summary_collections(&bytes, &["org.x".to_owned()]).unwrap();
        let x: Vec<&str> = listed["org.x"].keys().map(String::as_str).collect();
        assert_eq!(x, ["a"]);
        assert!(!listed.contains_key("org.y"), "{listed:?}");
    }
}
