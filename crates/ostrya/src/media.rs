//! The export of collection refs onto removable media.
//!
//! [`Repo::export_media`] copies the commits of collection refs onto a
//! mounted volume, into the repository `MOUNT/.ostree/repo`. A client that
//! has no network finds the repository on the volume and pulls from it. The
//! layout is the layout that `ostree create-usb` writes, and
//! `ostree find-remotes --pull` reads it.
//!
//! [`MediaExportOptions`] holds the options of the export, and
//! [`MediaExportReport`] gives the repository and the commit of each ref.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ostrya_core::{Checksum, Ref, RepoMode};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::error::{Error, Result};
use crate::pull::{check_collection_binding, check_ref_binding};
use crate::repo::{CreateOptions, Repo};
use crate::summary::SummaryOptions;

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
            media.pull_local_pinned(self, id, targets).await?;
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

/// The options, the report, and the future of an export move across tasks
/// and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MediaExportOptions>();
    assert_send_sync::<MediaExportReport>();
    fn assert_send<T: Send>(_: &T) {}
    let _ = |repo: &Repo, mount: &Path, refs: &[Ref]| {
        assert_send(&repo.export_media(mount, refs, MediaExportOptions::default()))
    };
};
