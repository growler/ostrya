//! The export of commits from a repository as one one-way stream.

use std::collections::HashSet;

use futures_io::AsyncWrite;
use ostrya_core::{Checksum, Commit, ObjectName, ObjectType};

use super::invalid;
use super::negotiate::check_ref_binding;
use super::source::RepoSource;
use crate::error::Result;
use crate::lock::LockKind;
use crate::pull::DetachedMetadataFilter;
use crate::push::{Compression, Expected, PushStats, RefUpdate, SessionOptions};
use crate::read::CommitState;
use crate::refs::validate_refspec;
use crate::repo::Repo;

/// What [`Repo::export_stream`] exports, and how.
///
/// The struct carries no `#[non_exhaustive]`: build it with
/// `..Default::default()`.
#[derive(Debug, Clone, Default)]
pub struct ExportStreamOptions {
    /// The ref updates of `Commit`. Each one expects
    /// [`Absent`](Expected::Absent) or [`Any`](Expected::Any) and sets a new
    /// commit. A name is `NAME` or `REMOTE:NAME`. The new commits are the
    /// commits of the stream.
    pub updates: Vec<RefUpdate>,
    /// The encoding of the content objects.
    pub compression: Compression,
    /// The filter the detached metadata of each commit passes before the
    /// stream carries it. Unset, the stream carries every key.
    pub detached_metadata_filter: DetachedMetadataFilter,
}

impl Repo {
    /// Write the commits that `opts.updates` name, and the updates, to
    /// `output` as one one-way stream, for `Repo::receive_stream` of the
    /// `receive` feature on the other side of a channel that carries data in
    /// one direction.
    ///
    /// The stream carries each new commit once, with each object its tree
    /// reaches and the detached metadata of the commit after
    /// [`detached_metadata_filter`](ExportStreamOptions::detached_metadata_filter).
    /// It carries no parent commit. The sender does no negotiation, so it
    /// sends each object whatever the receiver holds.
    ///
    /// The export holds the lock of the repository shared for the whole
    /// call. Before it writes a byte, the export refuses:
    ///
    /// - empty `updates`, a ref named twice, an update whose expected state
    ///   is [`Expected::Commit`], and an update with no new commit, as
    ///   [`Error::Push`](crate::Error::Push) with
    ///   [`InvalidInput`](crate::push::Error::InvalidInput);
    /// - a ref name that [`validate_refspec`] refuses, as
    ///   [`Error::InvalidRefspec`](crate::Error::InvalidRefspec);
    /// - a commit that the repository marks partial, as
    ///   [`Error::Push`](crate::Error::Push) with
    ///   [`InvalidInput`](crate::push::Error::InvalidInput);
    /// - a commit whose `ostree.ref-binding` is a list that does not hold the
    ///   name of its ref, the `REMOTE:` part of a remote ref left out, as
    ///   [`Error::Push`](crate::Error::Push) with
    ///   [`BindingMismatch`](crate::push::Error::BindingMismatch). A commit
    ///   with no binding, or with an empty list, passes;
    /// - a dirtree or a dirmeta that the repository does not hold, as
    ///   [`Error::ObjectNotFound`](crate::Error::ObjectNotFound);
    /// - each input that [`export_stream`](crate::push::session::export_stream)
    ///   of the session refuses: a level outside 1 through 9, and a `Hello`
    ///   or a `Commit` frame over 1 MiB, as
    ///   [`Error::Push`](crate::Error::Push) with
    ///   [`InvalidInput`](crate::push::Error::InvalidInput).
    ///
    /// The export does not check before the stream that each file object
    /// exists. A missing file object, and a source that fails, end the
    /// stream inside the object it was to send, with the abandon marker and
    /// `Abort`, and the export returns [`Error::Push`](crate::Error::Push)
    /// with the error of the source. The receiver then returns
    /// [`Aborted`](crate::push::Error::Aborted).
    ///
    /// An `archive` repository sends a file object in `deflate` as the bytes
    /// of its stored `.filez` file. The export writes `output` in blocks of
    /// 64 KiB, so the caller need not give a buffered writer. It flushes
    /// `output` after `Commit` and does not close it. The caller closes it, and the close
    /// gives the end of file that ends the stream. A caller that keeps its
    /// writer gives `&mut W`. The statistics count each object of the stream
    /// as offered and as needed.
    pub async fn export_stream<W>(&self, output: W, opts: ExportStreamOptions) -> Result<PushStats>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let updates = &opts.updates;
        if updates.is_empty() {
            return Err(invalid("a commit needs at least one ref update"));
        }
        let mut named = HashSet::new();
        for u in updates {
            validate_refspec(&u.name)?;
            if !named.insert(u.name.as_str()) {
                return Err(invalid(format!("ref '{}' is updated twice", u.name)));
            }
            if let Expected::Commit(_) = u.expected {
                return Err(invalid(format!(
                    "the update of '{}' expects a commit, which a one-way stream cannot state",
                    u.name
                )));
            }
            if u.new.is_none() {
                return Err(invalid(format!(
                    "the update of '{}' deletes the ref, which a one-way stream cannot do",
                    u.name
                )));
            }
        }
        drop(named);

        let _lock = self.lock_repo(LockKind::Shared).await?;
        // Each new commit once, in the order of the updates.
        let mut loaded: Vec<(Checksum, Commit)> = Vec::new();
        for u in updates {
            let checksum = u.new.expect("a delete is refused");
            let position = match loaded.iter().position(|(c, _)| *c == checksum) {
                Some(position) => position,
                None => {
                    let (commit, state) = self.load_commit(&checksum).await?;
                    if state == CommitState::Partial {
                        return Err(invalid(format!(
                            "commit {checksum} for '{}' is marked partial in the local \
                             repository",
                            u.name
                        )));
                    }
                    loaded.push((checksum, commit));
                    loaded.len() - 1
                }
            };
            check_ref_binding(&checksum, &loaded[position].1, &u.name)?;
        }

        let commits: Vec<Checksum> = loaded.iter().map(|(c, _)| *c).collect();
        let mut names: Vec<ObjectName> = commits
            .iter()
            .map(|c| ObjectName::new(*c, ObjectType::Commit))
            .collect();
        let mut seen = HashSet::new();
        for (_, commit) in &loaded {
            self.collect_tree_strict(
                commit.root_dirtree,
                commit.root_dirmeta,
                &mut seen,
                &mut names,
            )
            .await?;
        }
        drop(seen);
        drop(loaded);

        let source = RepoSource::new(self.clone(), opts.detached_metadata_filter);
        Ok(crate::push::session::export_stream(
            output,
            &source,
            &names,
            &commits,
            updates,
            opts.compression,
            SessionOptions::default(),
        )
        .await?)
    }
}

/// The options and the future of an export move to another thread.
const _: fn() = || {
    fn assert_send<T: Send>(_: T) {}
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ExportStreamOptions>();
    let _ = |repo: &Repo| {
        assert_send(repo.export_stream(futures_lite::io::sink(), ExportStreamOptions::default()))
    };
};
