//! The export of commits from a repository as a one-way stream.

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

/// The options of [`Repo::export_stream`].
///
/// The struct is not `#[non_exhaustive]`. A caller can build it with
/// `..Default::default()`.
#[derive(Debug, Clone, Default)]
pub struct ExportStreamOptions {
    /// The ref updates that the `Commit` frame of the stream carries.
    ///
    /// Each update expects [`Absent`](Expected::Absent) or
    /// [`Any`](Expected::Any) and sets a new commit. A name is `NAME` or
    /// `REMOTE:NAME`. The new commits are the commits of the stream.
    pub updates: Vec<RefUpdate>,
    /// The encoding of the content objects.
    pub compression: Compression,
    /// The filter for the detached metadata of each commit in the stream.
    ///
    /// If the filter is unset, the stream carries every key.
    pub detached_metadata_filter: DetachedMetadataFilter,
}

/// Methods that export commits as a one-way stream.
impl Repo {
    /// Writes the commits that `opts.updates` name to `output` as a one-way stream.
    ///
    /// A one-way stream goes over a channel that carries data in one
    /// direction. On the other side, `Repo::receive_stream` of the `receive`
    /// feature reads it. The stream ends with the `Commit` frame, which
    /// carries the updates of `opts.updates`.
    ///
    /// The call returns the [`PushStats`] of the stream. The statistics count
    /// each object of the stream as offered and as needed.
    ///
    /// # Stream content
    ///
    /// The stream carries each new commit once. With each commit, it carries
    /// each object that the tree of the commit reaches. It also carries the
    /// detached metadata of the commit after
    /// [`detached_metadata_filter`](ExportStreamOptions::detached_metadata_filter).
    /// The stream carries no parent commit.
    ///
    /// The call does no negotiation, so it sends each object, also the
    /// objects that the receiver holds.
    ///
    /// If the repository is in `archive` mode and `opts.compression` is
    /// [`Deflate`](Compression::Deflate), the stream carries each file object
    /// in `deflate`. The stream copies the bytes of the stored `.filez` file
    /// of the object.
    ///
    /// # Lock
    ///
    /// After the checks of `opts.updates`, the call takes the repository lock
    /// as [`Shared`](LockKind::Shared). It holds the lock to the end of
    /// the call. [`LockKind`] describes the repository lock.
    ///
    /// # Output
    ///
    /// The call writes `output` as
    /// [`export_stream`](crate::push::session::export_stream) of the session
    /// states. It does not close `output`. The caller closes `output` to end
    /// the stream.
    ///
    /// # Missing file objects
    ///
    /// The call does not check before the stream that each file object
    /// exists. A missing file object or a failed read of the repository ends
    /// the stream inside the object that the call was to send. The call
    /// writes the abandon marker and `Abort`, and returns the error. The
    /// receiver then returns [`Aborted`](crate::push::Error::Aborted).
    ///
    /// # Errors
    ///
    /// Before the call writes the first byte to `output`, it returns:
    ///
    /// - [`Error::Push`](crate::Error::Push) with
    ///   [`InvalidInput`](crate::push::Error::InvalidInput) if `updates` is
    ///   empty, or names a ref two times.
    /// - [`Error::Push`](crate::Error::Push) with
    ///   [`InvalidInput`](crate::push::Error::InvalidInput) if an update
    ///   expects [`Expected::Commit`], or has no new commit.
    /// - [`Error::InvalidRefspec`](crate::Error::InvalidRefspec) if
    ///   [`validate_refspec`] refuses a ref name.
    /// - [`Error::InvalidRefspec`](crate::Error::InvalidRefspec) if an update
    ///   writes a ref name of 64 lowercase hex characters with no `REMOTE:`
    ///   part. A revision reads such a name as a commit checksum. A delete of
    ///   such a name gives the error of an update with no new commit.
    /// - [`Error::LockTimeout`](crate::Error::LockTimeout) if the wait for the
    ///   lock passes `[core] lock-timeout-secs`.
    /// - [`Error::InvalidFormat`](crate::Error::InvalidFormat) if
    ///   `[core] lock-timeout-secs` is less than `-1`.
    /// - [`Error::Core`](crate::Error::Core) if `[core] locking` is not a
    ///   boolean or `[core] lock-timeout-secs` is not an integer.
    /// - [`Error::ObjectNotFound`](crate::Error::ObjectNotFound) if the
    ///   repository does not hold a new commit, or a dirtree or a dirmeta
    ///   that the tree of a new commit reaches.
    /// - [`Error::Core`](crate::Error::Core) if a commit object or a dirtree
    ///   object does not parse.
    /// - [`Error::Push`](crate::Error::Push) with
    ///   [`InvalidInput`](crate::push::Error::InvalidInput) if the repository
    ///   marks a new commit partial.
    /// - [`Error::Push`](crate::Error::Push) with
    ///   [`BindingMismatch`](crate::push::Error::BindingMismatch) if the
    ///   `ostree.ref-binding` list of a commit does not hold the name of its
    ///   ref. The check leaves out the `REMOTE:` part of a remote ref. A
    ///   commit with no binding, or with an empty list, passes.
    /// - [`Error::Push`](crate::Error::Push) with
    ///   [`InvalidInput`](crate::push::Error::InvalidInput) if
    ///   `opts.compression` has a level outside 1 through 9.
    /// - [`Error::Push`](crate::Error::Push) with
    ///   [`InvalidInput`](crate::push::Error::InvalidInput) if the `Hello`
    ///   frame or the `Commit` frame is more than 1 MiB.
    /// - [`Error::Io`](crate::Error::Io) if the open or the lock of the lock
    ///   file fails.
    /// - [`Error::Io`](crate::Error::Io) if a read of a commit, of its
    ///   `.commitpartial` marker, or of a dirtree fails, or if a lookup of a
    ///   dirmeta fails. A commit or a dirtree that is not a regular file, or
    ///   that is larger than [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE),
    ///   also gives this error.
    ///
    /// After the first byte, the call returns:
    ///
    /// - [`Error::Push`](crate::Error::Push) with
    ///   [`Source`](crate::push::Error::Source) if the read of an object or
    ///   of detached metadata fails, also for a missing file object. It holds
    ///   the error of the repository.
    /// - [`Error::Push`](crate::Error::Push) with
    ///   [`InvalidInput`](crate::push::Error::InvalidInput) if the data of an
    ///   object cannot go in the stream, as
    ///   [`export_stream`](crate::push::session::export_stream) of the session
    ///   states.
    /// - [`Error::Push`](crate::Error::Push) with
    ///   [`Io`](crate::push::Error::Io) if a write to `output` or a flush of
    ///   `output` fails.
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
            if u.new.is_some() && ostrya_core::is_checksum_shaped(&u.name) {
                return Err(crate::Error::InvalidRefspec(u.name.clone()));
            }
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

/// Checks at compile time that the options are `Send + Sync` and that the
/// future of an export is `Send`.
const _: fn() = || {
    fn assert_send<T: Send>(_: T) {}
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ExportStreamOptions>();
    let _ = |repo: &Repo| {
        assert_send(repo.export_stream(futures_lite::io::sink(), ExportStreamOptions::default()))
    };
};
