//! The export of commits from a repository as a one-way stream.

use std::collections::HashSet;

use futures_io::AsyncWrite;
use ostrya_core::{Checksum, Commit, ObjectName, ObjectType};

use super::invalid;
use super::negotiate::{Commits, Local, check_ref_binding, link_of};
use super::source::RepoSource;
use crate::error::Result;
use crate::lock::LockKind;
use crate::read::CommitState;
use crate::refs::validate_refspec;
use crate::related::{self, RelatedRule};
use crate::remote::{Compression, Expected, PushStats, RefUpdate, SessionOptions};
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
    /// `REMOTE:NAME`. The new commits are the commits of the stream. The
    /// stream also carries the dependencies of the new commits, with no ref.
    pub updates: Vec<RefUpdate>,
    /// The encoding of the content objects.
    pub compression: Compression,
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
    /// The stream carries each new commit once, then each dependency of the
    /// new commits once. With each commit, it carries each object that the
    /// tree of the commit reaches. It also carries the stored `.commitmeta`
    /// bytes of the commit with no parse, so the receiver refuses a
    /// `.commitmeta` that is not an `a{sv}` dict. If the repository holds the
    /// composefs image of a sent commit, the stream carries the image after
    /// the trees. The stream carries no parent commit.
    ///
    /// The call does no negotiation, so it sends each object, also the
    /// objects that the receiver holds.
    ///
    /// If the repository is in `archive` mode and `opts.compression` is
    /// [`Deflate`](Compression::Deflate), the stream carries each file object
    /// in `deflate`. The stream copies the bytes of the stored `.filez` file
    /// of the object.
    ///
    /// # Dependencies
    ///
    /// Field 2 of a commit names the dependencies of the commit.
    /// [`read_commit_related`](Repo::read_commit_related) reads them. The
    /// stream carries the dependencies of each new commit.
    ///
    /// - The call sends each dependency at depth 0, so a dependency entry
    ///   adds no parent to the stream. The stream carries a dependency one
    ///   time, also if several commits name it, or if it is also a new
    ///   commit.
    /// - The `Commit` frame holds no ref update for a dependency.
    /// - For each dependency, the stream carries the commit object, the
    ///   objects of its tree, and its detached metadata. If the repository
    ///   holds the composefs image of the dependency, the stream carries it.
    ///   An object that a new commit and a dependency share goes in the stream
    ///   one time.
    /// - The call does no negotiation, so it sends a dependency that the
    ///   receiver holds. The receiver accepts it, and drops its
    ///   `.commitmeta`: a held dependency gets no merge of detached metadata
    ///   and no signature.
    /// - A receiver that holds a dependency and marks it partial refuses the
    ///   stream with [`MissingObjects`](crate::remote::Error::MissingObjects)
    ///   and no object listed, also though the stream carries the whole tree
    ///   of the dependency. To complete the dependency at the receiver, send
    ///   it as the new commit of an update, in this stream or in an earlier
    ///   one. The receiver then removes its partial marker.
    /// - The call makes no ref-binding check on a dependency.
    /// - The call does not send a build source: a commit that the detached
    ///   metadata key `ostrya.related` names. The key goes with the detached
    ///   metadata of its commit.
    ///
    /// These cases refuse the export before the call writes the first byte:
    ///
    /// - An entry of field 2 of a new commit has an empty name or a checksum
    ///   that is not 32 bytes.
    /// - The repository does not hold a dependency, or marks it partial.
    /// - A dependency names dependencies of its own: its own field 2 is not
    ///   empty, also if that field 2 holds a defective entry. This is also
    ///   true for a dependency that is also a new commit. If the field 2 of
    ///   such a new commit holds a defective entry, the first case refuses
    ///   the export first.
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
    /// [`export_stream`](crate::remote::session::export_stream) of the session
    /// states. It does not close `output`. The caller closes `output` to end
    /// the stream.
    ///
    /// # Missing file objects
    ///
    /// The call does not check before the stream that each file object
    /// exists. A missing file object or a failed read of the repository ends
    /// the stream inside the object that the call was to send. The call
    /// writes the abandon marker and `Abort`, and returns the error. The
    /// receiver then returns [`Aborted`](crate::remote::Error::Aborted).
    ///
    /// # Errors
    ///
    /// Before the call writes the first byte to `output`, it returns:
    ///
    /// - [`Error::Remote`](crate::Error::Remote) with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if `updates` is
    ///   empty, or names a ref two times.
    /// - [`Error::Remote`](crate::Error::Remote) with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if an update
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
    ///   repository does not hold a new commit or a dependency, or a dirtree
    ///   or a dirmeta that the tree of a sent commit reaches.
    /// - [`Error::InvalidRelated`](crate::Error::InvalidRelated) if an entry
    ///   of field 2 of a new commit has an empty name or a checksum that is
    ///   not 32 bytes, or if the repository marks a dependency partial, or if
    ///   a dependency names dependencies of its own.
    /// - [`Error::Core`](crate::Error::Core) if a new commit or a dirtree
    ///   object does not parse. For the commit object of a dependency, the
    ///   call decodes the tuple frame, the parent and root checksums, and
    ///   field 2 alone, and gives this error if one of them does not decode.
    /// - [`Error::Remote`](crate::Error::Remote) with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the repository
    ///   marks a new commit partial.
    /// - [`Error::Remote`](crate::Error::Remote) with
    ///   [`BindingMismatch`](crate::remote::Error::BindingMismatch) if the
    ///   `ostree.ref-binding` list of a commit does not hold the name of its
    ///   ref. The check leaves out the `REMOTE:` part of a remote ref. A
    ///   commit with no binding, or with an empty list, passes.
    /// - [`Error::Remote`](crate::Error::Remote) with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if
    ///   `opts.compression` has a level outside 1 through 9.
    /// - [`Error::Remote`](crate::Error::Remote) with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the `Hello`
    ///   frame or the `Commit` frame is more than 1 MiB.
    /// - [`Error::Io`](crate::Error::Io) if the open or the lock of the lock
    ///   file fails.
    /// - [`Error::Io`](crate::Error::Io) if a read of a commit or of a
    ///   dependency, of its `.commitpartial` marker, or of a dirtree fails, or
    ///   if a lookup of a dirmeta fails. A commit or a dirtree that is not a
    ///   regular file, or that is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), also gives this
    ///   error.
    ///
    /// After the first byte, the call returns:
    ///
    /// - [`Error::Remote`](crate::Error::Remote) with
    ///   [`Source`](crate::remote::Error::Source) if the read of an object or
    ///   of detached metadata fails, also for a missing file object. It holds
    ///   the error of the repository.
    /// - [`Error::Remote`](crate::Error::Remote) with
    ///   [`InvalidInput`](crate::remote::Error::InvalidInput) if the data of an
    ///   object cannot go in the stream, as
    ///   [`export_stream`](crate::remote::session::export_stream) of the session
    ///   states.
    /// - [`Error::Remote`](crate::Error::Remote) with
    ///   [`Io`](crate::remote::Error::Io) if a write to `output` or a flush of
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
        let mut targets: Vec<Checksum> = Vec::new();
        let mut loaded: Vec<Commit> = Vec::new();
        let mut commits = Commits::default();
        for u in updates {
            let checksum = u.new.expect("a delete is refused");
            let position = match targets.iter().position(|c| *c == checksum) {
                Some(position) => position,
                None => {
                    let (mut commit, state) = self.load_commit(&checksum).await?;
                    if state == CommitState::Partial {
                        return Err(invalid(format!(
                            "commit {checksum} for '{}' is marked partial in the local \
                             repository",
                            u.name
                        )));
                    }
                    commits
                        .local
                        .insert(checksum, Local::Held(link_of(&commit)));
                    let related = std::mem::take(&mut commit.related);
                    commits.record(checksum, related::checked_dependencies(&checksum, related));
                    targets.push(checksum);
                    loaded.push(commit);
                    loaded.len() - 1
                }
            };
            check_ref_binding(&checksum, &loaded[position], &u.name)?;
        }
        drop(loaded);

        // The format of field 2 of each new commit, then its dependencies,
        // before the first byte.
        commits.check_fields(&targets)?;
        commits.check_dependencies(self, &targets).await?;

        // The new commits, then each dependency once.
        let mut sent = targets.clone();
        let mut known: HashSet<Checksum> = targets.iter().copied().collect();
        for target in &targets {
            for dependency in commits.dependencies_of(target) {
                if known.insert(dependency) {
                    sent.push(dependency);
                }
            }
        }
        drop(known);

        let mut names: Vec<ObjectName> = sent
            .iter()
            .map(|c| ObjectName::new(*c, ObjectType::Commit))
            .collect();
        let mut seen = HashSet::new();
        for commit in &sent {
            let Local::Held(link) = commits.local[commit] else {
                unreachable!("a sent commit is held");
            };
            self.collect_tree_strict(link.root_dirtree, link.root_dirmeta, &mut seen, &mut names)
                .await?;
        }
        drop(seen);
        drop(commits);
        // The composefs image of each sent commit that this repository holds
        // goes after the trees.
        let repo = self.clone();
        let wanted = sent.clone();
        let images = ostrya_rt::unblock(move || -> Result<Vec<ObjectName>> {
            let mut images = Vec::new();
            for commit in wanted {
                if repo.has_object_blocking(ObjectType::ComposefsImage, &commit)? {
                    images.push(ObjectName::new(commit, ObjectType::ComposefsImage));
                }
            }
            Ok(images)
        })
        .await?;
        names.extend(images);

        let source = RepoSource::new(self.clone(), RelatedRule::default());
        Ok(crate::remote::session::export_stream(
            output,
            &source,
            &names,
            &sent,
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
