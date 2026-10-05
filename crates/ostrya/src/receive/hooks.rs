//! The hooks a host gives one receive session: the call before the update
//! lock of the commit, the detached-metadata entries it returns, and the call
//! after the update lock is released.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;

use ostrya_core::{Checksum, Value};

use super::session::{Failure, ReceiveReport};
use crate::push::{self, RefUpdate};

/// The future a hook returns. It is `Send`, so the commit of a session can
/// run on a thread pool.
pub type HookFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The longest message of a hook, in bytes: the message of a [`HookRefusal`]
/// and the error of [`ReceiveHooks::after_update`].
pub(super) const MAX_MESSAGE: usize = 4096;

/// Cut `message` to [`MAX_MESSAGE`] bytes at a character boundary. A message
/// that is cut releases the memory past the cut.
pub(super) fn cut(message: &mut String) {
    if message.len() > MAX_MESSAGE {
        message.truncate(message.floor_char_boundary(MAX_MESSAGE));
        message.shrink_to_fit();
    }
}

/// The hooks of one receive session, which a host gives through
/// [`ReceiveService::hello_with_hooks`](super::ReceiveService::hello_with_hooks).
///
/// The hooks belong to the session. [`ReceiveService::hello`](super::ReceiveService::hello),
/// [`Repo::receive`](crate::Repo::receive), and
/// [`Repo::receive_stream`](crate::Repo::receive_stream) take none. The
/// receive endpoint of `ostrya-server` gives the hooks that its
/// `SessionSetup` holds.
///
/// # When `before_update` runs
///
/// [`before_update`](Self::before_update) runs once in each `Commit` of a
/// session with hooks, just before the update lock. Before it, the commit
/// runs all its checks of the ref names, of the size of the reply, of the
/// rules of the policy, of the objects, of the ref and collection bindings,
/// and of the signature policy. The server signatures and the ancestry walks
/// of the fast-forward check also run before it. A commit that fails one of
/// these checks does not call the hook.
///
/// The hook gets every ref update of the `Commit` message, a delete
/// included, as the client sent it: a delete has `new` set to `None`, and
/// `expected` is the state the client expects. The hook gets no `force`
/// flag: the policy of the session holds `allow_non_fast_forward`.
///
/// The checks of the current value of each ref run under the update lock,
/// after the hook: `ref-mismatch`, `non-fast-forward`, `delete-denied`, and
/// the refusal of a ref that is an alias. So a commit can fail after the hook
/// returned a plan. When one of these checks fails, no ref changes. On each
/// failure of the commit after the hook, the carried value drops once after
/// the update lock is released, and `after_update` does not run.
///
/// # The entries of the host
///
/// [`UpdatePlan::metadata`] gives detached-metadata entries for the new
/// commits of the updates. The commit writes them into the detached
/// metadata of each commit:
///
/// - A host entry replaces an entry of the client dict with the same key.
///   This is not a duplicate-key error.
/// - A commit with no client dict gets a new dict.
/// - The `detached-metadata-exclude` filter of the policy does not apply to
///   the host entries.
/// - A host entry with [`keep_existing`](HostEntry::keep_existing) false
///   replaces the value that the stored dict holds under its key. A host
///   entry with `keep_existing` true keeps a value that the stored dict holds
///   under its key, and its value is written only when the stored dict has
///   no such key. The stored dict is the one the repository holds under the
///   update lock, when the commit writes the detached metadata.
///
/// The entries are written also for an update that changes no ref, because
/// the ref names the commit already, and once for a commit that several
/// updates name. A plan with no entry writes no detached metadata.
///
/// A host entry cannot have a signature key: `ostree.gpgsigs`,
/// `ostree.sign.ed25519`, `ostree.sign.spki`, or `ostree.sign.dummy`. The
/// commit refuses with `internal`, before any merge, and changes no ref:
///
/// - a commit that is not the new commit of an update;
/// - a commit that the plan gives in two tuples;
/// - an entry under a signature key;
/// - a key that the plan gives two times for one commit;
/// - a value that is not a [`Value::Variant`];
/// - a variant that does not encode: an inner value that does not have the
///   type of the variant, a string with a NUL byte, a value or a type nested
///   deeper than the parser reads, or a type that the parser does not read,
///   for example a dict entry whose key is not a basic type. A key with a NUL
///   byte does not encode either.
///
/// The first five checks run over the whole plan first, in the order of the
/// tuples, and in each tuple in the order of its entries. The encode check
/// then runs over the plan in the same order. The first failure is the
/// refusal. A merged dict over
/// [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) is `limit-exceeded`, before
/// the update lock. No ref changes in any of these cases.
///
/// The detached metadata and the refs are written in one transaction
/// commit, and the detached metadata is durable before a ref names the
/// commit. So a mirror that pulls when the ref moves reads the entries of the
/// host.
///
/// # When `after_update` runs
///
/// [`after_update`](Self::after_update) runs once in each commit whose
/// transaction commit succeeds, also when no ref changes, for example when
/// each update names the commit that its ref names already. It runs after
/// the transaction commit, the removal of the partial markers, and the
/// summary step, and after the update lock is released. It gets the
/// [`ReceiveReport`] that the commit returns, and the carried value of the
/// plan. The hook owns the carried value from then on.
///
/// The transaction commit is not atomic. It writes the detached metadata,
/// then each ref, and then runs `fsync` on the ref directories. A failure of
/// a detached-metadata write, of a ref write, or of the `fsync` of a ref
/// directory can leave the detached metadata and some refs written. The
/// commit then returns the error as a failure on the server side, the
/// carried value drops, and `after_update` does not run. So the host makes
/// its own records agree with the refs of the repository.
///
/// The report goes to the hook before the host sends the reply, so it never
/// holds a warning of the step
/// [`ReplyNotDelivered`](super::ReceiveStep::ReplyNotDelivered). The time of
/// the hook adds to the time the commit takes to return.
///
/// An error of the hook makes the commit return `internal` with the message,
/// cut at 4096 bytes at a character boundary. The session then ends as
/// aborted. The refs and the detached metadata stay written, and the session
/// does not undo them: an aborted session can have written its refs.
///
/// # Locks
///
/// The session holds the repository lock shared from `Hello` to the commit of
/// its transaction. So the lock order is always: the repository lock shared, then
/// the locks the hook takes, then the update lock. The host obeys two rules:
///
/// - It never takes a lock that `before_update` takes while it holds the
///   update lock or an [`UpdateGuard`](crate::UpdateGuard).
/// - It never waits for an exclusive repository lock, for example the lock
///   of a prune, while it holds a lock that `before_update` takes.
///
/// The host can put the guards of its locks in [`UpdatePlan::carried`]. They
/// are then held from `before_update` across the wait for the update lock and
/// the ref update, until `after_update` drops the carried value. `carried` is
/// a `Box<dyn Any + Send>`, which is `'static`, so each guard in it must be an
/// owned guard. The session never looks inside `carried`.
///
/// When `after_update` runs, the session holds no lock: the update lock is
/// released, and the transaction commit released the repository lock shared.
/// So the hook can call [`Repo::set_ref_immediate`](crate::Repo::set_ref_immediate)
/// and [`Repo::begin_update`](crate::Repo::begin_update). The guards in the
/// carried value are still held, so the two rules still apply. While it holds
/// the carried value, the hook never waits for an exclusive repository lock,
/// for example the lock of a prune. Another session can hold the repository
/// lock shared and wait in `before_update` for a lock in the carried value,
/// and the two then deadlock.
///
/// The transaction commit writes the detached metadata and the refs on the
/// blocking pool. A [`commit`](super::ReceiveService::commit) future that is
/// dropped before it completes can release the update lock and drop the
/// carried value while these writes go on. A `commit` future that is dropped
/// while `after_update` runs drops the future of the hook and the carried
/// value, and the refs can be written. So the host runs each commit to its
/// end, for example in a task that it joins.
///
/// A panic in a hook is not caught. A panic in `after_update` comes after the
/// refs are written, and resumes in the caller of
/// [`commit`](super::ReceiveService::commit).
pub trait ReceiveHooks: Send + Sync {
    /// Give the detached-metadata entries of the host for the new commits of
    /// `updates`, and a value that goes to
    /// [`after_update`](Self::after_update), or refuse the commit.
    fn before_update<'a>(
        &'a self,
        updates: &'a [RefUpdate],
    ) -> HookFuture<'a, Result<UpdatePlan, HookRefusal>>;

    /// Take the report of a commit whose transaction commit succeeded, and the
    /// carried value of the plan of [`before_update`](Self::before_update).
    /// An error is `internal`, and the refs stay written.
    fn after_update<'a>(
        &'a self,
        report: &'a ReceiveReport,
        carried: Box<dyn Any + Send>,
    ) -> HookFuture<'a, Result<(), String>>;
}

/// What [`ReceiveHooks::before_update`] returns.
#[derive(Debug)]
pub struct UpdatePlan {
    /// The detached-metadata entries of the host, for each new commit, at
    /// most one tuple for each commit.
    pub metadata: Vec<(Checksum, Vec<HostEntry>)>,
    /// A value that goes to [`ReceiveHooks::after_update`]. On a failure of
    /// the commit after `before_update`, it drops once after the update lock
    /// is released, and `after_update` does not run. A failure of the
    /// transaction commit can leave the detached metadata and some refs
    /// written.
    pub carried: Box<dyn Any + Send>,
}

/// One detached-metadata entry of the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    /// The key.
    pub key: String,
    /// The value, a [`Value::Variant`].
    pub value: Value,
    /// With `false`, the value replaces the value that the stored dict or the
    /// client dict holds under the key. With `true`, a value that the stored
    /// dict holds under the key stays, and the value is written only when the
    /// stored dict has no such key.
    pub keep_existing: bool,
}

/// A refusal of [`ReceiveHooks::before_update`]. No ref changes.
#[derive(Debug)]
pub struct HookRefusal {
    kind: Kind,
    message: String,
}

#[derive(Debug)]
enum Kind {
    Denied,
    Internal,
}

impl HookRefusal {
    /// A refusal with the code `ref-denied`. The receive endpoint of an HTTP
    /// server answers it with 422. A message longer than 4096 bytes is cut at
    /// a character boundary.
    pub fn denied(message: impl Into<String>) -> HookRefusal {
        HookRefusal::new(Kind::Denied, message.into())
    }

    /// A refusal with the code `internal`. The receive endpoint of an HTTP
    /// server answers it with 500. A message longer than 4096 bytes is cut at
    /// a character boundary.
    pub fn internal(message: impl Into<String>) -> HookRefusal {
        HookRefusal::new(Kind::Internal, message.into())
    }

    fn new(kind: Kind, mut message: String) -> HookRefusal {
        cut(&mut message);
        HookRefusal { kind, message }
    }

    /// The failure of the session for the refusal.
    pub(super) fn into_failure(self) -> Failure {
        Failure::Wire(match self.kind {
            Kind::Denied => push::Error::RefDenied(self.message),
            Kind::Internal => push::Error::Internal(self.message),
        })
    }
}
