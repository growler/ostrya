//! The hooks that a host gives one receive session.
//!
//! The first hook runs before the update lock of the commit and returns
//! detached-metadata entries. The second hook runs after the release of the
//! update lock.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;

use ostrya_core::{Checksum, Value};

use super::session::{Failure, ReceiveReport};
use crate::push::{self, RefUpdate};

/// The future that a hook returns.
///
/// The future is `Send`, so the commit of a session can run on a thread pool.
pub type HookFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The longest message of a hook, in bytes: the message of a [`HookRefusal`]
/// and the error of [`ReceiveHooks::after_update`].
pub(super) const MAX_MESSAGE: usize = 4096;

/// Cuts `message` to [`MAX_MESSAGE`] bytes at a character boundary.
///
/// If the message is cut, this function releases the memory past the cut.
pub(super) fn cut(message: &mut String) {
    if message.len() > MAX_MESSAGE {
        message.truncate(message.floor_char_boundary(MAX_MESSAGE));
        message.shrink_to_fit();
    }
}

/// Host calls that run before and after the ref update of a receive session.
///
/// A host gives the hooks to one session through
/// [`ReceiveService::hello_with_hooks`](super::ReceiveService::hello_with_hooks).
/// [`ReceiveService::hello`](super::ReceiveService::hello),
/// [`Repo::receive`](crate::Repo::receive), and
/// [`Repo::receive_stream`](crate::Repo::receive_stream) take no hooks. The
/// receive endpoint of `ostrya-server` gives the hooks that its
/// `SessionSetup` holds.
///
/// # When `before_update` runs
///
/// In a session with hooks, [`before_update`](Self::before_update) runs once
/// in each `Commit`, just before the update lock. Before the hook, the commit
/// runs all its checks of these items:
///
/// - the ref names
/// - the size of the reply
/// - the commits of the detached metadata
/// - the rules of the policy
/// - the objects
/// - the ref and collection bindings
/// - the signature policy
///
/// The server signatures and the ancestry walks of the fast-forward check
/// also run before the hook. If the commit fails one of these checks, it does
/// not call the hook.
///
/// The hook gets each ref update of the `Commit` message as the client sent
/// it, deletes included. A delete has `new` set to `None`. The `expected`
/// field is the state that the client expects. The hook gets no `force` flag,
/// because the policy of the session holds `allow_non_fast_forward`.
///
/// The checks of the current value of each ref run after the hook, under the
/// update lock, in this order:
///
/// 1. the `ref-denied` refusals of a ref path, for example a ref that is an
///    alias
/// 2. `ref-mismatch`
/// 3. `delete-denied`
/// 4. `non-fast-forward`
///
/// A commit can fail at these checks after the hook returns a plan. If one of
/// these checks fails, no ref changes. If the commit fails after the hook, the
/// carried value drops once, after the release of the update lock, and
/// `after_update` does not run.
///
/// # The entries of the host
///
/// [`UpdatePlan::metadata`] gives detached-metadata entries for the new
/// commits of the updates. The commit writes them into the detached metadata
/// of each of these commits:
///
/// - A host entry replaces an entry of the client dict with the same key,
///   with no duplicate-key error.
/// - A commit with no client dict gets a new dict.
/// - The `detached-metadata-exclude` filter of the policy does not apply to
///   the host entries.
/// - If [`keep_existing`](HostEntry::keep_existing) is `false`, the host entry
///   replaces the value that the stored dict holds under its key.
/// - If `keep_existing` is `true`, a value that the stored dict holds under
///   the key stays. The commit writes the host value only if the stored dict
///   has no such key.
///
/// The stored dict is the dict that the repository holds under the update
/// lock, when the commit writes the detached metadata.
///
/// The commit writes the entries also for an update that changes no ref
/// because the ref already names the commit. It writes them once for a commit
/// that several updates name. If the plan has no entry, the commit writes no
/// detached metadata.
///
/// A host entry cannot have a signature key: `ostree.gpgsigs`,
/// `ostree.sign.ed25519`, `ostree.sign.spki`, or `ostree.sign.dummy`. If the
/// plan has one of these faults, the commit refuses the plan with `internal`
/// before any merge, and no ref changes:
///
/// - a commit that is not the new commit of an update
/// - a commit that the plan gives in two tuples
/// - an entry under a signature key
/// - a key that the plan gives two times for one commit
/// - a value that is not a [`Value::Variant`]
/// - an entry that does not encode:
///   - an inner value that does not have the type of the variant
///   - a string with a NUL byte
///   - a value or a type nested deeper than the parser reads
///   - a type that the parser does not read, for example a dict entry whose
///     key is not a basic type
///   - a key with a NUL byte
///
/// The first five checks run first over the whole plan. They run in the order
/// of the tuples and, in each tuple, in the order of its entries. Then the
/// encode check runs over the plan in the same order. The first failure is the
/// refusal.
///
/// If a merged dict with host entries is larger than
/// [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE), the commit refuses with
/// `limit-exceeded` before the update lock. If the stored dict changes before
/// the lock, the commit checks the size again under the lock. No ref changes
/// in any of these cases.
///
/// The commit writes the detached metadata and the refs in one transaction
/// commit. The detached metadata is durable before a ref names the commit.
/// As a result, a mirror that pulls when the ref moves reads the entries of
/// the host.
///
/// # When `after_update` runs
///
/// If the transaction commit succeeds, [`after_update`](Self::after_update)
/// runs once in the commit. It runs also if no ref changes, for example if
/// each update names the commit that its ref already names. It runs after
/// these steps:
///
/// - the transaction commit
/// - the removal of the partial markers
/// - the summary step
/// - the release of the update lock
///
/// The hook gets the [`ReceiveReport`] that the commit returns and the
/// carried value of the plan. From then on, the hook owns the carried value.
///
/// The transaction commit is not atomic. It writes the detached metadata,
/// then each ref, and then runs `fsync` on the ref directories. If one of
/// these writes or an `fsync` of a ref directory fails, the detached metadata
/// and some refs can stay written.
///
/// In this case, the commit returns the error as a failure on the server side.
/// The carried value drops, and `after_update` does not run. The host must
/// make its own records agree with the refs of the repository.
///
/// The report goes to the hook before the host sends the reply, so the
/// report never holds a warning of the step
/// [`ReplyNotDelivered`](super::ReceiveStep::ReplyNotDelivered). The time of
/// the hook adds to the time that the commit takes to return.
///
/// # Locks
///
/// The session holds the repository lock shared
/// ([`LockKind::Shared`](crate::LockKind::Shared)) from `Hello` to the commit
/// of its transaction. The lock order is always this:
///
/// 1. the repository lock, shared
/// 2. the locks that the hook takes
/// 3. the update lock
///
/// The host must obey two rules:
///
/// - It never takes a lock that `before_update` takes while it holds the
///   update lock or an [`UpdateGuard`](crate::UpdateGuard).
/// - It never waits for an exclusive repository lock, for example the lock
///   of a prune, while it holds a lock that `before_update` takes.
///
/// The host can put the guards of its locks in [`UpdatePlan::carried`]. Then
/// the guards stay held from `before_update`, across the wait for the update
/// lock and the ref update, until `after_update` drops the carried value.
/// `carried` is a `Box<dyn Any + Send>`, which is `'static`, so each guard in
/// it must be an owned guard. The session does not examine the contents of
/// `carried`.
///
/// When `after_update` runs, the session holds no lock. The update lock is
/// released, and the transaction commit released the shared repository lock.
/// The hook can call
/// [`Repo::set_ref_immediate`](crate::Repo::set_ref_immediate) and
/// [`Repo::begin_update`](crate::Repo::begin_update) because the session holds
/// no lock.
///
/// The guards in the carried value are still held, so the two rules still
/// apply. While the hook holds the carried value, it never waits for an
/// exclusive repository lock, for example the lock of a prune. Another session
/// can hold the shared repository lock and wait in `before_update` for a lock
/// in the carried value. Then the hook and that session deadlock.
///
/// # Cancellation
///
/// The transaction commit writes the detached metadata and the refs on the
/// blocking pool. If a [`commit`](super::ReceiveService::commit) future is
/// dropped before it completes, it can release the update lock and drop the
/// carried value while these writes continue. A `commit` future can also be
/// dropped while `after_update` runs. Then it drops the future of the hook and
/// the carried value, and the refs can be written already. The host must run
/// each commit to its end, for example in a task that it joins.
///
/// # Panics in a hook
///
/// The session does not catch a panic in a hook. A panic in `after_update`
/// comes after the refs are written, and resumes in the caller of
/// [`commit`](super::ReceiveService::commit).
pub trait ReceiveHooks: Send + Sync {
    /// Returns the detached-metadata entries of the host for the new commits
    /// of `updates`.
    ///
    /// The plan also holds a value that goes to
    /// [`after_update`](Self::after_update).
    ///
    /// # Errors
    ///
    /// If the hook returns a [`HookRefusal`], the commit fails with the code
    /// of the refusal, and no ref changes.
    fn before_update<'a>(
        &'a self,
        updates: &'a [RefUpdate],
    ) -> HookFuture<'a, Result<UpdatePlan, HookRefusal>>;

    /// Takes the report of a successful commit and the carried value of the
    /// plan.
    ///
    /// The hook runs only if the transaction commit succeeds. The carried
    /// value is the value of the plan of
    /// [`before_update`](Self::before_update).
    ///
    /// # Errors
    ///
    /// If the hook returns an error, the commit returns `internal` with the
    /// message of the error, cut to 4096 bytes at a character boundary. Then
    /// the session ends as aborted. The refs and the detached metadata stay
    /// written. The session does not undo them, so an aborted session can
    /// leave its refs written.
    fn after_update<'a>(
        &'a self,
        report: &'a ReceiveReport,
        carried: Box<dyn Any + Send>,
    ) -> HookFuture<'a, Result<(), String>>;
}

/// The plan that [`ReceiveHooks::before_update`] returns.
#[derive(Debug)]
pub struct UpdatePlan {
    /// The detached-metadata entries of the host for the new commits.
    ///
    /// The plan holds at most one tuple for each commit.
    pub metadata: Vec<(Checksum, Vec<HostEntry>)>,
    /// A value that goes to [`ReceiveHooks::after_update`].
    ///
    /// If the commit fails after `before_update`, the value drops once, after
    /// the release of the update lock, and `after_update` does not run. A
    /// failure of the transaction commit can leave the detached metadata and
    /// some refs written.
    pub carried: Box<dyn Any + Send>,
}

/// One detached-metadata entry of the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    /// The key.
    pub key: String,
    /// The value, a [`Value::Variant`].
    pub value: Value,
    /// The rule for a key that the stored dict already holds.
    ///
    /// If `false`, the value replaces the value that the stored dict or the
    /// client dict holds under the key. If `true`, a value that the stored
    /// dict holds under the key stays. The commit writes the value only if the
    /// stored dict has no such key.
    pub keep_existing: bool,
}

/// A refusal of the commit from [`ReceiveHooks::before_update`].
///
/// If the hook returns a refusal, no ref changes.
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
    /// Creates a refusal with the code `ref-denied`.
    ///
    /// The receive endpoint of `ostrya-server` answers it with 422. If the
    /// message is longer than 4096 bytes, this function cuts it to 4096 bytes
    /// at a character boundary.
    pub fn denied(message: impl Into<String>) -> HookRefusal {
        HookRefusal::new(Kind::Denied, message.into())
    }

    /// Creates a refusal with the code `internal`.
    ///
    /// The receive endpoint of `ostrya-server` answers it with 500. If the
    /// message is longer than 4096 bytes, this function cuts it to 4096 bytes
    /// at a character boundary.
    pub fn internal(message: impl Into<String>) -> HookRefusal {
        HookRefusal::new(Kind::Internal, message.into())
    }

    fn new(kind: Kind, mut message: String) -> HookRefusal {
        cut(&mut message);
        HookRefusal { kind, message }
    }

    /// Returns the failure of the session for the refusal.
    pub(super) fn into_failure(self) -> Failure {
        Failure::Wire(match self.kind {
            Kind::Denied => push::Error::RefDenied(self.message),
            Kind::Internal => push::Error::Internal(self.message),
        })
    }
}
