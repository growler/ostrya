//! The receive side of a push: the policy and the sessions of a server.
//!
//! This module needs the `receive` feature. These are its entry items:
//!
//! - [`ReceivePolicy`] states what a receiving repository accepts.
//!   [`ReceivePolicy::from_config`] reads it from the repository config.
//!   [`TrustedKeys`] holds the keys that a rule verifies a commit against.
//! - [`Repo::receive`](crate::Repo::receive) runs one push session over a
//!   pair of streams. Its doc lists the checks of `Commit` in order.
//! - [`ReceiveService`] runs a push session as steps, one step for each
//!   request of a transport such as HTTP. [`ReceiveService::commit`] states
//!   the condition of each wire code of `Commit`.
//! - [`ReceiveHooks`] are the calls of the host that run before and after the
//!   ref update of a session.
//! - [`Repo::receive_stream`](crate::Repo::receive_stream) reads one one-way
//!   stream: the messages of a session in one direction, with no reply.

mod ancestry;
mod core;
mod finish;
mod hooks;
mod ingest;
mod merge;
mod pattern;
mod policy;
mod reader;
mod service;
mod session;
mod signer;
mod stream;
mod trust;
mod walk;

pub use hooks::{HookFuture, HookRefusal, HostEntry, ReceiveHooks, UpdatePlan};
pub use pattern::RefPattern;
pub use policy::{ReceivePolicy, ReceiveRule, ReceiveVerify};
pub use service::ReceiveService;
pub use session::{ReceiveReport, ReceiveStep, ReceiveWarning};
pub use signer::ServerSigner;
pub use trust::TrustedKeys;

pub(crate) use merge::merge_detached;

/// The receive types move freely across tasks and threads, so one policy can
/// serve every session of a server.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ReceivePolicy>();
    assert_send_sync::<ReceiveRule>();
    assert_send_sync::<ReceiveVerify>();
    assert_send_sync::<RefPattern>();
    assert_send_sync::<TrustedKeys>();
    assert_send_sync::<ServerSigner>();
    assert_send_sync::<ReceiveReport>();
    assert_send_sync::<ReceiveWarning>();
    assert_send_sync::<ReceiveService>();
    assert_send_sync::<HostEntry>();
    assert_send_sync::<HookRefusal>();
    fn assert_send<T: Send>() {}
    assert_send::<UpdatePlan>();
};
