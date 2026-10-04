//! The receive side of a push: the policy a repository applies to the commits
//! and ref updates it receives.
//!
//! Behind the `receive` feature. [`ReceivePolicy`] states what the receiving
//! repository accepts. Its [`ReceiveRule`]s apply to the refs their
//! [`RefPattern`]s match, and the default rule applies to each other plain
//! ref. A rule states whether the ref is accepted, the signatures each new
//! commit must carry ([`ReceiveVerify`] over [`TrustedKeys`]), whether a
//! non-fast-forward update and a delete are accepted, and the keys the server
//! signs with ([`ServerSigner`]). The policy also states whether privileged
//! content is accepted, the keys that sign the regenerated summary, whether
//! the summary is regenerated, and which detached-metadata keys the
//! repository does not store.
//!
//! [`ReceivePolicy::from_config`] reads the policy from the receive groups of
//! the repository config, `[ex-ostrya receive]`,
//! `[ex-ostrya receive "PATTERN"]`, `[ex-ostrya trust "NAME"]`, and
//! `[ex-ostrya key "NAME"]`, and [`ReceivePolicy::from_file`] reads the same
//! groups from a file of their own.
//!
//! A received commit is held to the signature checks a pull makes. The axes
//! are ANDed, and the engines of the sign-api axis are ORed. A trust group
//! trusts the keys it names alone: no system key store, revoked set, or
//! global trusted keyring takes part. A rule that takes the pull trust of a
//! remote trusts what a pull from that remote trusts.
//!
//! [`Repo::receive`](crate::Repo::receive) runs one push session over a pair
//! of streams: it answers `Hello` and `Have`, and it stages the objects of
//! each object stream in the session transaction after the checksum and the
//! content checks of the repository mode.
//!
//! `Commit` ends the session: the checks of each ref update, the ref writes,
//! and the transaction commit under the update lock. The commit merges
//! each incoming detached-metadata dict into the dict the server holds with a
//! union of the signature lists. The module also holds the check whether a
//! server key already signed a commit.
//!
//! [`ReceiveService`] runs the same session as steps, one for each request of
//! a transport such as HTTP, with concurrent object streams on the one
//! session transaction.
//!
//! [`Repo::receive_stream`](crate::Repo::receive_stream) reads one one-way
//! stream: the messages of a session in one direction, with no reply. It runs
//! the checks and the commit of a session, with no server signature and no
//! summary step.

mod ancestry;
mod core;
mod finish;
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
};
