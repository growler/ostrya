//! The receive side of a push: the policy a repository applies to the commits
//! and ref updates it receives.
//!
//! Behind the `receive` feature. [`ReceivePolicy`] states what the receiving
//! repository accepts: non-fast-forward updates, deletes, privileged content,
//! remote refs, the signatures a commit must carry ([`ReceiveVerify`]), the
//! keys the server signs with ([`ServerSigner`]), whether it signs and
//! regenerates its summary, and which detached-metadata keys it does not
//! store. [`ReceivePolicy::from_config`] reads the policy from the `receive-*`
//! keys of the repository's `[ex-ostrya]` group, `[core] auto-update-summary`,
//! and `[ex-ostrya] detached-metadata-exclude`.
//!
//! A received commit is held to the signature checks a pull makes. The axes
//! are ANDed, and the engines of the sign-api axis are ORed. The keys are the
//! ones the receive keys name, and no system key store, revoked set, or global
//! trusted keyring takes part.
//!
//! The module also holds two steps of the commit that ends a session: the
//! union merge of an incoming detached-metadata dict into the dict the server
//! holds, and the check whether a server key already signed a commit.

mod merge;
mod policy;
mod signer;

pub use policy::{ReceivePolicy, ReceiveVerify};
pub use signer::ServerSigner;

/// The receive types move freely across tasks and threads, so one policy can
/// serve every session of a server.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ReceivePolicy>();
    assert_send_sync::<ReceiveVerify>();
    assert_send_sync::<ServerSigner>();
};
