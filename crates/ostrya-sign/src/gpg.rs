//! The GPG engine: the signer behind `sign-gpg`, the verifier behind `gpg`.
//!
//! The doc of `GpgSigner` holds the key selection, the signing process, and
//! the signature format. The doc of `GpgVerifier` holds the verdict and the
//! limits of a keyring.

#[cfg(feature = "sign-gpg")]
mod signer;
#[cfg(feature = "gpg")]
mod verifier;

#[cfg(feature = "sign-gpg")]
pub use signer::GpgSigner;
#[cfg(feature = "gpg")]
pub use verifier::{
    GpgKey, GpgOfferedKeys, GpgVerifier, MAX_KEYRING, gpg_keyring_keys, gpg_merge_keyring,
    gpg_offered_keys,
};

/// The key of the GPG engine in the detached-metadata dict.
///
/// The signer writes its signatures under this key, and the verifier reads
/// them from it.
const GPG_METADATA_KEY: &str = "ostree.gpgsigs";
/// The prefix of a machine-readable status line on the status fd.
#[cfg(any(test, feature = "sign-gpg"))]
const STATUS_PREFIX: &str = "[GNUPG:] ";
