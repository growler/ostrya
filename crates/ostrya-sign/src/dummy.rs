//! The test-only dummy engine.

use crate::{SignFuture, SignatureInfo, Signer, Verifier, VerifyFuture, VerifyOutcome};

/// A signer of the dummy engine, for tests.
///
/// The engine name is `dummy`, and the metadata key is `ostree.sign.dummy`.
/// The signature is the bytes of the key and does not depend on the payload.
/// The secret key and the public key are the same byte string.
///
/// The engine does no cryptography. Tests use it to check the signing
/// framework and to cross-check against the dummy engine of the `ostree`
/// command.
#[derive(Debug, Clone)]
pub struct DummySigner {
    key: Vec<u8>,
}

impl DummySigner {
    /// Creates a dummy signer whose signature is the bytes of `key`.
    pub fn new(key: impl Into<Vec<u8>>) -> DummySigner {
        DummySigner { key: key.into() }
    }
}

impl Signer for DummySigner {
    fn name(&self) -> &str {
        "dummy"
    }

    fn metadata_key(&self) -> &str {
        "ostree.sign.dummy"
    }

    fn sign<'a>(&'a self, _data: &'a [u8]) -> SignFuture<'a> {
        let signature = self.key.clone();
        Box::pin(async move { Ok(signature) })
    }
}

/// A verifier of the dummy engine, for tests.
///
/// If the bytes of a signature equal one of the trusted keys, the signature
/// verifies. The verifier does not read the payload. The metadata key is
/// `ostree.sign.dummy`.
#[derive(Debug, Clone)]
pub struct DummyVerifier {
    trusted: Vec<Vec<u8>>,
}

impl DummyVerifier {
    /// Creates a dummy verifier that trusts each key in `keys`.
    pub fn new<K, I>(keys: I) -> DummyVerifier
    where
        K: Into<Vec<u8>>,
        I: IntoIterator<Item = K>,
    {
        DummyVerifier {
            trusted: keys.into_iter().map(Into::into).collect(),
        }
    }
}

impl Verifier for DummyVerifier {
    fn metadata_key(&self) -> &str {
        "ostree.sign.dummy"
    }

    fn verify<'a>(&'a self, _data: &'a [u8], signatures: &'a [Vec<u8>]) -> VerifyFuture<'a> {
        let mut outcome = VerifyOutcome::default();
        for signature in signatures {
            let valid = self.trusted.iter().any(|key| key == signature);
            outcome.valid |= valid;
            outcome.signatures.push(SignatureInfo {
                valid,
                key_missing: !valid,
                ..SignatureInfo::default()
            });
        }
        Box::pin(async move { Ok(outcome) })
    }
}
